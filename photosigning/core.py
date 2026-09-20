"""Versioned pixel signature format. No private material is embedded in images.

The first RGB channel LSBs hold a fixed header followed by canonical JSON.
The digest clears ONLY those occupied LSBs. All remaining channel bits,
including alpha and unused LSBs, are hashed. The signature authenticates the
manifest, and strict canonical encoding authenticates the payload's layout.
Thus every pixel bit is covered either by the digest or the signed envelope.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import struct
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from PIL import ExifTags, Image, ImageOps, UnidentifiedImageError

MAGIC = b"PHOTOMK1"
HEADER = struct.Struct(">8sI")
DOMAIN = b"PhotoSigning/manifest/v1\x00"
MAX_PAYLOAD = 32_768
MAX_FILE_BYTES = 40 * 1024 * 1024
MAX_PIXELS = 25_000_000
EXIF_FIELDS = {
    "Make": "camera_make",
    "Model": "camera_model",
    "LensModel": "lens",
    "DateTimeOriginal": "captured_at",
    "ExposureTime": "exposure",
    "FNumber": "aperture",
    "ISOSpeedRatings": "iso",
    "PhotographicSensitivity": "iso",
    "FocalLength": "focal_length",
    "Artist": "artist",
    "Copyright": "copyright",
}


class PhotoSignError(ValueError):
    """An actionable input or signature-format error."""


@dataclass(frozen=True)
class SignedPhoto:
    png: bytes
    manifest: dict[str, Any]
    fingerprint: str
    payload_bytes: int


@dataclass(frozen=True)
class Verification:
    valid: bool
    status: str
    message: str
    manifest: dict[str, Any] | None = None
    fingerprint: str | None = None
    trusted: bool = False


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def generate_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_pem(key: Ed25519PublicKey | Ed25519PrivateKey) -> bytes:
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def fingerprint(key: Ed25519PublicKey | Ed25519PrivateKey) -> str:
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    return hashlib.sha256(key.public_bytes_raw()).hexdigest()


def export_private_key(key: Ed25519PrivateKey, password: str) -> bytes:
    if len(password) < 8:
        raise PhotoSignError("Use a password with at least 8 characters for your key backup.")
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode("utf-8")),
    )


def load_private_key(data: bytes, password: str = "") -> Ed25519PrivateKey:
    if len(data) > 16_384:
        raise PhotoSignError("This key file is too large.")
    try:
        key = serialization.load_pem_private_key(data, password.encode() if password else None)
    except (ValueError, TypeError) as exc:
        raise PhotoSignError("Could not unlock the key. Check the PEM file and password.") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise PhotoSignError("Please use an Ed25519 private key.")
    return key


def load_public_key(data: bytes) -> Ed25519PublicKey:
    if len(data) > 16_384:
        raise PhotoSignError("This key file is too large.")
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise PhotoSignError("Could not read this public PEM key.") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise PhotoSignError("Please use an Ed25519 public key.")
    return key


def read_photo(data: bytes, *, orient: bool = False) -> Image.Image:
    if len(data) > MAX_FILE_BYTES:
        raise PhotoSignError("Choose an image smaller than 40 MB.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as source:
                if source.width * source.height > MAX_PIXELS:
                    raise PhotoSignError("Choose an image with at most 25 megapixels.")
                if getattr(source, "n_frames", 1) != 1:
                    raise PhotoSignError("Animated or multi-page images are not supported.")
                source.load()
                if orient:
                    source = ImageOps.exif_transpose(source)
                mode = (
                    "RGBA" if "A" in source.getbands() or "transparency" in source.info else "RGB"
                )
                return source.convert(mode)
    except (
        UnidentifiedImageError,
        OSError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        SyntaxError,
        ValueError,
    ) as exc:
        if isinstance(exc, PhotoSignError):
            raise
        raise PhotoSignError("This file could not be decoded as a supported image.") from exc


def extract_exif(data: bytes) -> dict[str, str]:
    # Validate size/decoding first; GPS and device serial numbers are deliberately excluded.
    read_photo(data)
    result: dict[str, str] = {}
    try:
        with Image.open(io.BytesIO(data)) as photo:
            exif = photo.getexif()
            values = dict(exif)
            if 34665 in exif:
                values.update(exif.get_ifd(34665))
            for tag, value in values.items():
                field = EXIF_FIELDS.get(ExifTags.TAGS.get(tag, ""))
                if field and value is not None:
                    result[field] = str(value).strip("\x00 ")[:500]
    except (OSError, ValueError, TypeError, SyntaxError, KeyError, struct.error):
        pass
    return result


def _channel_index(bit: int, stride: int) -> int:
    return (bit // 3) * stride + bit % 3


def _extract(raw: bytes, stride: int, count: int, offset: int = 0) -> bytes:
    result = bytearray(count)
    for byte in range(count):
        value = 0
        for bit in range(8):
            value = (value << 1) | (raw[_channel_index(offset + byte * 8 + bit, stride)] & 1)
        result[byte] = value
    return bytes(result)


def _embed(raw: bytearray, stride: int, payload: bytes) -> None:
    for byte_index, value in enumerate(payload):
        for bit in range(8):
            index = _channel_index(byte_index * 8 + bit, stride)
            raw[index] = (raw[index] & 0xFE) | ((value >> (7 - bit)) & 1)


def _digest(photo: Image.Image, occupied_bits: int) -> str:
    raw = bytearray(photo.tobytes())
    stride = len(photo.getbands())
    for bit in range(occupied_bits):
        raw[_channel_index(bit, stride)] &= 0xFE
    digest = hashlib.sha256(b"PhotoSigning/pixels/v1\x00")
    digest.update(canonical({"width": photo.width, "height": photo.height, "mode": photo.mode}))
    digest.update(raw)
    return digest.hexdigest()


def _envelope(manifest: dict[str, Any], signature: bytes) -> bytes:
    return canonical({"manifest": manifest, "signature": base64.b64encode(signature).decode()})


def sign_photo(
    data: bytes, key: Ed25519PrivateKey, *, name: str, details: dict[str, str] | None = None
) -> SignedPhoto:
    name = name.strip()
    if not name or len(name) > 200:
        raise PhotoSignError("Enter a photographer name between 1 and 200 characters.")
    details = details or {}
    if len(details) > 30 or any(
        not isinstance(k, str) or not isinstance(v, str) or len(k) > 60 or len(v) > 500
        for k, v in details.items()
    ):
        raise PhotoSignError("Photo details must be short text fields (up to 500 characters each).")
    photo = read_photo(data, orient=True)
    manifest = {
        "format": "photosigning/v1",
        "algorithm": "Ed25519",
        "photographer": name,
        "details": {k: v.strip() for k, v in details.items() if v.strip()},
        "signed_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "image": {"width": photo.width, "height": photo.height, "mode": photo.mode},
        "pixel_sha256": "0" * 64,
        "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
    }
    size = len(_envelope(manifest, bytes(64)))
    occupied = (HEADER.size + size) * 8
    if size > MAX_PAYLOAD:
        raise PhotoSignError("The signed details are too large. Shorten the text fields.")
    if occupied > photo.width * photo.height * 3:
        raise PhotoSignError("This image is too small to hold the signature. Use a larger image.")
    manifest["pixel_sha256"] = _digest(photo, occupied)
    payload = _envelope(manifest, key.sign(DOMAIN + canonical(manifest)))
    assert (
        len(payload) == size
    )  # fixed-width hash and signature prevent a circular length dependency
    raw = bytearray(photo.tobytes())
    _embed(raw, len(photo.getbands()), HEADER.pack(MAGIC, size) + payload)
    signed = Image.frombytes(photo.mode, photo.size, bytes(raw))
    out = io.BytesIO()
    # Carry forward the display profile, but never the source's unsigned metadata or GPS.
    save_options = (
        {"icc_profile": photo.info["icc_profile"]} if photo.info.get("icc_profile") else {}
    )
    signed.save(out, format="PNG", **save_options)
    if out.tell() > MAX_FILE_BYTES:
        raise PhotoSignError(
            "The lossless signed PNG exceeds 40 MB. Resize the original before signing."
        )
    return SignedPhoto(out.getvalue(), manifest, fingerprint(key), HEADER.size + size)


def verify_photo(data: bytes, trusted_key: Ed25519PublicKey | None = None) -> Verification:
    try:
        photo = read_photo(data)
        capacity = photo.width * photo.height * 3 // 8
        if capacity < HEADER.size:
            return Verification(False, "no_signature", "No PhotoSigning signature found.")
        raw = photo.tobytes()
        stride = len(photo.getbands())
        magic, size = HEADER.unpack(_extract(raw, stride, HEADER.size))
        if magic != MAGIC:
            return Verification(
                False,
                "no_signature",
                "No readable PhotoSigning signature found. "
                "The photo may be unsigned or its signature may have been removed.",
            )
        if not 0 < size <= min(MAX_PAYLOAD, capacity - HEADER.size):
            raise PhotoSignError("The embedded signature has an invalid length.")
        payload = _extract(raw, stride, size, HEADER.size * 8)
        envelope = json.loads(payload)
        if not isinstance(envelope, dict) or set(envelope) != {"manifest", "signature"}:
            raise PhotoSignError("The embedded signature has an invalid structure.")
        if canonical(envelope) != payload:
            raise PhotoSignError("The embedded signature encoding has been altered.")
        manifest = envelope["manifest"]
        if not isinstance(manifest, dict):
            raise PhotoSignError("The embedded manifest is invalid.")
        if manifest.get("format") != "photosigning/v1" or manifest.get("algorithm") != "Ed25519":
            raise PhotoSignError("This signature format is not supported.")
        if (
            set(manifest)
            != {
                "format",
                "algorithm",
                "photographer",
                "details",
                "signed_at",
                "image",
                "pixel_sha256",
                "public_key",
            }
            or not isinstance(manifest["photographer"], str)
            or not 1 <= len(manifest["photographer"].strip()) <= 200
            or not isinstance(manifest["signed_at"], str)
            or not isinstance(manifest["pixel_sha256"], str)
            or len(manifest["pixel_sha256"]) != 64
            or not isinstance(manifest["details"], dict)
            or len(manifest["details"]) > 30
            or any(
                not isinstance(k, str) or not isinstance(v, str) or len(k) > 60 or len(v) > 500
                for k, v in manifest["details"].items()
            )
        ):
            raise PhotoSignError("The embedded manifest fields are invalid.")
        public = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(manifest["public_key"], validate=True)
        )
        signature = base64.b64decode(envelope["signature"], validate=True)
        if base64.b64encode(signature).decode("ascii") != envelope["signature"]:
            raise PhotoSignError("The embedded signature encoding has been altered.")
        public.verify(signature, DOMAIN + canonical(manifest))
        expected_image = {"width": photo.width, "height": photo.height, "mode": photo.mode}
        if manifest["image"] != expected_image or manifest["pixel_sha256"] != _digest(
            photo, (HEADER.size + size) * 8
        ):
            return Verification(
                False,
                "modified",
                "The signature is authentic, but the image pixels "
                "have changed. This photo does not match the signed image.",
            )
        signer = fingerprint(public)
        if trusted_key is not None and fingerprint(trusted_key) != signer:
            return Verification(
                False,
                "wrong_key",
                "The photo is intact, but it was signed by a "
                "different key than the trusted public key you supplied.",
                manifest,
                signer,
            )
        return Verification(
            True,
            "verified",
            "The embedded signature and image pixels are intact.",
            manifest,
            signer,
            trusted_key is not None,
        )
    except InvalidSignature:
        return Verification(
            False,
            "invalid_signature",
            "The embedded signature is invalid. "
            "The signing details or signature have been altered.",
        )
    except (PhotoSignError, ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        return Verification(
            False,
            "unreadable",
            "The image or embedded signature is unreadable: "
            + (str(exc) if isinstance(exc, PhotoSignError) else "invalid signature data."),
        )
