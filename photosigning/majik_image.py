"""Modified Python adaptation of Majik Signature's experimental image stamp.

Copyright (c) 2026 Majikah Solutions OPC. Apache-2.0.
See third_party/majik-signature/{LICENSE,NOTICE.md} for source and modifications.

This uses a NEW format. A valid proof authenticates a perceptual fingerprint,
not the exact pixels or every possible derivative. No separate key is needed.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass, replace
from functools import lru_cache

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from PIL import Image
from reedsolo import ReedSolomonError, RSCodec

from .core import PhotoSignError, canonical, fingerprint, read_photo

GRID = 512
STEP = 48.0
REPEATS = 4
PARITY = 80
STUB = struct.Struct(">4sH8s32sQ32s64s")  # 150 bytes, adapted from Majik's stub
MAGIC = b"PSR2"
DOMAIN = b"photosigning-resilient-v2:"
PHASH_THRESHOLD = 8


@dataclass(frozen=True)
class WatermarkProof:
    valid: bool
    message: str
    record_id: str | None = None
    fingerprint: str | None = None
    distance: int | None = None
    timestamp_ms: int | None = None
    normalization: str = "none"


@lru_cache(maxsize=2)
def dct_basis(size: int) -> np.ndarray:
    """Orthonormal DCT-II, matching the separable transform in Majik's source."""
    k = np.arange(size)[:, None]
    n = np.arange(size)[None, :]
    matrix = np.cos(np.pi * k * (2 * n + 1) / (2 * size)) * np.sqrt(2 / size)
    matrix[0] /= np.sqrt(2)
    return matrix


def phash(photo: Image.Image) -> str:
    """Majik's median/bit ordering, modified to antialias before downsampling."""
    rgb = np.asarray(photo.convert("RGB").resize((32, 32), Image.Resampling.LANCZOS), dtype=float)
    gray = rgb @ np.array([0.2126, 0.7152, 0.0722])
    basis = dct_basis(32)
    low = (basis @ gray @ basis.T)[:8, :8].ravel()[1:]
    bits = low > np.median(low)
    high = sum(int(value) << i for i, value in enumerate(bits[:32]))
    low_half = sum(int(value) << i for i, value in enumerate(bits[32:]))
    return f"{high:08x}{low_half:08x}"


def hamming(a: str, b: str) -> int:
    if len(a) != 16 or len(b) != 16:
        raise PhotoSignError("Perceptual fingerprints must have 16 hex characters.")
    return (int(a, 16) ^ int(b, 16)).bit_count()


def _payload(record_id: str, image_hash: str, timestamp_ms: int) -> bytes:
    return DOMAIN + canonical({"id": record_id, "pHash": image_hash, "ts": timestamp_ms, "v": 2})


def _stub(key: Ed25519PrivateKey, record_id: str, image_hash: str, timestamp_ms: int) -> bytes:
    return STUB.pack(
        MAGIC,
        2,
        bytes.fromhex(image_hash),
        key.public_key().public_bytes_raw(),
        timestamp_ms,
        bytes.fromhex(record_id),
        key.sign(_payload(record_id, image_hash, timestamp_ms)),
    )


def _luma(photo: Image.Image) -> np.ndarray:
    rgb = np.asarray(
        photo.convert("RGB").resize((GRID, GRID), Image.Resampling.LANCZOS), dtype=float
    )
    return rgb @ np.array([0.299, 0.587, 0.114])


def _blocks(array: np.ndarray) -> np.ndarray:
    return array.reshape(64, 8, 64, 8).transpose(0, 2, 1, 3).reshape(4096, 8, 8)


def _unblocks(blocks: np.ndarray) -> np.ndarray:
    return blocks.reshape(64, 64, 8, 8).transpose(0, 2, 1, 3).reshape(GRID, GRID)


@lru_cache(maxsize=1)
def _carriers() -> tuple[np.ndarray, np.ndarray]:
    basis = dct_basis(8)
    patterns = np.stack([np.outer(basis[1], basis[2]), np.outer(basis[2], basis[1])])
    # Public layout, not a secret. Interleaving distributes burst damage among RS symbols.
    slots = np.random.default_rng(20260919).permutation(8192)
    return patterns, slots


def embed_watermark(
    data: bytes, key: Ed25519PrivateKey, record_id: str, timestamp_ms: int
) -> bytes:
    photo = read_photo(data, orient=True)
    if min(photo.size) < GRID:
        raise PhotoSignError(
            "Invisible watermark needs both dimensions to be at least 512 pixels. "
            "Use registry recognition for smaller photos."
        )
    if photo.mode == "RGBA" and photo.getchannel("A").getextrema() != (255, 255):
        raise PhotoSignError(
            "Invisible watermark requires an opaque image. Use registry recognition "
            "for transparent images, or flatten them before signing."
        )
    if len(record_id) != 64:
        raise PhotoSignError("The photo record ID must be a SHA-256 hash.")
    original = np.asarray(photo.convert("RGB"))
    if np.std(_luma(photo)) < 10:
        raise PhotoSignError(
            "This image has too little visual detail for reliable watermarking. "
            "Use exact signing or registry recognition."
        )
    image_hash = phash(photo)
    code = RSCodec(PARITY).encode(_stub(key, record_id, image_hash, timestamp_ms))
    bits = np.unpackbits(np.frombuffer(bytes(code), dtype=np.uint8))
    patterns, slots = _carriers()
    active = slots[: len(bits) * REPEATS]
    targets = np.tile(bits, REPEATS)
    current = photo.convert("RGB")
    # Reproject the fixed-coordinate perturbation, correcting interpolation attenuation.
    for _ in range(4):
        blocks = _blocks(_luma(current))
        coefficients = np.einsum("bij,kij->bk", blocks, patterns).ravel()
        q = coefficients[active] / STEP
        desired = (np.rint((q - targets) / 2) * 2 + targets) * STEP
        delta = np.zeros(8192)
        delta[active] = desired - coefficients[active]
        correction = _unblocks(np.einsum("bk,kij->bij", delta.reshape(4096, 2), patterns))
        native = np.asarray(
            Image.fromarray(correction.astype(np.float32)).resize(
                photo.size, Image.Resampling.BICUBIC
            )
        )
        # Process one channel at a time rather than allocating multiple full RGB
        # float64 arrays for a 25-megapixel photograph.
        previous = np.asarray(current)
        rgb = np.empty_like(original)
        for channel in range(3):
            adjustment = previous[:, :, channel].astype(np.float32)
            adjustment -= original[:, :, channel]
            adjustment += native
            np.clip(adjustment, -28, 28, out=adjustment)
            adjustment += original[:, :, channel]
            np.clip(adjustment, 0, 255, out=adjustment)
            rgb[:, :, channel] = np.rint(adjustment).astype(np.uint8)
        current = Image.fromarray(rgb)
    out = io.BytesIO()
    current.save(out, format="PNG")
    result = verify_watermark(out.getvalue())
    if not result.valid or result.record_id != record_id:
        raise PhotoSignError(
            "This photo could not carry a reliable invisible watermark. "
            "Use registry recognition or try a larger, more detailed image."
        )
    return out.getvalue()


def verify_watermark(data: bytes) -> WatermarkProof:
    try:
        photo = read_photo(data, orient=True)
    except PhotoSignError as exc:
        return WatermarkProof(False, str(exc))
    if min(photo.size) < 128:
        return WatermarkProof(False, "Image is too small to recover an invisible watermark.")
    original = _verify_orientation(photo)
    if original.valid:
        return original
    # These exact geometric inverses do not weaken cryptographic checks: each
    # candidate must still recover an authentic proof AND match its signed pHash.
    for transform in Image.Transpose:
        oriented = photo.transpose(transform)
        proof = _verify_orientation(oriented)
        oriented.close()
        if proof.valid:
            return replace(
                proof,
                normalization=transform.name,
                message=proof.message + " Verification normalized image orientation.",
            )
    return original


def _verify_orientation(photo: Image.Image) -> WatermarkProof:
    try:
        patterns, slots = _carriers()
        coefficients = np.einsum("bij,kij->bk", _blocks(_luma(photo)), patterns).ravel()
        length = (STUB.size + PARITY) * 8
        q = (coefficients[slots[: length * REPEATS]] / STEP).reshape(REPEATS, length)
        even_error = np.square(q - np.rint(q / 2) * 2).sum(axis=0)
        odd_error = np.square(q - (np.rint((q - 1) / 2) * 2 + 1)).sum(axis=0)
        encoded = np.packbits((odd_error < even_error).astype(np.uint8)).tobytes()
        decoded = bytes(RSCodec(PARITY).decode(encoded)[0])
        magic, version, image_hash, public, timestamp, record, signature = STUB.unpack(decoded)
        if magic != MAGIC or version != 2:
            return WatermarkProof(False, "No supported invisible watermark found.")
        image_hash, record = image_hash.hex(), record.hex()
        key = Ed25519PublicKey.from_public_bytes(public)
        key.verify(signature, _payload(record, image_hash, timestamp))
        distance = hamming(image_hash, phash(photo))
        if distance > PHASH_THRESHOLD:
            return WatermarkProof(
                False,
                "An authentic watermark was recovered, but the image "
                "does not match its perceptual fingerprint.",
                record,
                fingerprint(key),
                distance,
                timestamp,
            )
        return WatermarkProof(
            True,
            "Authentic invisible watermark recovered; perceptual image "
            "match. This does not certify that pixels are unchanged.",
            record,
            fingerprint(key),
            distance,
            timestamp,
        )
    except (
        ReedSolomonError,
        InvalidSignature,
        PhotoSignError,
        ValueError,
        TypeError,
        struct.error,
    ):
        return WatermarkProof(
            False,
            "No valid invisible watermark recovered. It may be absent, "
            "damaged, or beyond the supported edit tolerance.",
        )
