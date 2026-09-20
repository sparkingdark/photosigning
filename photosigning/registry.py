"""Signed photo records and local, explicitly approximate derivative recognition."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import cv2
import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from PIL import Image

from .core import PhotoSignError, canonical, fingerprint, read_photo
from .majik_image import hamming, phash

DOMAIN = b"photosigning-registry-v1:"
MAX_RECORD_BYTES = 200_000
MAX_RECORDS = 500
MAX_FEATURES = 600


def pixel_hash(photo: Image.Image) -> str:
    return hashlib.sha256(
        canonical({"size": photo.size, "mode": photo.mode}) + photo.tobytes()
    ).hexdigest()


def image_features(photo: Image.Image) -> dict:
    image = photo.convert("RGB")
    image.thumbnail((1000, 1000), Image.Resampling.LANCZOS)
    gray = cv2.cvtColor(np.asarray(image), cv2.COLOR_RGB2GRAY)
    keypoints, descriptors = cv2.ORB_create(nfeatures=MAX_FEATURES).detectAndCompute(gray, None)
    points = [
        [round(k.pt[0] / image.width, 6), round(k.pt[1] / image.height, 6)] for k in keypoints
    ]
    tiny = np.asarray(image.convert("L").resize((32, 32), Image.Resampling.LANCZOS))
    return {
        "phash": phash(photo),
        "gray32": base64.b64encode(tiny.tobytes()).decode(),
        "points": points,
        "descriptors": base64.b64encode(
            descriptors.tobytes() if descriptors is not None else b""
        ).decode(),
    }


def create_record(
    data: bytes, key: Ed25519PrivateKey, *, name: str, details: dict[str, str]
) -> dict:
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 200:
        raise PhotoSignError("Enter a photographer name between 1 and 200 characters.")
    if len(details) > 30 or any(
        not isinstance(k, str) or not isinstance(v, str) or len(k) > 60 or len(v) > 500
        for k, v in details.items()
    ):
        raise PhotoSignError("Photo details must be short text fields.")
    photo = read_photo(data, orient=True)
    manifest = {
        "format": "photosigning-registry/v1",
        "photographer": name.strip(),
        "details": {k: v.strip() for k, v in details.items() if v.strip()},
        "signed_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "pixel_sha256": pixel_hash(photo),
        "image": {"width": photo.width, "height": photo.height, "mode": photo.mode},
        "feature_format": "majik-phash-lanczos-orb/v1",
        "features": image_features(photo),
    }
    return {
        "record_id": hashlib.sha256(canonical(manifest)).hexdigest(),
        "manifest": manifest,
        "signature": base64.b64encode(key.sign(DOMAIN + canonical(manifest))).decode(),
    }


def validate_record(record: dict) -> dict:
    """Authenticate before using stored feature data. Never trust SQLite or imported JSON."""
    try:
        if len(canonical(record)) > MAX_RECORD_BYTES or set(record) != {
            "record_id",
            "manifest",
            "signature",
        }:
            raise ValueError("Invalid record structure or size")
        manifest = record["manifest"]
        if (
            manifest["format"] != "photosigning-registry/v1"
            or manifest["feature_format"] != "majik-phash-lanczos-orb/v1"
        ):
            raise ValueError("Unsupported record version")
        if hashlib.sha256(canonical(manifest)).hexdigest() != record["record_id"]:
            raise ValueError("Record hash does not match its contents")
        public = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(manifest["public_key"], validate=True)
        )
        signature = base64.b64decode(record["signature"], validate=True)
        if base64.b64encode(signature).decode() != record["signature"]:
            raise ValueError("Noncanonical signature")
        public.verify(signature, DOMAIN + canonical(manifest))
        if (
            not isinstance(manifest["photographer"], str)
            or not 1 <= len(manifest["photographer"]) <= 200
        ):
            raise ValueError("Invalid photographer")
        if not isinstance(manifest["signed_at"], str) or len(manifest["signed_at"]) > 40:
            raise ValueError("Invalid timestamp")
        datetime.fromisoformat(manifest["signed_at"])
        details = manifest["details"]
        if (
            not isinstance(details, dict)
            or len(details) > 30
            or any(
                not isinstance(k, str) or not isinstance(v, str) or len(k) > 60 or len(v) > 500
                for k, v in details.items()
            )
        ):
            raise ValueError("Invalid signed details")
        for field in ["source_sha256", "pixel_sha256"]:
            if not re.fullmatch(r"[0-9a-f]{64}", manifest[field]):
                raise ValueError("Invalid digest")
        features = manifest["features"]
        if not re.fullmatch(r"[0-9a-f]{16}", features["phash"]):
            raise ValueError("Invalid perceptual fingerprint")
        if len(base64.b64decode(features["gray32"], validate=True)) != 1024:
            raise ValueError("Invalid thumbnail features")
        points = features["points"]
        if not isinstance(points, list) or len(points) > MAX_FEATURES:
            raise ValueError("Too many feature points")
        if any(
            not isinstance(p, list)
            or len(p) != 2
            or any(not isinstance(v, (int, float)) or not 0 <= v <= 1 for v in p)
            for p in points
        ):
            raise ValueError("Invalid feature coordinates")
        if len(base64.b64decode(features["descriptors"], validate=True)) != len(points) * 32:
            raise ValueError("Invalid feature descriptors")
        return record
    except (
        KeyError,
        TypeError,
        ValueError,
        InvalidSignature,
        OverflowError,
        RecursionError,
    ) as exc:
        raise PhotoSignError(
            "The photo record is malformed or its signature/hash is invalid."
        ) from exc


def import_record(data: bytes) -> dict:
    if len(data) > MAX_RECORD_BYTES:
        raise PhotoSignError("The photo record file is too large.")
    try:
        return validate_record(json.loads(data))
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, PhotoSignError):
            raise
        raise PhotoSignError("Choose a valid PhotoSigning record JSON file.") from exc


def record_fingerprint(record: dict) -> str:
    return fingerprint(
        Ed25519PublicKey.from_public_bytes(base64.b64decode(record["manifest"]["public_key"]))
    )


def _geometry_match(query: dict, reference: dict, *, durable=False) -> int:
    minimum = 8 if durable else 12
    if len(query["points"]) < minimum or len(reference["points"]) < minimum:
        return 0
    a = np.frombuffer(base64.b64decode(query["descriptors"]), dtype=np.uint8).reshape(-1, 32)
    b = np.frombuffer(base64.b64decode(reference["descriptors"]), dtype=np.uint8).reshape(-1, 32)
    pairs = cv2.BFMatcher(cv2.NORM_HAMMING).knnMatch(a, b, k=2)
    good = [p[0] for p in pairs if len(p) == 2 and p[0].distance < 0.7 * p[1].distance]
    # Do not count duplicate destinations as independent evidence.
    good = list({m.trainIdx: m for m in sorted(good, key=lambda m: -m.distance)}.values())
    if len(good) < minimum:
        return 0
    src = np.float32([query["points"][m.queryIdx] for m in good])
    dst = np.float32([reference["points"][m.trainIdx] for m in good])
    _, mask = cv2.findHomography(src, dst, cv2.RANSAC, 0.015)
    if mask is None:
        return 0
    mask = mask.ravel().astype(bool)
    count = int(mask.sum())
    if count < minimum or count / len(good) < 0.6:
        return 0
    if (
        cv2.contourArea(cv2.convexHull(src[mask])) < (0.01 if durable else 0.1)
        or cv2.contourArea(cv2.convexHull(dst[mask])) < (0.008 if durable else 0.015)
    ):
        return 0
    return count


class Registry:
    """Local persistent records, limited to 500 photos for bounded interactive searches."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(
            path or os.environ.get("PHOTOSIGNING_REGISTRY", ".photosigning/registry.sqlite3")
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
            )

    def _connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def save(self, record: dict) -> None:
        validate_record(record)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            exists = db.execute(
                "SELECT 1 FROM records WHERE id = ?", (record["record_id"],)
            ).fetchone()
            if count >= MAX_RECORDS and not exists:
                raise PhotoSignError(
                    "This local registry is full (500 records). Use another registry file."
                )
            db.execute(
                "INSERT OR REPLACE INTO records(id, payload) VALUES (?, ?)",
                (record["record_id"], canonical(record).decode()),
            )

    def get(self, record_id: str) -> dict | None:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", record_id):
            raise PhotoSignError("Enter the complete 64-character SHA-256 photo ID.")
        with self._connect() as db:
            row = db.execute(
                "SELECT payload FROM records WHERE id = ?", (record_id.lower(),)
            ).fetchone()
        if not row:
            return None
        record = import_record(row[0].encode())
        if record["record_id"] != record_id.lower():
            raise PhotoSignError("Registry index does not match the authenticated record ID.")
        return record

    def find_by_prefix(self, prefix: str) -> list[dict]:
        """Resolve a short watermark ID without ever accepting it as proof by itself."""
        if not re.fullmatch(r"[0-9a-fA-F]{10}", prefix):
            raise PhotoSignError("TrustMark lookup IDs must contain 10 hexadecimal characters.")
        with self._connect() as db:
            rows = db.execute(
                "SELECT payload FROM records WHERE id LIKE ? ORDER BY id LIMIT 10",
                (prefix.lower() + "%",),
            ).fetchall()
        return [validate_record(json.loads(row[0])) for row in rows]

    def records(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT payload FROM records ORDER BY rowid DESC LIMIT ?", (MAX_RECORDS,)
            ).fetchall()
        return [import_record(row[0].encode()) for row in rows]

    def recognize(
        self,
        data: bytes,
        record_id: str = "",
        *,
        exclude_fingerprint: str = "",
        durable=False,
    ) -> list[dict]:
        photo = read_photo(data, orient=True)
        query = image_features(photo)
        pixels = pixel_hash(photo)
        file_hash = hashlib.sha256(data).hexdigest()
        if record_id:
            item = self.get(record_id)
            records = [item] if item else []
        else:
            records = self.records()
        matches = []
        for record in records:
            if exclude_fingerprint and record_fingerprint(record) == exclude_fingerprint:
                continue
            manifest = record["manifest"]
            distance = hamming(query["phash"], manifest["features"]["phash"])
            exact = file_hash == manifest["source_sha256"] or pixels == manifest["pixel_sha256"]
            geometric = 0
            similar = False
            if not exact:
                # Test the unmodified/resize case conservatively before the crop/rotation path.
                x = np.frombuffer(base64.b64decode(query["gray32"]), dtype=np.uint8).astype(float)
                y = np.frombuffer(
                    base64.b64decode(manifest["features"]["gray32"]), dtype=np.uint8
                ).astype(float)
                if distance <= 8 and min(x.std(), y.std()) >= 10:
                    correlation = float(np.corrcoef(x, y)[0, 1])
                    similar = correlation >= 0.94
                if not similar:
                    geometric = _geometry_match(query, manifest["features"], durable=durable)
            if exact or similar or geometric:
                matches.append(
                    {
                        "record": record,
                        "exact": exact,
                        "phash_distance": distance,
                        "geometric_inliers": geometric,
                        "method": "exact" if exact else "geometric" if geometric else "perceptual",
                    }
                )
        return sorted(
            matches, key=lambda m: (not m["exact"], -m["geometric_inliers"], m["phash_distance"])
        )[:5]
