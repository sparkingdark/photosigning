"""Adobe TrustMark soft binding for high-resilience registry lookup.

TrustMark carries a short identifier, not a signature. A recovered identifier is
only accepted after the corresponding signed registry record also visually matches.
"""

from __future__ import annotations

import io
import re
import threading
from dataclasses import dataclass
from functools import lru_cache

from .core import PhotoSignError, read_photo

ALGORITHM = "com.adobe.trustmark.Q"
SCHEMA = 0  # BCH_SUPER: 40 payload bits, up to 8 corrected bit errors.
TAG_HEX_LENGTH = 10
STRENGTH = 1.25
_MODEL_LOCK = threading.Lock()


@dataclass(frozen=True)
class TrustMarkProof:
    valid: bool
    message: str
    tag: str | None = None
    schema: int | None = None


def record_tag(record_id: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", record_id):
        raise PhotoSignError("The photo record ID must be a SHA-256 hash.")
    return record_id[:TAG_HEX_LENGTH].lower()


def tag_bits(tag: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{10}", tag):
        raise PhotoSignError("TrustMark lookup IDs must contain 10 hexadecimal characters.")
    return f"{int(tag, 16):040b}"


@lru_cache(maxsize=1)
def _model():
    try:
        from trustmark import TrustMark

        return TrustMark(
            verbose=False,
            device="cpu",
            model_type="Q",
            encoding_type=TrustMark.Encoding.BCH_SUPER,
            loadRemover=False,
            loadBBoxDetector=True,
        )
    except Exception as exc:
        raise PhotoSignError(
            "Adobe TrustMark could not start. Run `uv sync`, keep internet available for "
            "the first model download, then restart the app."
        ) from exc


def embed_trustmark(data: bytes, record_id: str) -> bytes:
    photo = read_photo(data, orient=True)
    if min(photo.size) < 150:
        raise PhotoSignError(
            "Maximum resilience needs both image dimensions to be at least 150 pixels."
        )
    if photo.mode == "RGBA" and photo.getchannel("A").getextrema() != (255, 255):
        raise PhotoSignError(
            "Maximum resilience requires an opaque image. Flatten transparency first."
        )
    bits = tag_bits(record_tag(record_id))
    try:
        with _MODEL_LOCK:
            marked = _model().encode(photo.convert("RGB"), bits, MODE="binary", WM_STRENGTH=STRENGTH)
        output = io.BytesIO()
        marked.save(output, format="PNG")
        result = output.getvalue()
        proof = verify_trustmark(result, use_crop_detector=False)
        if not proof.valid or proof.tag != record_tag(record_id):
            raise PhotoSignError(
                "This photo could not carry a reliable TrustMark. Try a larger or more detailed image."
            )
        return result
    except PhotoSignError:
        raise
    except Exception as exc:
        raise PhotoSignError(f"TrustMark embedding failed: {exc}") from exc


def verify_trustmark(data: bytes, *, use_crop_detector: bool = True) -> TrustMarkProof:
    try:
        photo = read_photo(data, orient=True).convert("RGB")
        if min(photo.size) < 100:
            return TrustMarkProof(False, "Image is too small to recover Adobe TrustMark.")
        with _MODEL_LOCK:
            bits, present, schema = _model().decode(
                photo, MODE="binary", ROTATION=True, DETECTFIRST=False
            )
            if not present and use_crop_detector:
                bits, present, schema = _model().decode(
                    photo, MODE="binary", ROTATION=True, DETECTFIRST=True
                )
        if not present or schema != SCHEMA or not re.fullmatch(r"[01]{40}", bits):
            return TrustMarkProof(False, "No valid Adobe TrustMark identifier recovered.")
        tag = f"{int(bits, 2):010x}"
        return TrustMarkProof(
            True,
            "Adobe TrustMark identifier recovered. A signed registry record and visual "
            "match are still required before accepting provenance.",
            tag,
            schema,
        )
    except PhotoSignError as exc:
        return TrustMarkProof(False, str(exc))
    except (RuntimeError, ValueError, TypeError, AssertionError, OSError):
        return TrustMarkProof(False, "Adobe TrustMark could not be decoded from this image.")


def c2pa_soft_binding(record_id: str) -> dict:
    bits = tag_bits(record_tag(record_id))
    return {
        "label": "c2pa.soft-binding",
        "data": {"alg": ALGORITHM, "blocks": [{"scope": {}, "value": f"{SCHEMA}*{bits}"}]},
    }
