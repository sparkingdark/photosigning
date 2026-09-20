"""Four signing options with public keys carried automatically in every proof."""

import re
from dataclasses import dataclass, replace
from datetime import datetime

from .content_credentials import (
    Credentials,
    embed_credentials,
    inspect_credentials,
    local_credentials,
)
from .core import PhotoSignError, SignedPhoto, fingerprint, sign_photo, verify_photo
from .majik_image import embed_watermark, verify_watermark
from .registry import Registry, create_record, record_fingerprint
from .trustmark_image import embed_trustmark, verify_trustmark

MAXIMUM_RESILIENCE = "Maximum resilience · TrustMark + registry"
METHODS = [
    "Exact pixel signature",
    "Invisible resilient watermark",
    "Registry recognition only",
    MAXIMUM_RESILIENCE,
]


@dataclass(frozen=True)
class PhotoExport:
    data: bytes
    record: dict
    method: str
    exact: SignedPhoto | None
    c2pa: dict | None = None


def protect_photo(
    data,
    key,
    *,
    name,
    details,
    method=METHODS[0],
    registry: Registry | None = None,
    include_c2pa=True,
    c2pa_credentials: Credentials | None = None,
):
    if method not in METHODS:
        raise PhotoSignError("Choose a supported signing method.")
    if method == MAXIMUM_RESILIENCE and registry is None:
        raise PhotoSignError(
            "Maximum resilience needs the local registry. Turn on ‘Save unique photo ID’."
        )
    record = create_record(data, key, name=name, details=details)
    exact = None
    c2pa = None
    if method == METHODS[2]:
        output = data  # registry mode preserves the original file byte-for-byte
    else:
        output = data
        if method == METHODS[1]:
            timestamp = int(
                datetime.fromisoformat(record["manifest"]["signed_at"]).timestamp() * 1000
            )
            output = embed_watermark(data, key, record["record_id"], timestamp)
        elif method == MAXIMUM_RESILIENCE:
            # Do not stack the block-DCT watermark with TrustMark. Combining two
            # independent pixel perturbations causes visible 8x8 texture and can
            # make both detectors less reliable.
            output = embed_trustmark(data, record["record_id"])
        exact = sign_photo(
            output, key, name=name, details={**details, "record_id": record["record_id"]}
        )
        output = exact.png
        if include_c2pa:
            output, c2pa = embed_credentials(
                output, data, record, method, c2pa_credentials or local_credentials(key)
            )
            exact = replace(exact, png=output)
        if not verify_photo(output, key.public_key()).valid:
            raise PhotoSignError("The exact signature did not pass its output check.")
        if method == METHODS[1] and not verify_watermark(output).valid:
            raise PhotoSignError("The invisible watermark did not pass its output check.")
        if method == MAXIMUM_RESILIENCE:
            trustmark = verify_trustmark(output, use_crop_detector=False)
            if not trustmark.valid:
                raise PhotoSignError("Adobe TrustMark did not pass its output check.")
    if registry is not None:
        registry.save(record)
    return PhotoExport(output, record, method, exact, c2pa)


def inspect_photo(data, *, registry: Registry | None = None, record_id="", trusted_key=None):
    """Keep exact integrity, signed perceptual evidence, and candidates distinct."""
    if record_id and not re.fullmatch(r"[0-9a-fA-F]{64}", record_id):
        raise PhotoSignError("Enter the complete 64-character SHA-256 photo ID.")
    exact = verify_photo(data)
    wanted = fingerprint(trusted_key) if trusted_key is not None else None
    report = {
        "status": "unrecognized",
        "exact_valid": exact.valid,
        "watermark_valid": False,
        "trustmark_valid": False,
        "trustmark": None,
        "identity_trusted": False,
        "manifest": None,
        "record_id": None,
        "fingerprint": None,
        "candidates": [],
        "provenance_conflicts": [],
        "message": exact.message,
        "c2pa": inspect_credentials(data),
    }
    if exact.valid:
        report.update(
            status="exact",
            manifest=exact.manifest,
            fingerprint=exact.fingerprint,
            record_id=exact.manifest["details"].get("record_id"),
            message=exact.message,
        )
    else:
        watermark = verify_watermark(data)
        if watermark.valid:
            report.update(
                status="watermark",
                watermark_valid=True,
                record_id=watermark.record_id,
                fingerprint=watermark.fingerprint,
                message=watermark.message,
                phash_distance=watermark.distance,
                normalization=watermark.normalization,
            )
            if registry is not None:
                record = registry.get(watermark.record_id)
                if record and record_fingerprint(record) == watermark.fingerprint:
                    report["manifest"] = record["manifest"]
        elif registry is not None:
            trustmark = verify_trustmark(data)
            report["trustmark"] = {
                "present": trustmark.valid,
                "tag": trustmark.tag,
                "message": trustmark.message,
            }
            matches = []
            if trustmark.valid:
                tagged_records = registry.find_by_prefix(trustmark.tag)
                for tagged_record in tagged_records:
                    matches.extend(
                        registry.recognize(data, tagged_record["record_id"], durable=True)
                    )
                # The tag alone is copyable. Only an authenticated registry record
                # whose visual fingerprint also matches is accepted.
                if len(matches) == 1:
                    item = matches[0]["record"]
                    report.update(
                        status="trustmark",
                        trustmark_valid=True,
                        manifest=item["manifest"],
                        record_id=item["record_id"],
                        fingerprint=record_fingerprint(item),
                        message="Adobe TrustMark recovered and matched an authenticated visual registry record.",
                    )
                elif not tagged_records:
                    report.update(
                        status="trustmark_unresolved",
                        message="Adobe TrustMark was recovered, but its signed registry record is unavailable.",
                    )
                elif not matches:
                    report.update(
                        status="trustmark_mismatch",
                        message="Adobe TrustMark was recovered, but this image does not visually match its signed record.",
                    )
            if report["status"] != "trustmark":
                matches = registry.recognize(data, record_id)
            report["candidates"] = matches
            if matches and report["status"] != "trustmark":
                if len(matches) == 1 and matches[0]["exact"]:
                    item = matches[0]["record"]
                    report.update(
                        status="registered_exact",
                        exact_valid=True,
                        manifest=item["manifest"],
                        record_id=item["record_id"],
                        fingerprint=record_fingerprint(item),
                        message="Image matches the pixels or file hash in an authenticated registry record.",
                    )
                else:
                    report.update(
                        status="candidates",
                        message="Visual match candidates found. Their records are "
                        "authentic, but similarity is not cryptographic proof that this edited photo was signed.",
                    )
    if report["status"] == "unrecognized" and report["c2pa"]["valid"]:
        report.update(status="c2pa", message=report["c2pa"]["message"])
    # A valid new signature must not hide matching records signed by other keys.
    # This is a provenance warning, not an ownership judgment: key rotation and
    # legitimate collaboration can also produce multiple signing identities.
    if registry is not None and report["fingerprint"]:
        matches = registry.recognize(data, exclude_fingerprint=report["fingerprint"])
        report["provenance_conflicts"] = [
            {
                "record_id": item["record"]["record_id"],
                "photographer": item["record"]["manifest"]["photographer"],
                "fingerprint": record_fingerprint(item["record"]),
                "match_method": item["method"],
            }
            for item in matches
        ]
    if wanted and report["fingerprint"]:
        report["identity_trusted"] = report["fingerprint"] == wanted
        if not report["identity_trusted"]:
            report.update(
                status="wrong_key",
                message="The recovered signer does not match the trusted key you selected.",
            )
    if record_id and report["record_id"] and report["record_id"] != record_id.lower():
        report.update(
            status="wrong_record",
            message="The recovered photo ID differs from the ID you supplied.",
        )
    return report
