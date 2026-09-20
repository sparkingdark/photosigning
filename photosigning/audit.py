"""Reproducible local adversarial audit; no uploads, production keys, or registry writes.

Run: python -m photosigning.audit --output docs/robustness-audit
The finite fixture suite measures observed behavior, not universal robustness.
"""

from __future__ import annotations

import argparse
import io
import json
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageOps

from . import core
from .demo import demo_photo
from .majik_image import verify_watermark
from .registry import Registry, import_record
from .workflow import METHODS, inspect_photo, protect_photo


class FixedClock(datetime):
    @classmethod
    def now(cls, tz=None):
        value = cls(2026, 9, 19, 12, tzinfo=UTC)
        return value.astimezone(tz) if tz else value.replace(tzinfo=None)


def encode(photo, format="PNG", **options):
    out = io.BytesIO()
    photo.save(out, format=format, **options)
    return out.getvalue()


def textured_photo():
    rng = np.random.default_rng(412)
    photo = Image.fromarray(rng.integers(35, 220, (800, 1100, 3), dtype=np.uint8))
    photo = photo.filter(ImageFilter.GaussianBlur(3))
    draw = ImageDraw.Draw(photo)
    for _ in range(200):
        x, y = rng.integers(0, 1000), rng.integers(0, 700)
        radius = int(rng.integers(8, 60))
        color = tuple(int(c) for c in rng.integers(20, 230, 3))
        draw.ellipse((x, y, x + radius, y + radius), fill=color)
    return encode(photo)


def crop(photo, fraction):
    # fraction is retained AREA, not retained width.
    width, height = round(photo.width * fraction**0.5), round(photo.height * fraction**0.5)
    x, y = (photo.width - width) // 2, (photo.height - height) // 2
    return photo.crop((x, y, x + width, y + height))


def variations(data):
    photo = core.read_photo(data).convert("RGB")
    yield "Unchanged signed PNG", data
    yield "Metadata stripped / lossless PNG re-encode", encode(photo)
    for quality in [95, 70, 40, 10]:
        yield f"JPEG quality {quality}", encode(photo, "JPEG", quality=quality)
    yield "WebP quality 50", encode(photo, "WEBP", quality=50)
    for width in [1080, 720, 360, 128, 32]:
        resized = photo.resize(
            (width, round(photo.height * width / photo.width)), Image.Resampling.LANCZOS
        )
        yield f"Resize to width {width} + JPEG quality 70", encode(resized, "JPEG", quality=70)
    for fraction in [0.9, 0.5, 0.1]:
        yield f"Crop: retain {round(fraction * 100)}% of area", encode(crop(photo, fraction))
    yield "Rotate 90 degrees", encode(photo.transpose(Image.Transpose.ROTATE_90))
    yield (
        "Rotate 7 degrees with new border",
        encode(photo.rotate(7, expand=True, resample=Image.Resampling.BICUBIC)),
    )
    yield "Horizontal mirror", encode(ImageOps.mirror(photo))
    yield "Grayscale", encode(ImageOps.grayscale(photo).convert("RGB"))
    yield "Invert all colors", encode(ImageOps.invert(photo))
    yield "Posterize to 3 bits per channel", encode(ImageOps.posterize(photo, 3))
    for radius in [1, 3, 8]:
        yield (
            f"Gaussian blur radius {radius}",
            encode(photo.filter(ImageFilter.GaussianBlur(radius))),
        )
    for factor in [0.5, 1.5]:
        yield (
            f"Brightness multiplier {factor}",
            encode(ImageEnhance.Brightness(photo).enhance(factor)),
        )
    yield "Contrast multiplier 2", encode(ImageEnhance.Contrast(photo).enhance(2))
    yield "Saturation multiplier 2", encode(ImageEnhance.Color(photo).enhance(2))
    for deviation in [10, 30]:
        noisy = np.asarray(photo, dtype=float) + np.random.default_rng(55).normal(
            0, deviation, (photo.height, photo.width, 3)
        )
        yield (
            f"Gaussian noise standard deviation {deviation}",
            encode(Image.fromarray(np.clip(noisy, 0, 255).astype(np.uint8))),
        )
    overlaid = photo.copy()
    draw = ImageDraw.Draw(overlaid)
    draw.rectangle(
        (photo.width // 4, photo.height // 3, photo.width * 3 // 4, photo.height * 2 // 3),
        fill="black",
    )
    draw.text((photo.width // 3, photo.height // 2), "OTHER CREDIT", fill="white", font_size=40)
    yield "Opaque central credit overlay", encode(overlaid)
    painted = photo.copy()
    ImageDraw.Draw(painted).rectangle((0, 0, photo.width // 2, photo.height), fill="white")
    yield "Paint over left 50%", encode(painted)
    framed = Image.new("RGB", (photo.width + 140, photo.height + 200), "gray")
    framed.paste(photo, (70, 100))
    yield "Screenshot-like border (simulated)", encode(framed, "JPEG", quality=75)
    combined = crop(photo, 0.5).rotate(7, expand=True, resample=Image.Resampling.BICUBIC)
    combined.thumbnail((600, 600), Image.Resampling.LANCZOS)
    combined = ImageEnhance.Contrast(combined).enhance(1.5)
    yield (
        "Combined crop + rotate + resize + contrast + JPEG 30",
        encode(combined, "JPEG", quality=30),
    )
    yield "Complete opaque replacement", encode(Image.new("RGB", photo.size, "white"))


def run_audit():
    owner = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    other = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
    results, threats = [], []
    with tempfile.TemporaryDirectory(prefix="photosigning-audit-") as directory:
        for label, source in [("landscape", demo_photo()), ("textured", textured_photo())]:
            registry = Registry(Path(directory) / f"{label}.sqlite3")
            with (
                patch("photosigning.registry.datetime", FixedClock),
                patch("photosigning.core.datetime", FixedClock),
            ):
                protected = protect_photo(
                    source,
                    owner,
                    name="Original photographer",
                    details={},
                    method=METHODS[1],
                    registry=registry,
                )
            for name, data in variations(protected.data):
                exact = core.verify_photo(data).valid
                watermark = verify_watermark(data).valid
                matches = registry.recognize(data)
                report = inspect_photo(data, registry=registry, trusted_key=owner.public_key())
                results.append(
                    {
                        "fixture": label,
                        "attempt": name,
                        "exact": exact,
                        "watermark": watermark,
                        "registry_match": bool(matches),
                        "result": report["status"],
                        "identity_trusted": report["identity_trusted"],
                    }
                )

            # Copy the exact embedded record into unrelated pixel content.
            signed_image = core.read_photo(protected.data)
            payload = core._extract(signed_image.tobytes(), 3, protected.exact.payload_bytes)
            unrelated = Image.new("RGB", signed_image.size, (80, 50, 120))
            raw = bytearray(unrelated.tobytes())
            core._embed(raw, 3, payload)
            transplanted = encode(Image.frombytes("RGB", unrelated.size, bytes(raw)))
            threats.append(
                {
                    "fixture": label,
                    "attempt": "Copy exact signature onto unrelated image",
                    "result": inspect_photo(transplanted, registry=registry)["status"],
                }
            )
            edited_record = json.loads(json.dumps(protected.record))
            edited_record["manifest"]["photographer"] = "Other photographer"
            try:
                import_record(json.dumps(edited_record).encode())
                outcome = "INCORRECTLY_ACCEPTED"
            except core.PhotoSignError:
                outcome = "rejected"
            threats.append(
                {
                    "fixture": label,
                    "attempt": "Change signed photographer name in record",
                    "result": outcome,
                }
            )
            # Anyone can legitimately generate another key; that does not confer ownership.
            resigned = core.sign_photo(source, other, name="Original photographer")
            for trusted in [False, True]:
                report = inspect_photo(
                    resigned.png,
                    registry=registry,
                    trusted_key=owner.public_key() if trusted else None,
                )
                threats.append(
                    {
                        "fixture": label,
                        "attempt": "Re-sign copied image with different key "
                        + (
                            "(trusted owner key supplied)"
                            if trusted
                            else "(no trusted key supplied)"
                        ),
                        "result": report["status"],
                        "identity_trusted": report["identity_trusted"],
                        "provenance_conflicts": len(report.get("provenance_conflicts", [])),
                    }
                )
            # A stolen private key can make valid signatures. Cryptography cannot infer consent.
            compromised = core.sign_photo(encode(unrelated), owner, name="Original photographer")
            report = inspect_photo(compromised.png, trusted_key=owner.public_key())
            threats.append(
                {
                    "fixture": label,
                    "attempt": "Attacker has a copy of the owner's private key",
                    "result": report["status"],
                    "identity_trusted": report["identity_trusted"],
                }
            )
            for seed in range(10):
                unrelated_noise = np.random.default_rng(seed + 900).integers(
                    0, 256, (600, 800, 3), dtype=np.uint8
                )
                report = inspect_photo(encode(Image.fromarray(unrelated_noise)), registry=registry)
                threats.append(
                    {
                        "fixture": label,
                        "attempt": f"Unrelated negative control {seed + 1}",
                        "result": report["status"],
                    }
                )
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": "Two deterministic synthetic images; "
        "finite local transformations. No real platform uploads, camera corpus, AI reconstruction, "
        "or exhaustive adversarial search. No rate is a real-world probability.",
        "transformations": results,
        "threats": threats,
    }


def write_report(report, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
    totals = Counter(row["result"] for row in report["transformations"])
    lines = [
        "# PhotoSigning adversarial audit",
        "",
        f"Generated: {report['generated_at']}",
        "",
        report["scope"],
        "",
        "**No foolproof or theft-preventing claim is supported.**",
        "",
        (
            f"Evaluated {len(report['transformations'])} image/transform combinations and "
            f"{len(report['threats'])} forgery, re-signing, key-compromise, and negative-control cases."
        ),
        "",
        "Workflow result counts: " + ", ".join(f"{k}={v}" for k, v in sorted(totals.items())) + ".",
        "",
        (
            "Exact checks establish covered-pixel integrity. A watermark authenticates a perceptual "
            "fingerprint, which tolerates edits and can collide. Registry matches are candidates, not "
            "proof of ownership. No match does not prove a photo is unsigned or free to use."
        ),
        "",
        "## Transformation results",
        "",
        "| Fixture | Attempt | Exact | Watermark | Registry candidate | Workflow |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in report["transformations"]:
        flags = ["yes" if row[k] else "no" for k in ["exact", "watermark", "registry_match"]]
        lines.append(
            f"| {row['fixture']} | {row['attempt']} | {' | '.join(flags)} | {row['result']} |"
        )
    lines += [
        "",
        "## Misuse and forgery checks",
        "",
        "| Fixture | Attempt | Result |",
        "| --- | --- | --- |",
    ]
    for row in report["threats"]:
        suffix = (
            f"; other signer records={row['provenance_conflicts']}"
            if "provenance_conflicts" in row
            else ""
        )
        lines.append(f"| {row['fixture']} | {row['attempt']} | {row['result']}{suffix} |")
    lines += [
        "",
        "## Boundaries",
        "",
        "- A thief can copy a photo unchanged; signatures do not enforce usage rights.",
        (
            "- A new valid signature establishes control of a new key, not authorship. Local conflicting "
            "records are a warning, not a verdict; collaboration and key rotation can also explain them."
        ),
        (
            "- Stolen private keys can produce authentic signatures. Password-protected backups and "
            "trusted identity/key history remain necessary."
        ),
        "- Local record timestamps are self-reported, not independently witnessed. No trusted timestamp service is configured.",
        "- If original pixels, watermark, and matching visual structure are all lost, recovery is impossible from the derivative alone.",
        (
            "- AI redraw, inpainting, screenshot capture on real devices, platform-specific processing, "
            "and adaptive perceptual-hash collision attacks are not covered by this finite run."
        ),
        "",
        "Reproduce with `uv run python -m photosigning.audit --output docs/robustness-audit`.",
        "",
    ]
    path.with_suffix(".md").write_text("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="docs/robustness-audit")
    args = parser.parse_args()
    report = run_audit()
    write_report(report, args.output)
    print(
        json.dumps(
            {
                "transformations": Counter(r["result"] for r in report["transformations"]),
                "threats": len(report["threats"]),
                "report": args.output,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
