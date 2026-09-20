# PhotoSigning technical reference

[Back to the README](../README.md) · [User guide](user-guide.md) ·
[Contributing](../CONTRIBUTING.md)

Source paths and commands below are relative to the repository root. The custom
pixel-signature and watermark formats have not undergone an independent security audit.

## Exact signature format and integrity

`photosigning/core.py` implements the versioned `photosigning/v1` format. It uses
[Ed25519 from cryptography](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/)
and Pillow for image decoding/encoding. This pixel format is custom and has not undergone
an independent security audit. Standard C2PA credentials are added separately by
`photosigning/content_credentials.py` using the official SDK.

Input images are normalized to 8-bit RGB or RGBA, with EXIF orientation applied when
signing. One least-significant bit per RGB channel carries the record, in row-major
order; alpha is never used for storage. Only occupied RGB channels can change, by at
most one intensity level each. Higher bit-depth and other color modes are converted.

The record is an 8-byte `PHOTOMK1` magic, a 4-byte big-endian payload length, and canonical
ASCII JSON containing a manifest and a base64-encoded signature. The manifest includes
dimensions, mode, photographer, details, UTC signing time, raw public key, and SHA-256
pixel digest. JSON keys are sorted, separators are compact, and strings are ASCII escaped.
The Ed25519 signature covers `PhotoSigning/manifest/v1\0` followed by canonical manifest
bytes. Both JSON and signature base64 encodings are required to be canonical.

The digest covers `PhotoSigning/pixels/v1\0`, canonical image dimensions/mode, and decoded
pixels, with **only the occupied carrier LSBs cleared**. All other bits—including unused
LSBs and all alpha bits—are hashed. The signature authenticates the manifest; strict
envelope encoding prevents undetected changes to the carrier record. Fixed-width digest
and signature fields allow the occupied region to be determined before hashing.

Bounds: 40 MB files, 25 million pixels, 32 KiB embedded payload, single-frame images.
Private-key backups use encrypted PKCS8 PEM with `BestAvailableEncryption`.

## Invisible watermark and recognition implementation

The maximum-resilience option adds the official MIT-licensed
[Adobe TrustMark Q](https://github.com/adobe/trustmark), an algorithm on the
[C2PA soft-binding list](https://spec.c2pa.org/softbinding-alg-list/softbinding-algorithm-list.json).
It uses BCH_SUPER error correction (40 payload bits, up to eight corrected bit errors),
strength 1.25, rotation trials, and the optional crop detector. The 40-bit value is the
first ten hexadecimal digits of the 256-bit record ID. It is only a lookup tag: verification
requires the full signed registry record and an independent visual match, preventing a
copied tag alone from being accepted. The C2PA manifest includes the corresponding
`c2pa.soft-binding` assertion using `com.adobe.trustmark.Q`.

Maximum resilience does not stack the custom block-DCT watermark with TrustMark. Stacking
both pixel encoders created visible square texture in smooth areas and could make the two
detectors interfere. The old DCT encoder remains in the Python API so existing files can be
verified and regression-tested, but it is no longer offered as a signing choice in the UI.
The recommended workflow uses TrustMark as its only lossy pixel layer.

TrustMark downloads approximately 145 MB of model weights on first use and runs locally
through PyTorch; photos are not uploaded. Its authors report robustness to common social
platform processing, JPEG, screenshots, and moderate cropping, while explicitly stating
that it can be removed. This app therefore calls the option “maximum resilience,” not
“survives everything.”

`photosigning/majik_image.py` adapts Majik's DCT/pHash, compact public-key stub, and
domain-separated image payload to Python. The upstream raw unit-parity embedding and
content-dependent skipped blocks are replaced with fixed 512×512 coordinate normalization,
two 8×8 mid-frequency carriers, quantization-index modulation (step 48), four interleaved
repetitions, and 80 Reed–Solomon parity bytes. The carrier operates on luminance; up to
four reprojection passes compensate for resizing interpolation. Changes are bounded to
28 intensity levels per RGB channel before the exact-signature LSB layer. This is more
robust, but can be visible in some images: inspect the downloaded result. Fully opaque
images with both dimensions at least 512 pixels are required; low-detail or unrecoverable
inputs are rejected instead of silently producing a broken watermark.

The `PSR2` proof is 150 bytes: magic (4), version (2), pHash (8), public key (32), UTC Unix
milliseconds (8), SHA-256 record ID (32), and Ed25519 signature (64). Its signed payload is
`photosigning-resilient-v2:` followed by canonical JSON `{id,pHash,ts,v}`. Error correction
encodes it to 230 bytes before repetition. Recovery verifies the Ed25519 signature, then
requires a perceptual Hamming distance at most 8. The pHash preserves Majik's DCT median
and two-half bit ordering, with Lanczos antialiasing added before downsampling.
Recovery also tries all seven rotated/reflected orientations when the original orientation
fails. Every candidate must pass the same signature and perceptual checks; the report
records the normalization used. This does not provide arbitrary-angle or crop invariance.

Registry recognition first compares exact source-file and decoded-pixel hashes. For
derivatives it combines perceptual Hamming distance ≤8 and grayscale correlation ≥0.94,
or ORB feature matching with a RANSAC homography, at least 12 inliers, a 60% inlier ratio,
and minimum spatial coverage. Low-detail images do not pass the perceptual fallback.
These thresholds reduce false matches, but do not turn similarity into a cryptographic
identity test. Every matching record's signature is checked independently.

This is a **distinct PhotoSigning format**, not wire-compatible with Majik `.mjksig` or
`MSIG` files. It does not port Majik's full SDK or its ML-DSA-87, blockchain, or TSA
features. The selected upstream image fallback itself uses Ed25519. The upstream version
and license are retained under `third_party/majik-signature`.

## Python API

This example uses the low-level exact pixel-signature API. It does not add C2PA
credentials or a TrustMark watermark. The application coordinates those layers in
`photosigning/workflow.py`. Run the example from the repository environment.

```python
from pathlib import Path
from photosigning.core import generate_key, sign_photo, verify_photo

key = generate_key()  # Save an encrypted backup with export_private_key().
signed = sign_photo(
    Path("original.jpg").read_bytes(),
    key,
    name="Ada Photographer",
    details={"camera_make": "Fujifilm", "camera_model": "X-T5"},
)
Path("signed.png").write_bytes(signed.png)
result = verify_photo(signed.png, trusted_key=key.public_key())
assert result.valid and result.trusted
```

## Research basis and practical limit

The design follows the layered approach described by the
[C2PA Durable Content Credentials proposal](https://opensource.contentauthenticity.org/docs/durable-cr/):
put the cryptographic manifest in the asset, add a robust pixel signal, and retain an
authenticated record that can be found when platforms remove the manifest. It also agrees
with the linked [IMATAG overview](https://www.imatag.com/blog/image-authenticity-verification-methods-what-works-today),
which says that no single authenticity technique solves the problem and recommends combining
provenance, watermarking, and fingerprinting.

The public research does not support a “survives all” claim. The AISTATS 2025 paper
[On the Difficulty of Constructing a Robust and Publicly-Detectable Watermark](https://proceedings.mlr.press/v258/fairoze25a.html)
shows the unresolved tension between robustness, public detection, and unforgeability.
PhotoSigning uses Adobe's [TrustMark ICCV 2025 implementation](https://github.com/adobe/trustmark);
its own FAQ says that a determined attacker can remove it. Google's 2025
[SynthID-Image report](https://arxiv.org/abs/2510.09263) likewise describes robustness as
a tradeoff rather than perfect security.

In the included tests, the maximum-resilience export is recovered after simulated social
resizing and JPEG recompression, and after a centered crop retaining 70% of the image area
plus JPEG quality 70. A copied TrustMark tag on an unrelated image is rejected. These are
finite tests, not promises about Facebook, WhatsApp, future platform pipelines, screenshots,
large crops, generative edits, opaque overlays, or deliberate watermark removal.

## Reproducible adversarial audit

```bash
uv run python -m photosigning.audit --output docs/robustness-audit
```

The [audit report](robustness-audit.md) and its JSON counterpart preserve failures as
well as successes. The audit exercises 70 transformation cases on two deterministic
synthetic images and 30 forgery, re-signing, stolen-key, and unrelated-image cases. It uses
temporary registries and public test keys, never your saved registry or private key.
It is a finite engineering check, not an exhaustive security assessment or platform guarantee.

The distinction between exact integrity and image matching also appears in
[C2PA's soft-binding specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_validating_soft_binding_matches):
soft bindings can recover a related manifest without establishing that its exact content
hash matches the edited asset. PhotoSigning embeds and verifies standard C2PA manifests.
Its custom DCT watermark is not a C2PA soft-binding resolver. Maximum resilience declares
the registered TrustMark algorithm and resolves the recovered tag against this app's signed
local registry; it does not publish or retrieve manifests through a public C2PA repository.
There is no independently witnessed timestamp service.
