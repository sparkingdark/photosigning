# PhotoSigning

A Python-only photo signing app with a Streamlit interface. Sign your name, camera model,
lens, and EXIF details; recover an invisible watermark after common sharing edits; or
recognize registered photos using visual fingerprints. Verification keys are included
in proofs and records: **no separate public-key file is needed**. Private keys are never embedded.
Standard **C2PA Content Credentials** are also enabled by default for signed PNGs,
including the invisible-watermark option.

The invisible image watermark is a modified Python adaptation of the Apache-2.0
[Majik Signature image-stamping implementation](https://github.com/Majikah/majik-signature/tree/main/src/core/stamp).
See [attribution and modifications](third_party/majik-signature/NOTICE.md).

## License and source provenance

PhotoSigning is licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE) for
the adapted Majik Signature code and [third-party notices](THIRD_PARTY_NOTICES.md)
for dependency and asset licensing. Dependencies retain their own licenses.

The maintainer reports that the code was generated using OpenAI Codex, with the
Majik Signature source supplied as a reference for the credited adaptation.
This is an independent project; mentioning upstream projects does not imply endorsement.

For the publication review and first GitHub upload, see
[Publishing PhotoSigning](docs/publishing.md).

## Run locally

Requires Python 3.11 or newer. From this directory:

```bash
uv sync
uv run streamlit run app.py
```

Open **http://localhost:8501**. The default configuration listens only on localhost.
Dependencies are recorded in `uv.lock` for reproducible installation.

Without uv:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .
python -m streamlit run app.py
```

On Windows, activate with `.venv\Scripts\activate` instead.

## Workflow

1. **Create a signing key** in the sidebar, or import an existing Ed25519 PEM key in
   **Your keys**. Save the encrypted private-key backup and its password somewhere safe.
   Keys are held only in the current Streamlit session; restarting or losing that session
   can lose an unbacked-up key. Public-key export is optional; never share the private key.
2. **Sign a photo.** Upload a JPEG, PNG, WebP, or TIFF, or try the built-in demo landscape.
   Review your name and the camera/EXIF details and choose a protection method below.
   Optionally save the photo's unique ID and signed record to the local registry (enabled
   by default). Download the photo and back up the record JSON. Embedded outputs pass
   C2PA, exact-signature and, when selected, watermark self-checks before download is offered.
3. **Verify a photo.** Upload an original or edited copy. C2PA validation is shown separately.
   The app automatically tries exact
   signature verification, invisible watermark recovery, then registry recognition. Keys
   are recovered automatically. A trusted public key is only needed if you want to check
   a particular signing identity. You can optionally supply a unique photo ID.
4. **Photo registry.** Browse records, look up a SHA-256 photo ID, or import/export signed
   JSON records to move recognition and signed details to another installation. A verifier
   without the registry can still check the invisible proof and recover its photo ID and
   signer fingerprint, but needs the record to display the full name and EXIF details.

No cloud account, JavaScript build, or external image service is required.
When hosted remotely, Streamlit uploads photos and imported keys to the machine running
the app; run it locally to keep these on your own device. Do not expose an unauthenticated
instance publicly. The optional UI web font has a local sans-serif fallback.

## Three protection options

| Method | Image changes | What survives / what the result means |
| --- | --- | --- |
| Exact pixel signature | Selected RGB least-significant bits; PNG output | Pixel-preserving copies. Checks exact integrity. Edits invalidate this layer. |
| Registry recognition only | None; original file returned byte-for-byte | Signed record supports exact-hash lookup and approximate recognition of resized, cropped, rotated, or lightly adjusted copies. Edited matches are **candidates**, not signatures on those copies. |
| Maximum resilience (default) | Adobe TrustMark Q + authenticated registry match + exact signature + C2PA; PNG output; registry required | Strongest option for social sharing. The C2PA-approved 40-bit TrustMark tag is accepted only when its authenticated registry record also visually matches. Still cannot survive every transformation or deliberate removal. |

No technique survives **every** photo manipulation. A tiny thumbnail, large crop, heavy
editing, opaque overlay, or intentional removal can destroy the watermark and the visual
evidence needed to recognize the photo. These tests simulate sharing transformations;
they do not guarantee any particular social platform's current processing pipeline.

There is no signing method that prevents theft or survives arbitrary replacement of the
image. A person can copy an intact signed image, remove identifying visual information,
or sign a copy under a new key. Keeping the original and its signed record preserves
evidence even when a derivative can no longer be recognized. The app's self-reported
signing time is not independent proof of when a photograph existed.

The new **SHA-256 photo ID** hashes the signed record's canonical manifest, including
source hash, signed details, timestamp, key, and visual features. It is a stable lookup
identifier for that record. It is not a secret, proof of ownership, or a content hash that
magically stays constant after editing. The perceptual hash is a separate, non-unique,
non-cryptographic similarity feature. A plain SHA-256 image hash necessarily changes when
the image file changes.

## C2PA Content Credentials

The **Embed C2PA Content Credentials** checkbox is enabled by default for **Exact pixel
signature**, **Invisible resilient watermark**, and **Maximum resilience**. Sign again and
download the new PNG; files exported before this feature was added do not gain C2PA
automatically. The registry-only option preserves the original file and adds no new
credential, regardless of the checkbox.

The app uses the [official CAI Python SDK](https://github.com/contentauth/c2pa-python)
to embed a signed C2PA manifest and certificate chain in the PNG after pixel signing.
It checks the final export with the SDK and rechecks the pixel proofs. No private key is
embedded. Open **Verify a photo** to see the **C2PA · Content Credentials** result and
expand **View C2PA manifest and validation** for its assertions and downloadable report.
Compatible external C2PA viewers can read the embedded credentials without a public-key
file. A normal gallery does not necessarily display a Content Credentials badge; nothing
is drawn visibly on the photograph.

By default, the app issues a local certificate for your current Ed25519 key. It validates
the signature but **does not add this certificate to a trust store**. Expect external viewers
to show an unknown/untrusted signer. This is different from missing or tampered credentials.
For an issued certificate, go to **Your keys → C2PA signing certificate (optional)** and
import a leaf-first PEM chain and its matching private key (Ed25519, ES256/384/512, or
RSA-PSS/SHA-256 with RSA ≥2048). The C2PA signer can differ from the pixel-signing key.
An import alone does not establish trust; the issuing authority must be accepted by the
verifier. See the [certificate requirements](https://opensource.contentauthenticity.org/docs/signing/get-cert/).

### Real-world creator identity

The public key is already embedded, so “unknown identity” does **not** mean that a verifier
needs a separate public-key file. It means the included key was created locally and no
independent authority has established who controls it. A typed photographer name, EXIF field,
or self-signed certificate cannot prove a person’s identity.

C2PA claim-signing trust and creator identity are separate. A trusted claim certificate says
that a recognized product or certificate holder generated the Content Credential. A
[CAWG identity assertion](https://opensource.contentauthenticity.org/docs/manifest/reading/reading-cawg-id/)
can bind a creator to third-party evidence such as document verification, control of a website
or social account, or membership in an organization. The identity provider must issue and sign
that evidence; PhotoSigning cannot create trustworthy identity evidence by itself.

For a personal workflow today:

1. Export the protected photograph from PhotoSigning.
2. Use a compatible identity provider or
   [Adobe Content Authenticity](https://contentauthenticity.adobe.com/) to verify a name or
   connect supported accounts and add the creator identity to the exported file.
3. Verify the resulting Content Credential in a CAWG-aware verifier. Keep the PhotoSigning
   registry record because social platforms may still remove the entire C2PA manifest.

For a private team, members can approve each other's public-key fingerprints through an
already trusted channel. That proves a match to the approved key inside that team; it is not
a globally recognized identity credential.

Name and camera/lens fields use a standard [CAWG metadata assertion](https://cawg.io/metadata/1.1/).
The complete reviewed details, record ID and pixel-signing public key are also signed in
an `org.photosigning.provenance` assertion. These remain user-supplied claims. The manifest
records opening and editing an existing image, not a certified camera capture. Existing
C2PA history is retained as a source ingredient and may contain earlier metadata or thumbnails.

Signing and verification run offline, without remote-manifest fetching, a timestamp authority,
or live revocation checks. Imported credentials live only in the server session. Local
certificates expire after one year; without a trusted timestamp, validation after certificate
expiry is not guaranteed. The UI's trust result reflects the SDK's configured trust store,
which may differ from another viewer's trust list.

**C2PA can be stripped by social-media processing, re-encoding, or metadata removal.**
The invisible watermark can sometimes survive those operations, but recovering it does
not recreate or validate a missing C2PA manifest. Keep the original downloaded PNG and
its signed registry record. Failed C2PA signing stops the requested export; it never
silently falls back to a file without credentials.

## Local registry and portability

Records persist in `.photosigning/registry.sqlite3` (ignored by Git). Set
`PHOTOSIGNING_REGISTRY` to use another SQLite path. No database server is required.
Up to 500 records are supported for bounded local searches. The registry stores signed
details and features, including a 32×32 grayscale representation and ORB descriptors;
it does not store full-resolution photos or private keys. All users of the same hosted
instance share this local registry; this app is intended for a single trusted local user.

Each record carries an Ed25519 public key and signature. Imports and database reads
authenticate records before using their claims/features. Back up JSON records to another
machine or your own storage; the app does not synchronize or publish them automatically.
Deleting the local database removes local lookup/recognition until records are imported
again. Multiple possible matches are displayed without choosing an owner.
When an embedded signature is valid, verification still checks the registry for matching
photos registered by other keys and shows a provenance warning. The warning does not
accuse anyone of theft: collaborators, licensees, and key rotation can also explain it.
It only covers the records present in this local registry, not every image on the internet.

## What verification means

- A successful integrity check confirms that the embedded manifest was signed by the
  embedded public key and that the covered pixels match that manifest.
- Supplying an independently trusted public key also confirms that the expected key
  signed the image. Without this check, a name alone is **not verified identity**.
- Names, EXIF values, and timestamps are claims by the signer, not certified facts.
  The timestamp uses the signing machine's clock. There is no trusted timestamp service.
- This does not prove copyright ownership, prevent copying, or locate images online.
  Anyone can remove the signature or sign another image with a different key.
- **Keep the original signed PNG.** Only it offers exact pixel integrity. Edited copies
  may retain the invisible proof or be recognized from a registered record. These are
  deliberately separate result categories, and fallback never claims exact integrity.
- Perceptual hashes can collide and be manipulated. Neither an authentic perceptual
  watermark nor a visual registry match proves that an edited image has not been changed
  maliciously, proves ownership, or establishes a person's real-world identity.
- Ordinary file metadata and ICC color profiles are outside the pixel-signature boundary.
  The separate C2PA signature binds the exported file according to the C2PA format.
  Signed EXIF values live in the embedded manifest. Original EXIF, GPS, and serial numbers
  are not copied as file metadata in signed PNGs. Exact signing preserves an existing
  ICC display profile; resilient output operates on decoded RGB and does not retain it.
  Registry-only leaves the original file and all its original metadata unchanged.

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

## Checks

```bash
uv sync --group dev
uv run pytest -q
uv run ruff check .
```

Tests cover cryptographic round trips, wrong keys, pixel/alpha tampering, signature
transplants, forged metadata, malformed records, EXIF orientation, key encryption,
lossless/lossy conversions, persistent registry/import/export, wrong-record lookup,
ambiguous candidates, unrelated-image rejection, and the Streamlit signing/verification
workflow. The resilience suite exercises both the demo landscape and a deterministic
textured image against JPEG Q70/Q85, WebP Q75, 50% and 75% resizing plus JPEG encoding,
brightness +10%, cropping, rotation, and contrast adjustment. It is a regression suite,
not a universal robustness or adversarial-security guarantee.

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
Adobe's [TrustMark ICCV 2025 implementation](https://github.com/adobe/trustmark) is the
strongest suitable open implementation found for this Python app, but its own FAQ says
that a determined attacker can remove it. Google's 2025
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

The [audit report](docs/robustness-audit.md) and its JSON counterpart preserve failures as
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
