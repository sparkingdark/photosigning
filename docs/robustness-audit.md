# PhotoSigning adversarial audit

Generated: 2026-09-19T10:15:50.590130+00:00

Two deterministic synthetic images; finite local transformations. No real platform uploads, camera corpus, AI reconstruction, or exhaustive adversarial search. No rate is a real-world probability.

**No foolproof or theft-preventing claim is supported.**

Evaluated 70 image/transform combinations and 30 forgery, re-signing, key-compromise, and negative-control cases.

Workflow result counts: candidates=27, exact=4, unrecognized=12, watermark=27.

Exact checks establish covered-pixel integrity. A watermark authenticates a perceptual fingerprint, which tolerates edits and can collide. Registry matches are candidates, not proof of ownership. No match does not prove a photo is unsigned or free to use.

## Transformation results

| Fixture | Attempt | Exact | Watermark | Registry candidate | Workflow |
| --- | --- | --- | --- | --- | --- |
| landscape | Unchanged signed PNG | yes | yes | yes | exact |
| landscape | Metadata stripped / lossless PNG re-encode | yes | yes | yes | exact |
| landscape | JPEG quality 95 | no | yes | yes | watermark |
| landscape | JPEG quality 70 | no | yes | yes | watermark |
| landscape | JPEG quality 40 | no | yes | yes | watermark |
| landscape | JPEG quality 10 | no | no | yes | candidates |
| landscape | WebP quality 50 | no | yes | yes | watermark |
| landscape | Resize to width 1080 + JPEG quality 70 | no | yes | yes | watermark |
| landscape | Resize to width 720 + JPEG quality 70 | no | yes | yes | watermark |
| landscape | Resize to width 360 + JPEG quality 70 | no | no | yes | candidates |
| landscape | Resize to width 128 + JPEG quality 70 | no | no | yes | candidates |
| landscape | Resize to width 32 + JPEG quality 70 | no | no | yes | candidates |
| landscape | Crop: retain 90% of area | no | no | yes | candidates |
| landscape | Crop: retain 50% of area | no | no | no | unrecognized |
| landscape | Crop: retain 10% of area | no | no | no | unrecognized |
| landscape | Rotate 90 degrees | no | yes | yes | watermark |
| landscape | Rotate 7 degrees with new border | no | no | yes | candidates |
| landscape | Horizontal mirror | no | yes | no | watermark |
| landscape | Grayscale | no | yes | yes | watermark |
| landscape | Invert all colors | no | no | no | unrecognized |
| landscape | Posterize to 3 bits per channel | no | no | yes | candidates |
| landscape | Gaussian blur radius 1 | no | yes | yes | watermark |
| landscape | Gaussian blur radius 3 | no | no | yes | candidates |
| landscape | Gaussian blur radius 8 | no | no | yes | candidates |
| landscape | Brightness multiplier 0.5 | no | no | yes | candidates |
| landscape | Brightness multiplier 1.5 | no | no | yes | candidates |
| landscape | Contrast multiplier 2 | no | no | yes | candidates |
| landscape | Saturation multiplier 2 | no | yes | yes | watermark |
| landscape | Gaussian noise standard deviation 10 | no | yes | yes | watermark |
| landscape | Gaussian noise standard deviation 30 | no | yes | yes | watermark |
| landscape | Opaque central credit overlay | no | no | no | unrecognized |
| landscape | Paint over left 50% | no | no | no | unrecognized |
| landscape | Screenshot-like border (simulated) | no | no | yes | candidates |
| landscape | Combined crop + rotate + resize + contrast + JPEG 30 | no | no | no | unrecognized |
| landscape | Complete opaque replacement | no | no | no | unrecognized |
| textured | Unchanged signed PNG | yes | yes | yes | exact |
| textured | Metadata stripped / lossless PNG re-encode | yes | yes | yes | exact |
| textured | JPEG quality 95 | no | yes | yes | watermark |
| textured | JPEG quality 70 | no | yes | yes | watermark |
| textured | JPEG quality 40 | no | yes | yes | watermark |
| textured | JPEG quality 10 | no | no | yes | candidates |
| textured | WebP quality 50 | no | yes | yes | watermark |
| textured | Resize to width 1080 + JPEG quality 70 | no | yes | yes | watermark |
| textured | Resize to width 720 + JPEG quality 70 | no | yes | yes | watermark |
| textured | Resize to width 360 + JPEG quality 70 | no | yes | yes | watermark |
| textured | Resize to width 128 + JPEG quality 70 | no | no | yes | candidates |
| textured | Resize to width 32 + JPEG quality 70 | no | no | no | unrecognized |
| textured | Crop: retain 90% of area | no | no | yes | candidates |
| textured | Crop: retain 50% of area | no | no | yes | candidates |
| textured | Crop: retain 10% of area | no | no | no | unrecognized |
| textured | Rotate 90 degrees | no | yes | yes | watermark |
| textured | Rotate 7 degrees with new border | no | no | yes | candidates |
| textured | Horizontal mirror | no | yes | no | watermark |
| textured | Grayscale | no | yes | yes | watermark |
| textured | Invert all colors | no | no | no | unrecognized |
| textured | Posterize to 3 bits per channel | no | no | yes | candidates |
| textured | Gaussian blur radius 1 | no | yes | yes | watermark |
| textured | Gaussian blur radius 3 | no | no | yes | candidates |
| textured | Gaussian blur radius 8 | no | no | yes | candidates |
| textured | Brightness multiplier 0.5 | no | no | yes | candidates |
| textured | Brightness multiplier 1.5 | no | no | yes | candidates |
| textured | Contrast multiplier 2 | no | no | yes | candidates |
| textured | Saturation multiplier 2 | no | yes | yes | watermark |
| textured | Gaussian noise standard deviation 10 | no | yes | yes | watermark |
| textured | Gaussian noise standard deviation 30 | no | yes | yes | watermark |
| textured | Opaque central credit overlay | no | no | no | unrecognized |
| textured | Paint over left 50% | no | no | yes | candidates |
| textured | Screenshot-like border (simulated) | no | no | yes | candidates |
| textured | Combined crop + rotate + resize + contrast + JPEG 30 | no | no | yes | candidates |
| textured | Complete opaque replacement | no | no | no | unrecognized |

## Misuse and forgery checks

| Fixture | Attempt | Result |
| --- | --- | --- |
| landscape | Copy exact signature onto unrelated image | unrecognized |
| landscape | Change signed photographer name in record | rejected |
| landscape | Re-sign copied image with different key (no trusted key supplied) | exact; other signer records=1 |
| landscape | Re-sign copied image with different key (trusted owner key supplied) | wrong_key; other signer records=1 |
| landscape | Attacker has a copy of the owner's private key | exact |
| landscape | Unrelated negative control 1 | unrecognized |
| landscape | Unrelated negative control 2 | unrecognized |
| landscape | Unrelated negative control 3 | unrecognized |
| landscape | Unrelated negative control 4 | unrecognized |
| landscape | Unrelated negative control 5 | unrecognized |
| landscape | Unrelated negative control 6 | unrecognized |
| landscape | Unrelated negative control 7 | unrecognized |
| landscape | Unrelated negative control 8 | unrecognized |
| landscape | Unrelated negative control 9 | unrecognized |
| landscape | Unrelated negative control 10 | unrecognized |
| textured | Copy exact signature onto unrelated image | unrecognized |
| textured | Change signed photographer name in record | rejected |
| textured | Re-sign copied image with different key (no trusted key supplied) | exact; other signer records=1 |
| textured | Re-sign copied image with different key (trusted owner key supplied) | wrong_key; other signer records=1 |
| textured | Attacker has a copy of the owner's private key | exact |
| textured | Unrelated negative control 1 | unrecognized |
| textured | Unrelated negative control 2 | unrecognized |
| textured | Unrelated negative control 3 | unrecognized |
| textured | Unrelated negative control 4 | unrecognized |
| textured | Unrelated negative control 5 | unrecognized |
| textured | Unrelated negative control 6 | unrecognized |
| textured | Unrelated negative control 7 | unrecognized |
| textured | Unrelated negative control 8 | unrecognized |
| textured | Unrelated negative control 9 | unrecognized |
| textured | Unrelated negative control 10 | unrecognized |

## Boundaries

- A thief can copy a photo unchanged; signatures do not enforce usage rights.
- A new valid signature establishes control of a new key, not authorship. Local conflicting records are a warning, not a verdict; collaboration and key rotation can also explain them.
- Stolen private keys can produce authentic signatures. Password-protected backups and trusted identity/key history remain necessary.
- Local record timestamps are self-reported, not independently witnessed. No trusted timestamp service is configured.
- If original pixels, watermark, and matching visual structure are all lost, recovery is impossible from the derivative alone.
- AI redraw, inpainting, screenshot capture on real devices, platform-specific processing, and adaptive perceptual-hash collision attacks are not covered by this finite run.

Reproduce with `uv run python -m photosigning.audit --output docs/robustness-audit`.
