# Majik Signature attribution

Copyright (c) 2026 Majikah Solutions OPC. Licensed under Apache-2.0; see LICENSE.

Source: https://github.com/Majikah/majik-signature
Revision: e10d3984fdc25e5bde62f03362461d2344422bbc (package version 0.6.0).

`photosigning/majik_image.py` is a modified Python adaptation of:

- `src/core/stamp/core/phash.ts`: separable orthonormal DCT, 63-bit median
  perceptual hash and two-half bit ordering.
- `src/core/stamp/core/dct-stego.ts`: luminance-domain DCT coefficient embedding.
- `src/core/stamp/core/stub.ts` and `payload.ts`: compact public-key proof and
  domain-separated image signature payload.

Changes: NumPy vectorization; antialiased perceptual-hash downsampling; fixed
512-pixel coordinate normalization; quantization-index modulation rather than
unit coefficient parity; fixed coefficient positions (no content-dependent
skipping); four interleaved repetitions; Reed–Solomon correction via reedsolo;
record hash in the compact proof; strict input validation and output self-checks.
Verification additionally tests the eight rotation/reflection orientations, applying
the same signature and perceptual-fingerprint checks to each.

This is a distinct, versioned PhotoSigning format. It does NOT claim wire
compatibility with Majik `.mjksig` or `MSIG` images, nor implement the complete
Majik SDK, ML-DSA-87, blockchain, or timestamp-authority features. The image
fallback in upstream also uses Ed25519. No upstream robustness claim is treated
as a guarantee; the local transformation tests establish only tested cases.

The source repository contained no separate NOTICE file at this revision.
