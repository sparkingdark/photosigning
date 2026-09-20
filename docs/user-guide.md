# PhotoSigning user guide

[Back to the README](../README.md) · [Technical reference](technical-reference.md)

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
   The app checks exact signatures, TrustMark and legacy watermark recovery, and
   registry recognition. Verification keys are recovered from proofs or signed records.
   A trusted public key is only needed if you want to check a particular signing
   identity. You can optionally supply a unique photo ID.
4. **Photo registry.** Browse records, look up a SHA-256 photo ID, or import/export signed
   JSON records to move recognition and signed details to another installation. A verifier
   needs the matching signed registry record to authenticate a recovered TrustMark tag
   and show its details. A legacy DCT watermark carries its own signed proof; the
   registry supplies the full name and EXIF details for that proof.

No cloud account, JavaScript build, or external image service is required. TrustMark
downloads model weights on first use; its image processing then runs locally.
When hosted remotely, Streamlit uploads photos and imported keys to the machine running
the app; run it locally to keep these on your own device. Do not expose an unauthenticated
instance publicly. The optional UI web font has a local sans-serif fallback.

## Three protection options

| Method | Image changes | What survives / what the result means |
| --- | --- | --- |
| Exact pixel signature | Selected RGB least-significant bits; PNG output | Pixel-preserving copies. Checks exact integrity. Edits invalidate this layer. |
| Registry recognition only | None; original file returned byte-for-byte | Signed record supports exact-hash lookup and approximate recognition of resized, cropped, rotated, or lightly adjusted copies. Edited matches are **candidates**, not signatures on those copies. |
| Maximum resilience (default) | Adobe TrustMark Q + authenticated registry match + exact signature + C2PA enabled by default; PNG output; registry required | The 40-bit TrustMark lookup tag is accepted only when its authenticated registry record also visually matches. Still cannot survive every transformation or deliberate removal. |

No technique survives **every** photo manipulation. A tiny thumbnail, large crop, heavy
editing, opaque overlay, or intentional removal can destroy the watermark and the visual
evidence needed to recognize the photo. These tests simulate sharing transformations;
they do not guarantee any particular social platform's current processing pipeline.

There is no signing method that prevents theft or survives arbitrary replacement of the
image. A person can copy an intact signed image, remove identifying visual information,
or sign a copy under a new key. Keeping the original and its signed record preserves
evidence even when a derivative can no longer be recognized. The app's self-reported
signing time is not independent proof of when a photograph existed.

The **SHA-256 photo ID** hashes the signed record's canonical manifest, including
source hash, signed details, timestamp, key, and visual features. It is a stable lookup
identifier for that record. It is not a secret, proof of ownership, or a content hash that
magically stays constant after editing. The perceptual hash is a separate, non-unique,
non-cryptographic similarity feature. A plain SHA-256 image hash necessarily changes when
the image file changes.

## C2PA Content Credentials

The **Embed C2PA Content Credentials** checkbox is enabled by default for **Exact pixel
signature** and **Maximum resilience** in the interface. The legacy **Invisible resilient
watermark** option remains available through the Python workflow API and can also include
credentials. Files exported without C2PA do not gain it automatically; sign and download
a new PNG to include credentials. The registry-only option preserves the original
file and adds no new credential, regardless of the checkbox.

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
