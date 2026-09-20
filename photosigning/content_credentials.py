"""C2PA Content Credentials, independent of the application's pixel proofs.

Uses the official CAI SDK with trust checks enabled. Local certificates are never
added to its trust store. All operations are offline; no photo or key is uploaded.
"""

from __future__ import annotations

import io
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from c2pa import Builder, C2paError, C2paSignerInfo, Context, Reader, Signer
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from PIL import Image

from .core import MAX_FILE_BYTES, PhotoSignError
from .trustmark_image import c2pa_soft_binding


@dataclass(frozen=True)
class Credentials:
    certificate_chain: bytes
    private_key: object = field(repr=False)
    algorithm: str = "ed25519"


def local_credentials(key: ed25519.Ed25519PrivateKey) -> Credentials:
    """Issue a local leaf for the user's key; discard the temporary CA private key."""
    authority = ed25519.Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "PhotoSigning Local CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PhotoSigning Local — Unverified"),
        ]
    )
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Local photo signer"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PhotoSigning Local — Unverified"),
        ]
    )

    def issue(public, name, ca):
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer)
            .public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=not ca,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=ca,
                    crl_sign=ca,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()),
                critical=False,
            )
        )
        if not ca:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=True
            )
        return builder.sign(authority, None).public_bytes(serialization.Encoding.PEM)

    chain = issue(key.public_key(), subject, False) + issue(authority.public_key(), issuer, True)
    return Credentials(chain, key)


def load_credentials(chain: bytes, private_pem: bytes, password: str = "") -> Credentials:
    """Load leaf-first PEM certificates and their matching C2PA signing key."""
    if len(chain) > 256_000 or len(private_pem) > 64_000:
        raise PhotoSignError("C2PA certificate or private key file is too large.")
    try:
        certs = x509.load_pem_x509_certificates(chain)
        key = serialization.load_pem_private_key(
            private_pem, password.encode() if password else None
        )
        if not certs:
            raise ValueError("missing certificates")
        public_format = serialization.PublicFormat.SubjectPublicKeyInfo
        if certs[0].public_key().public_bytes(serialization.Encoding.DER, public_format) != (
            key.public_key().public_bytes(serialization.Encoding.DER, public_format)
        ):
            raise PhotoSignError("The C2PA private key does not match the first certificate.")
        now = datetime.now(UTC)
        if not certs[0].not_valid_before_utc <= now <= certs[0].not_valid_after_utc:
            raise PhotoSignError("The C2PA signing certificate is expired or not yet valid.")
        if isinstance(key, ed25519.Ed25519PrivateKey):
            alg = "ed25519"
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            alg = {"secp256r1": "es256", "secp384r1": "es384", "secp521r1": "es512"}.get(
                key.curve.name
            )
        elif isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048:
            alg = "ps256"
        else:
            alg = None
        if not alg:
            raise PhotoSignError("Use an Ed25519, P-256/P-384/P-521, or RSA ≥2048 C2PA key.")
        # Only public certificate blocks may enter the exported manifest.
        public_chain = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
        return Credentials(public_chain, key, alg)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        if isinstance(exc, PhotoSignError):
            raise
        raise PhotoSignError(
            "Cannot load C2PA credentials. Check the PEM files and password."
        ) from exc


def offline_context() -> Context:
    return Context.from_dict(
        {
            "core": {"allowed_network_hosts": []},
            "verify": {
                "verify_after_reading": True,
                "verify_after_sign": True,
                "verify_trust": True,
                "verify_timestamp_trust": True,
                "remote_manifest_fetch": False,
                "ocsp_fetch": False,
            },
            "builder": {"thumbnail": {"enabled": False}},
        }
    )


def inspect_credentials(data: bytes) -> dict:
    result = {
        "status": "absent",
        "present": False,
        "valid": False,
        "trusted": False,
        "message": "No embedded C2PA Content Credentials found.",
        "manifest_store": None,
    }
    if len(data) > MAX_FILE_BYTES:
        return {**result, "status": "error", "message": "Photo exceeds the 40 MB limit."}
    try:
        with offline_context() as context:
            reader = Reader.try_create(io.BytesIO(data), context=context)
            if reader is None:
                return result
            with reader:
                store = json.loads(reader.json())
                state = reader.get_validation_state()
                valid = state in ("Valid", "Trusted")
                trusted = state == "Trusted"
                return {
                    **result,
                    "present": True,
                    "valid": valid,
                    "trusted": trusted,
                    "status": "trusted" if trusted else "valid_untrusted" if valid else "invalid",
                    "validation_state": state,
                    "message": (
                        "C2PA Content Credentials verified with a trusted signing certificate."
                        if trusted
                        else "C2PA Content Credentials are intact. The signing certificate is untrusted; "
                        "the signer's identity is unconfirmed."
                        if valid
                        else "C2PA Content Credentials failed validation. Review the validation report."
                    ),
                    "manifest_store": store,
                }
    except C2paError.NotSupported:
        return {
            **result,
            "status": "unsupported",
            "message": "C2PA reader does not support this file format.",
        }
    except (C2paError, ValueError) as exc:
        return {**result, "status": "error", "message": f"C2PA could not be validated: {exc}"}


def embed_credentials(
    png: bytes, source: bytes, record: dict, method: str, credentials: Credentials
) -> tuple[bytes, dict]:
    """Seal the final PNG, retaining the original's C2PA history as an ingredient."""
    signed = record["manifest"]
    metadata = {
        "@context": {
            "dc": "http://purl.org/dc/elements/1.1/",
            "tiff": "http://ns.adobe.com/tiff/1.0/",
            "exifEX": "http://cipa.jp/exif/2.32/",
        },
        "dc:creator": {"@list": [signed["photographer"]]},
    }
    for field_name, label in (
        ("camera_make", "tiff:Make"),
        ("camera_model", "tiff:Model"),
        ("lens", "exifEX:LensModel"),
    ):
        if signed["details"].get(field_name):
            metadata[label] = signed["details"][field_name]
    manifest = {
        "claim_version": 2,
        "claim_generator_info": [{"name": "PhotoSigning", "version": "1.0.0"}],
        "title": "Signed photograph",
        "assertions": [
            {"label": "cawg.metadata", "kind": "Json", "data": metadata},
            {
                "label": "org.photosigning.provenance",
                "data": {
                    "photographer": signed["photographer"],
                    "details": signed["details"],
                    "record_id": record["record_id"],
                    "method": method,
                    "pixel_signing_public_key": signed["public_key"],
                    "statements_are_user_supplied": True,
                },
            },
        ],
    }
    if method.startswith("Maximum resilience"):
        manifest["assertions"].append(c2pa_soft_binding(record["record_id"]))
    try:
        with Image.open(io.BytesIO(source)) as image:
            mime = Image.MIME[image.format]
        private_pem = credentials.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        info = C2paSignerInfo(
            credentials.algorithm, credentials.certificate_chain, private_pem, None
        )
        with (
            offline_context() as context,
            Signer.from_info(info) as signer,
            Builder(manifest, context=context) as builder,
        ):
            builder.add_ingredient(
                {
                    "title": "Original photograph",
                    "relationship": "parentOf",
                    "label": "source",
                },
                mime,
                io.BytesIO(source),
            )
            builder.add_action(
                {
                    "action": "c2pa.opened",
                    "parameters": {"ingredientIds": ["source"]},
                }
            )
            builder.add_action({"action": "c2pa.edited"})
            if method.startswith("Maximum resilience"):
                builder.add_action({"action": "c2pa.watermarked"})
            output = io.BytesIO()
            builder.sign(signer, "image/png", io.BytesIO(png), output)
            result = output.getvalue()
        if len(result) > MAX_FILE_BYTES:
            raise PhotoSignError("C2PA export exceeds the 40 MB limit. Use a smaller photograph.")
        report = inspect_credentials(result)
        if not report["valid"]:
            raise PhotoSignError(report["message"])
        return result, report
    except C2paError as exc:
        raise PhotoSignError(
            f"C2PA signing failed; no export was created. Check your signing certificate: {exc}"
        ) from exc
