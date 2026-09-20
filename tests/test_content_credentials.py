"""Exercise the real C2PA SDK, including hashes, history and certificate trust."""

import io
import struct
import zlib

import pytest
from c2pa import Reader
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from PIL import Image

from photosigning.content_credentials import (
    embed_credentials,
    inspect_credentials,
    load_credentials,
    local_credentials,
    offline_context,
)
from photosigning.core import PhotoSignError, generate_key, read_photo, verify_photo
from photosigning.demo import demo_photo
from photosigning.majik_image import verify_watermark
from photosigning.registry import Registry, create_record
from photosigning.workflow import METHODS, inspect_photo, protect_photo


@pytest.fixture(scope="module")
def signed():
    key = generate_key()
    return protect_photo(
        demo_photo(),
        key,
        name="Ada Photographer",
        details={"camera_model": "X-T5"},
        method=METHODS[1],
    )


def test_default_watermark_export_has_standard_credentials(signed):
    assert signed.c2pa["valid"]
    assert not signed.c2pa["trusted"]
    assert verify_photo(signed.data).valid
    assert verify_watermark(signed.data).valid
    # Independent entry point: a standard SDK reader, not our pixel decoder.
    with (
        offline_context() as context,
        Reader("image/png", io.BytesIO(signed.data), context=context) as reader,
    ):
        assert reader.is_embedded()
        assert reader.get_validation_state() == "Valid"
        active = reader.get_active_manifest()
        assertion = next(
            a for a in active["assertions"] if a["label"] == "org.photosigning.provenance"
        )
        assert assertion["data"]["photographer"] == "Ada Photographer"
        assert assertion["data"]["details"]["camera_model"] == "X-T5"
        assert assertion["data"]["record_id"] == signed.record["record_id"]
        metadata = next(a for a in active["assertions"] if a["label"] == "cawg.metadata")
        assert metadata["data"]["dc:creator"] == {"@list": ["Ada Photographer"]}
        assert metadata["data"]["tiff:Model"] == "X-T5"
        checks = reader.get_validation_results()["activeManifest"]
        assert "claimSignature.validated" in {s["code"] for s in checks["success"]}
        assert {s["code"] for s in checks["failure"]} == {"signingCredential.untrusted"}


def test_metadata_stripping_leaves_pixel_proof_but_removes_c2pa(signed):
    stripped = io.BytesIO()
    image = read_photo(signed.data)
    image.info.clear()
    image.save(stripped, format="PNG")
    result = inspect_photo(stripped.getvalue())
    assert result["exact_valid"]
    assert result["c2pa"]["status"] == "absent"
    assert verify_watermark(stripped.getvalue()).valid


def test_recompressed_copy_does_not_claim_c2pa_recovery(signed):
    output = io.BytesIO()
    read_photo(signed.data).save(output, format="JPEG", quality=70)
    result = inspect_photo(output.getvalue())
    assert result["watermark_valid"]
    assert not result["c2pa"]["valid"]
    assert result["c2pa"]["status"] == "absent"


def replace_png_chunk(data, target, change):
    result, offset = bytearray(data[:8]), 8
    while offset < len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        if kind == target:
            payload = change(payload)
        result.extend(struct.pack(">I", len(payload)) + kind + payload)
        result.extend(struct.pack(">I", zlib.crc32(kind + payload)))
        offset += length + 12
    return bytes(result)


def test_c2pa_rejects_modified_assertion_even_with_intact_pixel_signature(signed):
    tampered = replace_png_chunk(
        signed.data, b"caBX", lambda b: b.replace(b"Ada Photographer", b"Eve Photographer")
    )
    assert tampered != signed.data
    assert verify_photo(tampered).valid
    report = inspect_photo(tampered)
    assert report["c2pa"]["status"] == "invalid"
    assert not report["c2pa"]["valid"]


def test_c2pa_rejects_changed_pixels_with_manifest_retained(signed):
    # Recompress the PNG scanlines with a different first-channel value, keeping
    # every C2PA byte and producing correct chunk CRCs so this is a real hash test.
    def alter(payload):
        raw = bytearray(zlib.decompress(payload))
        raw[1] ^= 16
        return zlib.compress(raw)

    # Pillow may split IDAT; merge them before altering their deflate stream.
    chunks, offset = [], 8
    while offset < len(signed.data):
        length = int.from_bytes(signed.data[offset : offset + 4], "big")
        kind = signed.data[offset + 4 : offset + 8]
        payload = signed.data[offset + 8 : offset + 8 + length]
        chunks.append((kind, payload))
        offset += length + 12
    modified = alter(b"".join(p for k, p in chunks if k == b"IDAT"))
    out, added = bytearray(signed.data[:8]), False
    for kind, payload in chunks:
        if kind == b"IDAT":
            if added:
                continue
            payload, added = modified, True
        out.extend(struct.pack(">I", len(payload)) + kind + payload)
        out.extend(struct.pack(">I", zlib.crc32(kind + payload)))
    read_photo(bytes(out))
    report = inspect_credentials(bytes(out))
    assert report["status"] == "invalid"
    failures = report["manifest_store"]["validation_results"]["activeManifest"]["failure"]
    assert "assertion.dataHash.mismatch" in {f["code"] for f in failures}


def test_disabled_and_registry_only_do_not_add_c2pa():
    data, key = demo_photo(), generate_key()
    disabled = protect_photo(data, key, name="Ada", details={}, include_c2pa=False)
    assert disabled.c2pa is None
    assert inspect_credentials(disabled.data)["status"] == "absent"
    registered = protect_photo(data, key, name="Ada", details={}, method=METHODS[2])
    assert registered.data == data
    assert registered.c2pa is None


def test_exact_export_retains_original_c2pa_history(signed):
    result = protect_photo(signed.data, generate_key(), name="Editor", details={})
    store = result.c2pa["manifest_store"]
    original_label = signed.c2pa["manifest_store"]["active_manifest"]
    assert original_label in store["manifests"]
    assert len(store["manifests"]) == 2
    assert result.c2pa["valid"]
    assert verify_photo(result.data).valid


def test_c2pa_only_photo_is_recognized():
    data, key = demo_photo(), generate_key()
    record = create_record(data, key, name="Ada", details={})
    output, _ = embed_credentials(data, data, record, "C2PA only", local_credentials(key))
    result = inspect_photo(output)
    assert result["status"] == "c2pa"
    assert result["c2pa"]["valid"]
    assert not result["exact_valid"]


def test_imported_credentials_and_mismatched_key():
    key = generate_key()
    credentials = local_credentials(key)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"test password"),
    )
    loaded = load_credentials(credentials.certificate_chain, pem, "test password")
    result = protect_photo(
        demo_photo(), generate_key(), name="Ada", details={}, c2pa_credentials=loaded
    )
    assert result.c2pa["valid"]
    with pytest.raises(PhotoSignError, match="password"):
        load_credentials(credentials.certificate_chain, pem, "wrong password")
    with pytest.raises(PhotoSignError, match="does not match"):
        load_credentials(local_credentials(generate_key()).certificate_chain, pem, "test password")


def test_imported_es256_certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    chain = local_credentials(key).certificate_chain
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    loaded = load_credentials(chain, pem)
    assert loaded.algorithm == "es256"
    result = protect_photo(
        demo_photo(), generate_key(), name="Ada", details={}, c2pa_credentials=loaded
    )
    assert result.c2pa["valid"]
    assert not result.c2pa["trusted"]


def test_failed_c2pa_signing_does_not_save_registry(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise PhotoSignError("C2PA failed")

    monkeypatch.setattr("photosigning.workflow.embed_credentials", fail)
    registry = Registry(tmp_path / "registry.sqlite3")
    with pytest.raises(PhotoSignError, match="C2PA failed"):
        protect_photo(demo_photo(), generate_key(), name="Ada", details={}, registry=registry)
    assert registry.records() == []


@pytest.mark.parametrize("format", ["JPEG", "WEBP", "TIFF"])
def test_supported_inputs_produce_c2pa(format):
    output = io.BytesIO()
    Image.new("RGB", (200, 200), "navy").save(output, format=format)
    result = protect_photo(output.getvalue(), generate_key(), name="Ada", details={})
    assert result.c2pa["valid"]
