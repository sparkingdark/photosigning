import copy
import io
import json
import sqlite3

import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter

from photosigning.core import PhotoSignError, read_photo, verify_photo
from photosigning.demo import demo_photo
from photosigning.majik_image import embed_watermark, phash, verify_watermark
from photosigning.registry import Registry, create_record, import_record, validate_record
from photosigning.workflow import METHODS, inspect_photo, protect_photo


def encode(photo, format="PNG", **kwargs):
    out = io.BytesIO()
    photo.save(out, format=format, **kwargs)
    return out.getvalue()


@pytest.fixture(scope="module")
def key():
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


@pytest.fixture(scope="module", params=["landscape", "textured"])
def source(request):
    if request.param == "landscape":
        return demo_photo()
    rng = np.random.default_rng(412)
    pixels = rng.integers(35, 220, (800, 1100, 3), dtype=np.uint8)
    photo = Image.fromarray(pixels).filter(ImageFilter.GaussianBlur(3))
    draw = ImageDraw.Draw(photo)
    for _ in range(200):
        x, y = rng.integers(0, 1000), rng.integers(0, 700)
        r = int(rng.integers(8, 60))
        color = tuple(int(c) for c in rng.integers(20, 230, 3))
        draw.ellipse((x, y, x + r, y + r), fill=color)
    return encode(photo)


@pytest.fixture(scope="module")
def protected(source, key):
    return protect_photo(
        source, key, name="Test Photographer", details={"camera_model": "X-T5"}, method=METHODS[1]
    )


@pytest.mark.parametrize(
    "change", ["png", "jpeg70", "jpeg85", "webp75", "half", "resize75", "brightness"]
)
def test_invisible_proof_survives_tested_transforms(protected, change):
    photo = read_photo(protected.data)
    fmt, options = "PNG", {}
    if change.startswith("jpeg"):
        fmt, options = "JPEG", {"quality": int(change[4:])}
    elif change == "webp75":
        fmt, options = "WEBP", {"quality": 75}
    elif change in ["half", "resize75"]:
        ratio = 0.5 if change == "half" else 0.75
        photo = photo.resize(
            (round(photo.width * ratio), round(photo.height * ratio)), Image.Resampling.LANCZOS
        )
        fmt, options = "JPEG", {"quality": 80 if change == "half" else 70}
    elif change == "brightness":
        photo = ImageEnhance.Brightness(photo).enhance(1.1)
    data = encode(photo, fmt, **options)
    proof = verify_watermark(data)
    assert proof.valid, (change, proof.message)
    assert proof.record_id == protected.record["record_id"]
    if change != "png":
        assert not verify_photo(data).valid
        report = inspect_photo(data)  # no registry and no external public key
        assert report["status"] == "watermark"
        assert not report["exact_valid"] and not report["identity_trusted"]


def test_original_keeps_exact_signature(protected, key):
    assert verify_photo(protected.data, key.public_key()).valid


def test_wrong_key_does_not_become_verified_via_fallback(protected):
    jpeg = encode(read_photo(protected.data), "JPEG", quality=70)
    report = inspect_photo(jpeg, trusted_key=Ed25519PrivateKey.generate().public_key())
    assert report["status"] == "wrong_key"
    assert not report["identity_trusted"]


def test_unsigned_and_tiny_image_do_not_verify(source):
    assert not verify_watermark(source).valid
    assert not verify_watermark(encode(Image.new("RGB", (64, 64), "white"))).valid
    assert not verify_watermark(b"not an image").valid


def test_small_or_transparent_input_rejected(key):
    with pytest.raises(PhotoSignError, match="512"):
        embed_watermark(encode(Image.new("RGB", (200, 200))), key, "ab" * 32, 1)
    with pytest.raises(PhotoSignError, match="opaque"):
        embed_watermark(encode(Image.new("RGBA", (600, 600), (1, 2, 3, 100))), key, "ab" * 32, 1)


def test_registry_persistence_export_import_and_hash(source, key, tmp_path):
    original = create_record(source, key, name="Ada", details={"camera_model": "X-T5"})
    registry = Registry(tmp_path / "records.sqlite3")
    registry.save(original)
    reloaded = Registry(tmp_path / "records.sqlite3")
    assert reloaded.get(original["record_id"]) == original
    assert import_record(json.dumps(original).encode()) == original
    assert reloaded.recognize(source)[0]["exact"]
    assert inspect_photo(source, registry=reloaded)["status"] == "registered_exact"


def test_registry_rejects_tampering(source, key, tmp_path):
    record = create_record(source, key, name="Ada", details={})
    altered = copy.deepcopy(record)
    altered["manifest"]["photographer"] = "Eve"
    with pytest.raises(PhotoSignError):
        validate_record(altered)
    with pytest.raises(PhotoSignError):
        Registry(tmp_path / "records.sqlite3").save(altered)


def test_registry_index_cannot_substitute_another_record(source, key, tmp_path):
    record = create_record(source, key, name="Ada", details={})
    registry = Registry(tmp_path / "records.sqlite3")
    registry.save(record)
    with sqlite3.connect(registry.path) as db:
        db.execute("UPDATE records SET id = ?", ("ab" * 32,))
    with pytest.raises(PhotoSignError, match="index"):
        registry.get("ab" * 32)


@pytest.mark.parametrize("change", ["half_jpeg", "crop", "rotate", "contrast"])
def test_registry_recognizes_derivatives_as_candidates(source, key, tmp_path, change):
    registry = Registry(tmp_path / "records.sqlite3")
    record = create_record(source, key, name="Ada", details={})
    registry.save(record)
    photo = read_photo(source)
    if change == "half_jpeg":
        photo = photo.resize((photo.width // 2, photo.height // 2), Image.Resampling.LANCZOS)
    elif change == "crop":
        photo = photo.crop(
            (
                int(photo.width * 0.1),
                int(photo.height * 0.1),
                int(photo.width * 0.9),
                int(photo.height * 0.9),
            )
        )
    elif change == "rotate":
        photo = photo.transpose(Image.Transpose.ROTATE_90)
    else:
        photo = ImageEnhance.Contrast(photo).enhance(1.2)
    derivative = encode(photo, "JPEG", quality=75)
    matches = registry.recognize(derivative)
    assert matches and matches[0]["record"]["record_id"] == record["record_id"], change
    assert not matches[0]["exact"]
    assert inspect_photo(derivative, registry=registry)["status"] == "candidates"


def test_unrelated_photo_is_not_recognized(source, key, tmp_path):
    registry = Registry(tmp_path / "records.sqlite3")
    registry.save(create_record(source, key, name="Ada", details={}))
    other = np.random.default_rng(177).integers(0, 256, (600, 800, 3), dtype=np.uint8)
    assert not registry.recognize(encode(Image.fromarray(other)))
    assert not registry.recognize(encode(Image.new("RGB", (800, 600), "gray")))


def test_registry_only_does_not_change_file(source, key, tmp_path):
    registry = Registry(tmp_path / "records.sqlite3")
    exported = protect_photo(
        source, key, name="Ada", details={}, method=METHODS[2], registry=registry
    )
    assert exported.data == source
    assert exported.exact is None
    assert registry.get(exported.record["record_id"])


def test_photo_id_narrows_search_and_rejects_wrong_record(source, key, protected, tmp_path):
    registry = Registry(tmp_path / "records.sqlite3")
    record = create_record(source, key, name="Ada", details={})
    registry.save(record)
    assert registry.recognize(source, record["record_id"])
    assert not registry.recognize(source, "ab" * 32)
    assert inspect_photo(protected.data, record_id="ab" * 32)["status"] == "wrong_record"
    with pytest.raises(PhotoSignError, match="64-character"):
        inspect_photo(protected.data, record_id="invalid")


def test_recovered_record_supplies_signed_exif(protected, tmp_path):
    registry = Registry(tmp_path / "records.sqlite3")
    registry.save(protected.record)
    jpeg = encode(read_photo(protected.data), "JPEG", quality=70)
    report = inspect_photo(jpeg, registry=registry)
    assert report["status"] == "watermark"
    assert report["manifest"]["details"]["camera_model"] == "X-T5"


def test_ambiguous_matching_records_do_not_select_an_owner(source, key, tmp_path):
    registry = Registry(tmp_path / "records.sqlite3")
    registry.save(create_record(source, key, name="Ada", details={}))
    registry.save(create_record(source, Ed25519PrivateKey.generate(), name="Eve", details={}))
    result = inspect_photo(source, registry=registry)
    assert result["status"] == "candidates"
    assert len(result["candidates"]) == 2
    assert result["manifest"] is None


@pytest.mark.parametrize("invalid", [b"null", b"[]", b"{}", b"bad json", b"x" * 200001])
def test_malformed_import_is_actionable(invalid):
    with pytest.raises(PhotoSignError):
        import_record(invalid)


def test_perceptual_hash_is_not_a_unique_content_hash():
    # The UI must never describe pHash as a cryptographic, collision-free identity.
    assert len(phash(read_photo(demo_photo()))) == 16


@pytest.mark.parametrize("transform", list(Image.Transpose))
def test_watermark_recovers_after_rotation_and_reflection(protected, transform):
    data = encode(read_photo(protected.data).transpose(transform))
    proof = verify_watermark(data)
    assert proof.valid
    assert proof.record_id == protected.record["record_id"]
    assert proof.normalization != "none"
    assert not verify_photo(data).valid


def test_resigning_does_not_hide_another_registered_signer(source, key, tmp_path):
    from photosigning.core import sign_photo

    registry = Registry(tmp_path / "records.sqlite3")
    original = create_record(source, key, name="Original photographer", details={})
    registry.save(original)
    other = Ed25519PrivateKey.generate()
    resigned = sign_photo(source, other, name="Original photographer")
    result = inspect_photo(resigned.png, registry=registry)
    assert result["exact_valid"]  # signing with a new key is possible, but proves no ownership
    assert not result["identity_trusted"]
    assert result["provenance_conflicts"][0]["record_id"] == original["record_id"]
    trusted = inspect_photo(resigned.png, registry=registry, trusted_key=key.public_key())
    assert trusted["status"] == "wrong_key"
    assert trusted["provenance_conflicts"]


def test_own_records_do_not_hide_other_signers_or_warn_about_themselves(source, key, tmp_path):
    from photosigning.core import sign_photo

    registry = Registry(tmp_path / "records.sqlite3")
    other = create_record(source, Ed25519PrivateKey.generate(), name="Another signer", details={})
    registry.save(other)
    for number in range(6):
        registry.save(create_record(source, key, name="Ada", details={"revision": str(number)}))
    result = inspect_photo(sign_photo(source, key, name="Ada").png, registry=registry)
    assert len(result["provenance_conflicts"]) == 1
    assert result["provenance_conflicts"][0]["record_id"] == other["record_id"]


def test_opaque_replacement_destroys_recoverable_evidence(protected, tmp_path):
    registry = Registry(tmp_path / "records.sqlite3")
    registry.save(protected.record)
    erased = encode(Image.new("RGB", read_photo(protected.data).size, "white"))
    report = inspect_photo(erased, registry=registry)
    assert report["status"] == "unrecognized"
    assert not report["exact_valid"] and not report["watermark_valid"]
