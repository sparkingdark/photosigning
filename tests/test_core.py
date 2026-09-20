import base64
import io
import json
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from PIL import Image

from photosigning import core


def png(image):
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


@pytest.fixture
def key():
    return core.generate_key()


@pytest.fixture
def original():
    return png(Image.new("RGB", (240, 180), (153, 100, 52)))


@pytest.fixture
def signed(original, key):
    return core.sign_photo(original, key, name="Ada Photographer", details={"camera_model": "X-T5"})


def rewrite_payload(data, change):
    image = core.read_photo(data)
    raw = bytearray(image.tobytes())
    _, size = core.HEADER.unpack(core._extract(raw, 3, core.HEADER.size))
    envelope = json.loads(core._extract(raw, 3, size, core.HEADER.size * 8))
    change(envelope)
    payload = core.canonical(envelope)
    core._embed(raw, 3, core.HEADER.pack(core.MAGIC, len(payload)) + payload)
    return png(Image.frombytes("RGB", image.size, bytes(raw)))


def test_sign_verify_with_trusted_key(signed, key):
    result = core.verify_photo(signed.png, key.public_key())
    assert result.valid and result.trusted
    assert result.manifest["photographer"] == "Ada Photographer"
    assert result.manifest["details"]["camera_model"] == "X-T5"
    assert result.fingerprint == core.fingerprint(key)


def test_verification_without_trust_does_not_claim_identity(signed):
    result = core.verify_photo(signed.png)
    assert result.valid and not result.trusted


def test_wrong_trusted_key(signed):
    result = core.verify_photo(signed.png, core.generate_key().public_key())
    assert not result.valid and result.status == "wrong_key"


@pytest.mark.parametrize("channel,mask", [(0, 1), (1, 2), (2, 128)])
def test_pixel_tampering_including_unused_lsb(signed, channel, mask):
    image = core.read_photo(signed.png)
    pixel = list(image.getpixel((239, 179)))
    pixel[channel] ^= mask
    image.putpixel((239, 179), tuple(pixel))
    result = core.verify_photo(png(image))
    assert not result.valid and result.status == "modified"


def test_carrier_high_bit_tampering(signed):
    image = core.read_photo(signed.png)
    r, g, b = image.getpixel((0, 0))
    image.putpixel((0, 0), (r ^ 2, g, b))
    assert core.verify_photo(png(image)).status == "modified"


def test_carrier_header_tampering(signed):
    image = core.read_photo(signed.png)
    r, g, b = image.getpixel((0, 0))
    image.putpixel((0, 0), (r ^ 1, g, b))
    assert not core.verify_photo(png(image)).valid


def test_forged_name(signed):
    forged = rewrite_payload(
        signed.png, lambda e: e["manifest"].update(photographer="Eve Photographer")
    )
    assert core.verify_photo(forged).status == "invalid_signature"


def test_forged_camera(signed):
    forged = rewrite_payload(
        signed.png, lambda e: e["manifest"]["details"].update(camera_model="Fake")
    )
    assert core.verify_photo(forged).status == "invalid_signature"


def test_signature_transplant(signed):
    image = core.read_photo(signed.png)
    other = Image.new("RGB", image.size, (50, 100, 153))
    raw = bytearray(other.tobytes())
    payload = core._extract(image.tobytes(), 3, signed.payload_bytes)
    core._embed(raw, 3, payload)
    assert (
        core.verify_photo(png(Image.frombytes("RGB", other.size, bytes(raw)))).status == "modified"
    )


def test_rgba_and_alpha_integrity(key):
    original = Image.new("RGBA", (240, 180), (100, 150, 200, 120))
    signed = core.sign_photo(png(original), key, name="Ada")
    image = core.read_photo(signed.png)
    assert image.getchannel("A").tobytes() == original.getchannel("A").tobytes()
    assert core.verify_photo(signed.png).valid
    pixel = image.getpixel((0, 0))
    image.putpixel((0, 0), (*pixel[:3], 121))
    assert core.verify_photo(png(image)).status == "modified"


def test_changes_at_most_one_per_color_channel(original, signed):
    before, after = core.read_photo(original), core.read_photo(signed.png)
    assert max(abs(a - b) for a, b in zip(before.tobytes(), after.tobytes())) <= 1


def test_lossless_resave_and_metadata_removal(signed):
    # Re-encoding PNG removes all file metadata but preserves the pixel signature.
    image = Image.frombytes(
        "RGB", core.read_photo(signed.png).size, core.read_photo(signed.png).tobytes()
    )
    assert core.verify_photo(png(image)).valid


def test_jpeg_conversion_does_not_verify(signed):
    out = io.BytesIO()
    core.read_photo(signed.png).save(out, format="JPEG", quality=95)
    assert not core.verify_photo(out.getvalue()).valid


def test_resizing_does_not_verify(signed):
    assert not core.verify_photo(png(core.read_photo(signed.png).resize((120, 90)))).valid


def test_unsigned_and_invalid_input(original):
    assert core.verify_photo(original).status == "no_signature"
    assert not core.verify_photo(b"not an image").valid


def test_small_image_rejected(key):
    with pytest.raises(core.PhotoSignError, match="too small"):
        core.sign_photo(png(Image.new("RGB", (10, 10))), key, name="Ada")


def test_name_and_details_validation(original, key):
    with pytest.raises(core.PhotoSignError, match="name"):
        core.sign_photo(original, key, name="   ")
    with pytest.raises(core.PhotoSignError, match="short text"):
        core.sign_photo(original, key, name="Ada", details={"camera": "x" * 501})


def test_private_key_roundtrip_and_wrong_password(key):
    pem = core.export_private_key(key, "correct horse battery staple")
    assert b"ENCRYPTED PRIVATE KEY" in pem
    loaded = core.load_private_key(pem, "correct horse battery staple")
    assert isinstance(loaded, Ed25519PrivateKey)
    assert core.fingerprint(loaded) == core.fingerprint(key)
    with pytest.raises(core.PhotoSignError, match="unlock"):
        core.load_private_key(pem, "wrong password")
    with pytest.raises(core.PhotoSignError, match="8 characters"):
        core.export_private_key(key, "short")


def test_public_key_roundtrip(key):
    public = core.load_public_key(core.public_pem(key))
    assert core.fingerprint(public) == core.fingerprint(key)
    with pytest.raises(core.PhotoSignError):
        core.load_public_key(b"invalid")


def test_malicious_length_is_bounded(signed):
    image = core.read_photo(signed.png)
    raw = bytearray(image.tobytes())
    core._embed(raw, 3, core.MAGIC + struct.pack(">I", 0xFFFFFFFF))
    assert (
        core.verify_photo(png(Image.frombytes("RGB", image.size, bytes(raw)))).status
        == "unreadable"
    )


def test_noncanonical_payload_rejected(signed):
    image = core.read_photo(signed.png)
    raw = bytearray(image.tobytes())
    payload = core._extract(raw, 3, signed.payload_bytes - core.HEADER.size, core.HEADER.size * 8)
    payload += b" "
    core._embed(raw, 3, core.HEADER.pack(core.MAGIC, len(payload)) + payload)
    assert (
        core.verify_photo(png(Image.frombytes("RGB", image.size, bytes(raw)))).status
        == "unreadable"
    )


def test_noncanonical_base64_padding_rejected(signed):
    def alter_padding(envelope):
        value = envelope["signature"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        # These four unused bits must not allow undetected carrier changes.
        replacement = alphabet[alphabet.index(value[-3]) | 1]
        altered = value[:-3] + replacement + "=="
        assert base64.b64decode(altered) == base64.b64decode(value)
        envelope["signature"] = altered

    assert core.verify_photo(rewrite_payload(signed.png, alter_padding)).status == "unreadable"


def test_malformed_manifest_does_not_crash_verification(signed):
    altered = rewrite_payload(signed.png, lambda e: e["manifest"].update(details=["invalid"]))
    assert core.verify_photo(altered).status == "unreadable"


def test_output_size_limit_is_actionable(original, key, monkeypatch):
    monkeypatch.setattr(core, "MAX_FILE_BYTES", len(original) + 10)
    with pytest.raises(core.PhotoSignError, match="lossless signed PNG"):
        core.sign_photo(original, key, name="Ada")


def test_exif_extraction_and_orientation(key):
    image = Image.new("RGB", (240, 180), (150, 60, 30))
    exif = Image.Exif()
    exif[271] = "Fujifilm"
    exif[272] = "X-T5"
    exif[274] = 6
    out = io.BytesIO()
    image.save(out, format="JPEG", exif=exif)
    assert core.extract_exif(out.getvalue())["camera_model"] == "X-T5"
    signed = core.sign_photo(out.getvalue(), key, name="Ada")
    assert signed.manifest["image"]["width"] == 180
    assert core.verify_photo(signed.png).valid


def test_transparent_palette_input(key):
    image = Image.new("P", (240, 180))
    image.info["transparency"] = 0
    signed = core.sign_photo(png(image), key, name="Ada")
    assert signed.manifest["image"]["mode"] == "RGBA"
    assert core.verify_photo(signed.png).valid


def test_unicode_details(original, key):
    signed = core.sign_photo(original, key, name="Élodie 山", details={"copyright": "© 2026"})
    assert core.verify_photo(signed.png).manifest["photographer"] == "Élodie 山"


def test_animated_input_rejected(key):
    out = io.BytesIO()
    Image.new("RGB", (200, 200), "red").save(
        out, format="PNG", save_all=True, append_images=[Image.new("RGB", (200, 200), "blue")]
    )
    with pytest.raises(core.PhotoSignError, match="Animated"):
        core.sign_photo(out.getvalue(), key, name="Ada")
