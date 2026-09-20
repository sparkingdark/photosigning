"""Maximum-resilience stack: TrustMark lookup is never accepted without visual proof."""

import io
import math

import numpy as np
import pytest
from PIL import Image

from photosigning.core import generate_key, read_photo
from photosigning.demo import demo_photo
from photosigning.registry import Registry, create_record
from photosigning.trustmark_image import (
    ALGORITHM,
    c2pa_soft_binding,
    embed_trustmark,
    record_tag,
    tag_bits,
    verify_trustmark,
)
from photosigning.workflow import MAXIMUM_RESILIENCE, inspect_photo, protect_photo


def encode(photo, quality=72):
    output = io.BytesIO()
    photo.convert("RGB").save(output, format="JPEG", quality=quality, optimize=True)
    return output.getvalue()


def test_tag_and_soft_binding_are_c2pa_registered_format():
    record_id = "0123456789" + "ab" * 27
    assert record_tag(record_id) == "0123456789"
    assert tag_bits("0123456789") == f"{int('0123456789', 16):040b}"
    assertion = c2pa_soft_binding(record_id)
    assert assertion["data"]["alg"] == ALGORITHM == "com.adobe.trustmark.Q"
    assert assertion["data"]["blocks"][0]["value"].startswith("0*")


def test_registry_prefix_lookup_authenticates_records(tmp_path):
    data, key = demo_photo(), generate_key()
    record = create_record(data, key, name="Ada", details={})
    registry = Registry(tmp_path / "registry.sqlite3")
    registry.save(record)
    assert registry.find_by_prefix(record["record_id"][:10]) == [record]
    assert registry.find_by_prefix("0000000000") == []


@pytest.fixture(scope="module")
def maximum_export(tmp_path_factory):
    registry = Registry(tmp_path_factory.mktemp("maximum") / "registry.sqlite3")
    result = protect_photo(
        demo_photo(), generate_key(), name="Ada Photographer",
        details={"camera_model": "X-T5"}, method=MAXIMUM_RESILIENCE, registry=registry,
    )
    return result, registry


def test_maximum_export_has_trustmark_and_c2pa(maximum_export):
    result, registry = maximum_export
    proof = verify_trustmark(result.data, use_crop_detector=False)
    assert proof.valid and proof.tag == result.record["record_id"][:10]
    assert result.c2pa["valid"]
    active = result.c2pa["manifest_store"]["manifests"][
        result.c2pa["manifest_store"]["active_manifest"]
    ]
    soft = next(a for a in active["assertions"] if a["label"] == "c2pa.soft-binding")
    assert soft["data"]["alg"] == ALGORITHM
    assert registry.get(result.record["record_id"]) == result.record


def test_maximum_export_does_not_add_visible_block_artifacts(maximum_export):
    result, _ = maximum_export
    source = np.asarray(read_photo(demo_photo()).convert("RGB"), dtype=np.float32)
    marked = np.asarray(read_photo(result.data).convert("RGB"), dtype=np.float32)
    mse = float(np.mean(np.square(source - marked)))
    psnr = math.inf if mse == 0 else 20 * math.log10(255 / math.sqrt(mse))
    # TrustMark is lossy, but the recommended export must remain visually close.
    assert psnr >= 34


@pytest.mark.parametrize(
    ("width", "quality"),
    [(1080, 82), (960, 72), (720, 60)],
    ids=["facebook-like", "whatsapp-like", "heavy-recompression"],
)
def test_simulated_social_recompression_recovers_signed_record(maximum_export, width, quality):
    result, registry = maximum_export
    photo = read_photo(result.data)
    if photo.width > width:
        photo = photo.resize(
            (width, round(photo.height * width / photo.width)), Image.Resampling.LANCZOS
        )
    shared = encode(photo, quality)
    assert verify_trustmark(shared).valid
    report = inspect_photo(shared, registry=registry)
    assert report["status"] == "trustmark"
    assert report["record_id"] == result.record["record_id"]


def test_copied_trustmark_tag_is_not_accepted_without_visual_match(maximum_export):
    result, registry = maximum_export
    # Register an unrelated image under the same test environment. The verifier
    # must still require a visual match to the record selected by the short tag.
    unrelated = Image.effect_noise((800, 600), 40).convert("RGB")
    output = io.BytesIO()
    unrelated.save(output, format="PNG")
    forged = embed_trustmark(output.getvalue(), result.record["record_id"])
    assert verify_trustmark(forged, use_crop_detector=False).valid
    report = inspect_photo(forged, registry=registry)
    assert report["status"] != "trustmark"
    assert not report["trustmark_valid"]


def test_trustmark_fallback_recovers_after_moderate_crop(maximum_export):
    result, registry = maximum_export
    photo = read_photo(result.data).convert("RGB")
    retained_area = 0.7
    width = round(photo.width * retained_area**0.5)
    height = round(photo.height * retained_area**0.5)
    left, top = (photo.width - width) // 2, (photo.height - height) // 2
    cropped = photo.crop((left, top, left + width, top + height))
    shared = encode(cropped, 70)
    report = inspect_photo(shared, registry=registry)
    assert report["status"] == "trustmark"
    assert report["trustmark_valid"]
    assert report["record_id"] == result.record["record_id"]
