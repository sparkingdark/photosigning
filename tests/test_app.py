import io
from dataclasses import replace
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from photosigning.core import read_photo
from photosigning.workflow import METHODS

APP = str(Path(__file__).resolve().parents[1] / "app.py")


@pytest.fixture(autouse=True)
def isolated_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("PHOTOSIGNING_REGISTRY", str(tmp_path / "registry.sqlite3"))


def test_navigation():
    app = AppTest.from_file(APP).run(timeout=30)
    assert not app.exception
    for page in ["Verify a photo", "Photo registry", "Your keys", "How it works", "Sign a photo"]:
        app.sidebar.radio[0].set_value(page).run()
        assert not app.exception


def test_complete_demo_sign_and_verify_workflow():
    app = AppTest.from_file(APP).run(timeout=30)
    app.sidebar.button[0].click().run()
    app.toggle[0].set_value(True).run()
    app.text_input[0].set_value("Ada Photographer")
    app.text_input[2].set_value("X-T5")
    next(b for b in app.button if "Sign & seal" in b.label).click().run(timeout=30)
    assert not app.exception
    assert any("Signed and verified" in s.value for s in app.success)
    assert any("C2PA embedded and verified" in s.value for s in app.success)
    assert any("Identity is unknown" in s.value for s in app.warning)
    app.sidebar.radio[0].set_value("Verify a photo").run()
    app.checkbox[0].set_value(True).run()
    app.checkbox[1].set_value(True).run()
    next(b for b in app.button if "Verify photograph" in b.label).click().run(timeout=30)
    assert not app.exception
    assert any("Signer matches" in s.value for s in app.success)
    assert any("C2PA embedded and verified" in s.value for s in app.success)


def test_missing_photo_shows_actionable_error():
    app = AppTest.from_file(APP).run(timeout=30)
    next(b for b in app.button if "Sign & seal" in b.label).click().run()
    assert not app.exception
    assert any("Choose a photo" in error.value for error in app.error)


def test_key_backup_ui():
    app = AppTest.from_file(APP).run(timeout=30)
    app.sidebar.button[0].click().run()
    app.sidebar.radio[0].set_value("Your keys").run()
    app.text_input(key="backup_password").set_value("a long backup password").run()
    assert not app.exception
    assert any(
        "Save encrypted private key" == button.label.lstrip("↓ ")
        for button in app.get("download_button")
    )


def test_trustmark_verification_ui_needs_no_separate_key():
    app = AppTest.from_file(APP).run(timeout=30)
    app.sidebar.button[0].click().run()
    app.toggle[0].set_value(True).run()
    app.text_input[0].set_value("Ada Photographer")
    next(b for b in app.button if "Sign & seal" in b.label).click().run(timeout=30)
    exported = app.session_state.photo_export
    output = io.BytesIO()
    read_photo(exported.data).save(output, format="JPEG", quality=70)
    app.session_state.photo_export = replace(exported, data=output.getvalue())
    app.sidebar.radio[0].set_value("Verify a photo").run()
    app.checkbox[0].set_value(True).run()
    next(b for b in app.button if "Verify photograph" in b.label).click().run(timeout=30)
    assert not app.exception
    assert any("Adobe TrustMark" in s.value for s in app.success)
    assert any("Durable visual match" in s.value for s in app.warning)
    assert any("No embedded C2PA" in s.value for s in app.info)


def test_registry_only_ui_workflow():
    app = AppTest.from_file(APP).run(timeout=30)
    app.sidebar.button[0].click().run()
    app.toggle[0].set_value(True).run()
    app.text_input[0].set_value("Ada Photographer")
    app.selectbox[0].set_value(METHODS[2])
    next(b for b in app.button if "Sign & seal" in b.label).click().run(timeout=30)
    assert not app.exception
    assert any("Registered" in s.value for s in app.success)
    app.sidebar.radio[0].set_value("Photo registry").run()
    assert not app.exception
    assert app.metric[0].value == "1"
    assert any("Record signature verified" in s.value for s in app.success)


def test_verification_warns_about_another_registered_signer():
    from photosigning.core import generate_key, sign_photo

    app = AppTest.from_file(APP).run(timeout=30)
    app.sidebar.button[0].click().run()
    app.toggle[0].set_value(True).run()
    app.text_input[0].set_value("Original photographer")
    next(b for b in app.button if "Sign & seal" in b.label).click().run(timeout=30)
    exported = app.session_state.photo_export
    resigned = sign_photo(exported.data, generate_key(), name="Another signer")
    app.session_state.photo_export = replace(exported, data=resigned.png)
    app.sidebar.radio[0].set_value("Verify a photo").run()
    app.checkbox[0].set_value(True).run()
    next(b for b in app.button if "Verify photograph" in b.label).click().run(timeout=30)
    assert not app.exception
    assert any("other signing keys" in warning.value for warning in app.warning)
