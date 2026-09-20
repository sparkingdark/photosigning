"""PhotoSigning's entirely Python-driven Streamlit interface."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import streamlit as st

from photosigning.content_credentials import load_credentials
from photosigning.core import (
    PhotoSignError,
    export_private_key,
    extract_exif,
    fingerprint,
    generate_key,
    load_private_key,
    load_public_key,
    public_pem,
    read_photo,
)
from photosigning.demo import demo_photo
from photosigning.registry import Registry, record_fingerprint
from photosigning.registry_ui import render_registry
from photosigning.workflow import MAXIMUM_RESILIENCE, METHODS, inspect_photo, protect_photo

st.set_page_config(page_title="PhotoSigning · Make it yours", page_icon="◈", layout="wide")

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&display=swap');
html, body, [class*="css"], .stApp {font-family:'DM Sans',sans-serif;}
h1,h2,h3 {font-family:'Manrope',sans-serif!important;letter-spacing:-1.4px!important;}
.stMainBlockContainer {max-width:1400px;padding:2.7rem 3.4rem 3rem;}
[data-testid="stSidebar"] {background:#202C27;}
[data-testid="stSidebar"] * {color:#E8EBE3;}
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] * {color:#A9B5AB;}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] hr {border-color:#415047;}
[data-testid="stSidebar"] [data-testid="stRadio"] label {padding:10px 4px;}
[data-testid="stSidebar"] button {background:#35473B;border-color:#506153;}
[data-testid="stSidebar"] [data-testid="stAlert"] {background:#35473B;}
[data-testid="stHeader"] {background:transparent;}
.brand {font-family:'Manrope',sans-serif;font-weight:800;font-size:25px;letter-spacing:-1px;margin:9px 0 3px;}
.brand-icon {color:#E0AF78!important;margin-right:7px;font-size:30px;}
.brand-sub {color:#ABB8AC!important;font-size:11px;letter-spacing:2.5px;margin:0 0 38px 41px;}
.eyebrow {font-size:11px;letter-spacing:2.3px;font-weight:700;color:#7C8278;margin-bottom:13px;}
.hero-title {font-family:'Manrope',sans-serif;font-size:44px;line-height:1.15;letter-spacing:-2px;font-weight:800;color:#24332A;margin-bottom:15px;}
.hero-sub {font-size:15px;color:#797D72;line-height:1.8;max-width:650px;}
.pill {display:inline-block;padding:7px 12px;border:1px solid #D8DDD0;border-radius:30px;font-size:11px;color:#53664E;background:#F0F2E9;letter-spacing:.4px;}
.steps {display:flex;gap:25px;padding:24px 0 28px;flex-wrap:wrap;}
.step {font-size:12px;color:#7E8378;display:flex;align-items:center;gap:9px;}
.step b {font-size:11px;border:1px solid #D6D9CE;border-radius:50%;width:25px;height:25px;display:inline-flex;align-items:center;justify-content:center;}
.step.active {color:#283C2C;font-weight:600;}.step.active b {color:#FFF;background:#344B37;border-color:#344B37;}
.section-label {font-size:15px;font-weight:700;letter-spacing:-.3px;margin:3px 0 2px;}
.subtle {font-size:12px;color:#84887F;line-height:1.7;}
.empty-preview {height:320px;border:1px dashed #D3D6CA;border-radius:12px;background:radial-gradient(ellipse at center,#E8EBDF,#F2F2EB);display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;}
.preview-symbol {font-size:67px;font-weight:400;color:#7D8A76;line-height:1.4;}
.empty-preview strong {font-size:17px;color:#42503D;margin:8px 0;}
.empty-preview span {font-size:12px;color:#7B8574;line-height:1.8;}
.note {border-left:2px solid #CC9B6D;padding:4px 0 4px 14px;margin:19px 0;color:#777E70;font-size:12px;line-height:1.8;}
.footer {border-top:1px solid #DDDFD5;margin-top:36px;padding-top:19px;font-size:11px;color:#8A8F81;letter-spacing:.4px;}
[data-testid="stVerticalBlockBorderWrapper"]>div {border-color:#DDDFD5!important;border-radius:12px!important;}
[data-testid="stFileUploader"] section {background:#F0F0E8;border:1px dashed #D2D5C9;border-radius:9px;}
[data-testid="stImage"] img {border-radius:9px;}
[data-testid="stTextInput"] input {font-size:13px;}
.stButton>button,.stDownloadButton>button,.stFormSubmitButton>button {border-radius:7px;min-height:42px;font-size:13px;font-weight:600;}
button[kind="primary"],button[kind="primaryFormSubmit"] {background:#C86545;border-color:#C86545;}
[data-testid="stMetricValue"] {font-size:24px!important;}
@media(max-width:800px){.stMainBlockContainer{padding:2rem 1rem;}.hero-title{font-size:34px;}.steps{gap:14px;}}
</style>
""",
    unsafe_allow_html=True,
)


@st.cache_data
def get_demo() -> bytes:
    return demo_photo()


def heading(kicker: str, title: str, subtitle: str) -> None:
    st.markdown(
        f'<div class="eyebrow">{kicker}</div><div class="hero-title">{title}</div>'
        f'<div class="hero-sub">{subtitle}</div>',
        unsafe_allow_html=True,
    )


def show_fingerprint(value: str) -> None:
    st.caption("PUBLIC KEY FINGERPRINT · SHA-256")
    st.code(value, language=None, wrap_lines=True)


def show_c2pa(report: dict | None) -> None:
    st.markdown("**C2PA · Content Credentials**")
    if report is None:
        st.caption(
            "No new C2PA credential added. Enable it when signing; registry-only preserves the original."
        )
        return
    if report["trusted"]:
        st.success("C2PA credential verified · signing certificate is trusted")
        st.caption(
            "Certificate trust identifies the claim generator or certificate holder. "
            "A verified person requires a separate CAWG creator-identity assertion."
        )
    elif report["valid"]:
        st.success("C2PA embedded and verified · content intact")
        st.warning(
            "Identity is unknown: the included certificate is self-issued and is not in a "
            "recognized trust list. Supplying the public key is not required to check integrity."
        )
    elif report["status"] in ("invalid", "error"):
        st.error(report["message"])
    else:
        st.info(report["message"])
    if report.get("manifest_store"):
        with st.expander("View C2PA manifest and validation"):
            st.json(report["manifest_store"])
            st.download_button(
                "↓ Download C2PA manifest report",
                json.dumps(report["manifest_store"], indent=2),
                "c2pa-manifest.json",
                "application/json",
                key="c2pa_report",
                on_click="ignore",
            )


def show_manifest(manifest: dict) -> None:
    a, b = st.columns(2)
    a.metric("Photographer", manifest["photographer"])
    b.metric("Camera", manifest["details"].get("camera_model", "Not specified"))
    st.caption(f"Signed {manifest['signed_at']} · Ed25519 · SHA-256")
    if manifest["details"]:
        st.dataframe(
            [
                {"Detail": k.replace("_", " ").capitalize(), "Signed value": v}
                for k, v in manifest["details"].items()
            ],
            hide_index=True,
            width="stretch",
        )
    with st.expander("View signed manifest"):
        st.json(manifest)


with st.sidebar:
    st.markdown(
        '<div class="brand"><span class="brand-icon">◈</span>PhotoSigning</div>'
        '<div class="brand-sub">A MARK THAT MATTERS</div>',
        unsafe_allow_html=True,
    )
    st.caption("YOUR WORKSPACE")
    page = st.radio(
        "Navigation",
        ["Sign a photo", "Verify a photo", "Photo registry", "Your keys", "How it works"],
        label_visibility="collapsed",
    )
    st.markdown("---")
    st.caption("SIGNING IDENTITY")
    if "private_key" in st.session_state:
        st.markdown("**● Key ready to sign**")
        st.caption(f"{fingerprint(st.session_state.private_key)[:20]}…")
        st.caption("This key lives in your current session. Save an encrypted backup in Your keys.")
    else:
        st.markdown("**No signing key yet**")
        st.caption("Create a key to put your signature behind every photograph.")
        if st.button("＋ Create a signing key", width="stretch"):
            st.session_state.private_key = generate_key()
            st.rerun()
    st.markdown("---")
    st.caption("PRIVATE BY DESIGN")
    st.caption(
        "Processed by this Python app. No third-party image service. "
        "Run locally to keep photos and keys on your device."
    )
    st.markdown(
        '<div style="margin-top:50px;font-size:11px;color:#9AA99A">'
        "Made for the people behind the lens.<br>PhotoSigning / 1.0</div>",
        unsafe_allow_html=True,
    )


if page == "Sign a photo":
    heading(
        "YOUR PHOTO. YOUR SIGNATURE.",
        "Make it unmistakably yours.",
        "Sign your photo, add an invisible watermark for shared copies, or register its visual "
        "fingerprint. Verification keys travel with the proof.",
    )
    st.markdown(
        '<div class="steps"><div class="step active"><b>1</b> Choose your photo</div>'
        '<div class="step"><b>2</b> Add your details</div>'
        '<div class="step"><b>3</b> Sign & download</div></div>',
        unsafe_allow_html=True,
    )
    left, right = st.columns([1.25, 1], gap="large")
    photo_bytes = None
    filename = "photo"
    exif = {}
    with left:
        with st.container(border=True):
            st.markdown(
                '<div class="section-label">The photograph</div>'
                '<div class="subtle">Start with the image you want to put your name on.</div>',
                unsafe_allow_html=True,
            )
            upload = st.file_uploader(
                "Choose a photo",
                type=["jpg", "jpeg", "png", "webp", "tif", "tiff"],
                label_visibility="collapsed",
                key="sign_upload",
            )
            demo = st.toggle(
                "Try a demo landscape",
                value=False,
                help="A locally generated illustration, ready to sign and verify.",
            )
            if upload is not None:
                photo_bytes, filename = upload.getvalue(), Path(upload.name).stem
            elif demo:
                photo_bytes, filename = get_demo(), "demo-landscape"
            if photo_bytes:
                try:
                    photo = read_photo(photo_bytes, orient=True)
                    exif = extract_exif(photo_bytes)
                    st.image(photo, width="stretch")
                    c1, c2, c3 = st.columns(3)
                    c1.caption(f"{photo.width:,} × {photo.height:,} PX")
                    c2.caption(f"{len(photo_bytes) / 1024 / 1024:.2f} MB")
                    c3.caption("PNG OUTPUT")
                except PhotoSignError as exc:
                    st.error(str(exc))
                    photo_bytes = None
            else:
                st.markdown(
                    '<div class="empty-preview"><div class="preview-symbol">▧</div>'
                    "<strong>Your next signature starts here</strong>"
                    "<span>Choose a photograph above, or try the demo.<br>"
                    "JPG, PNG, WebP or TIFF · up to 40 MB / 25 MP</span></div>",
                    unsafe_allow_html=True,
                )
        st.markdown(
            '<div class="note">Choose the protection your photo needs.<br>'
            "Exact signing checks every pixel. The resilient watermark tolerates common sharing edits. "
            "Registry recognition helps find edited copies.</div>",
            unsafe_allow_html=True,
        )
    with right:
        with st.container(border=True):
            st.markdown(
                '<div class="section-label">Behind the lens</div>'
                '<div class="subtle">These details become part of your signed photo.</div>',
                unsafe_allow_html=True,
            )
            token = hashlib.sha256(photo_bytes or b"").hexdigest()[:12]
            with st.form(f"sign_form_{token}"):
                name = st.text_input(
                    "Photographer name *",
                    value=exif.get("artist", ""),
                    placeholder="Your name or studio",
                    max_chars=200,
                )
                a, b = st.columns(2)
                make = a.text_input(
                    "Camera make",
                    value=exif.get("camera_make", ""),
                    placeholder="e.g. Fujifilm",
                    max_chars=500,
                )
                model = b.text_input(
                    "Camera model",
                    value=exif.get("camera_model", ""),
                    placeholder="e.g. X-T5",
                    max_chars=500,
                )
                lens = st.text_input(
                    "Lens",
                    value=exif.get("lens", ""),
                    placeholder="e.g. XF 35mm f/1.4",
                    max_chars=500,
                )
                copyright_text = st.text_input(
                    "Copyright / credit",
                    value=exif.get("copyright", ""),
                    placeholder="e.g. © 2026 Your name",
                    max_chars=500,
                )
                with st.expander("More EXIF details", expanded=False):
                    st.caption(
                        "Read from your photo when available. Review before signing. GPS and serial numbers are excluded."
                    )
                    extra = {}
                    for field, label in [
                        ("captured_at", "Capture date"),
                        ("exposure", "Exposure time"),
                        ("aperture", "Aperture"),
                        ("iso", "ISO"),
                        ("focal_length", "Focal length"),
                    ]:
                        extra[field] = st.text_input(
                            label, value=exif.get(field, ""), max_chars=500
                        )
                method = st.selectbox(
                    "Protection method",
                    [METHODS[0], METHODS[2], MAXIMUM_RESILIENCE],
                    index=2,
                    help="Maximum resilience combines Adobe TrustMark, registry fingerprints, exact signing, and C2PA. Registry-only leaves the photo unchanged.",
                )
                save_registry = st.checkbox(
                    "Save unique photo ID in my local registry",
                    value=True,
                    help="Stores a signed record and visual features for recognizing edited copies. No private key is saved.",
                )
                include_c2pa = st.checkbox(
                    "Embed C2PA Content Credentials",
                    value=True,
                    help="Adds standard Content Credentials to exact, invisible-watermark, and maximum-resilience PNGs. Registry-only keeps the original unchanged.",
                )
                st.caption(
                    "C2PA uses your imported certificate from Your keys, or a local untrusted certificate. "
                    "It appears in compatible viewers, not as a visible badge in the pixels. "
                    "Registry-only adds no C2PA credential."
                )
                st.caption(
                    "No separate public key required. Edited-image matches do not prove unchanged pixels. "
                    "No method survives every crop, resize, or manipulation."
                )
                if method == MAXIMUM_RESILIENCE:
                    st.info(
                        "Recommended for Facebook and WhatsApp sharing. First use downloads local "
                        "TrustMark models. Keep registry saving on; it authenticates the short watermark ID."
                    )
                submitted = st.form_submit_button(
                    "Sign & seal photograph  ↗", type="primary", width="stretch"
                )
            if submitted:
                if photo_bytes is None:
                    st.error("Choose a photo or turn on the demo first.")
                elif "private_key" not in st.session_state:
                    st.error("Create a signing key in the sidebar, or import one in Your keys.")
                else:
                    try:
                        with st.spinner("Signing your photograph…"):
                            exported = protect_photo(
                                photo_bytes,
                                st.session_state.private_key,
                                name=name,
                                details={
                                    **extra,
                                    "camera_make": make,
                                    "camera_model": model,
                                    "lens": lens,
                                    "copyright": copyright_text,
                                },
                                method=method,
                                registry=Registry() if save_registry else None,
                                include_c2pa=include_c2pa,
                                c2pa_credentials=st.session_state.get("c2pa_credentials"),
                            )
                            st.session_state.photo_export = exported
                            st.session_state.signed_filename = (
                                f"{filename}-signed.png"
                                if exported.exact
                                else upload.name
                                if upload
                                else "demo-landscape.png"
                            )
                            st.session_state.signed_source = token
                    except PhotoSignError as exc:
                        st.error(str(exc))
        st.markdown(
            '<span class="pill">◈ &nbsp; YOUR PRIVATE KEY NEVER GOES INTO THE PHOTO</span>',
            unsafe_allow_html=True,
        )
    if "photo_export" in st.session_state:
        exported = st.session_state.photo_export
        with st.container(border=True):
            label = "Signed and verified" if exported.exact else "Registered · signed record ready"
            st.success(f"{label} · {st.session_state.signed_filename}")
            st.caption(f"Protection: {exported.method}")
            if exported.method == MAXIMUM_RESILIENCE:
                st.success(
                    "TrustMark Q passed its export check without stacking the block-DCT watermark. "
                    "Keep the signed registry record so edited copies can resolve the short tag."
                )
            show_c2pa(getattr(exported, "c2pa", None))
            st.caption("UNIQUE PHOTO ID · SHA-256 of the signed record's manifest")
            st.code(exported.record["record_id"], language=None, wrap_lines=True)
            if st.session_state.signed_source != token:
                st.caption(
                    "This is your last signed export. Sign again to export the currently selected photo."
                )
            a, b, c = st.columns(3)
            a.download_button(
                "↓ Download signed PNG" if exported.exact else "↓ Download unchanged original",
                exported.data,
                st.session_state.signed_filename,
                mime="image/png" if exported.exact else "application/octet-stream",
                type="primary",
                width="stretch",
            )
            b.download_button(
                "↓ Back up signed photo record",
                json.dumps(exported.record, indent=2),
                f"{exported.record['record_id'][:16]}.photosigning.json",
                "application/json",
                width="stretch",
            )
            # Derive this export from the actual signature, even if the active key later changes.
            import base64

            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            signed_public = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(exported.record["manifest"]["public_key"])
            )
            c.download_button(
                "↓ Public key (optional)",
                public_pem(signed_public),
                "signer-public.pem",
                width="stretch",
            )
            st.caption(
                "Save the record JSON to recover full signed details on another installation. "
                "The invisible proof verifies without a key file or registry; registry-only recognition needs its record."
            )

elif page == "Verify a photo":
    heading(
        "LET THE PIXELS SPEAK",
        "A photo with a story. Verify it.",
        "Check C2PA Content Credentials and exact signatures, recover invisible watermarks, and look for registered "
        "visual matches. No separate public-key upload is needed.",
    )
    st.write("")
    left, right = st.columns([1.15, 1], gap="large")
    with left, st.container(border=True):
        upload = st.file_uploader(
            "Photograph to verify",
            type=["png", "jpg", "jpeg", "webp", "tif", "tiff"],
            key="verify_upload",
        )
        use_last = st.checkbox(
            "Use my last signed photo", disabled="photo_export" not in st.session_state
        )
        data = (
            st.session_state.photo_export.data
            if use_last and "photo_export" in st.session_state
            else upload.getvalue()
            if upload
            else None
        )
        if data:
            try:
                st.image(read_photo(data), width="stretch")
            except PhotoSignError as exc:
                st.error(str(exc))
        else:
            st.markdown(
                '<div class="empty-preview"><div class="preview-symbol">◈</div>'
                "<strong>Every signature has a source</strong>"
                "<span>Add a signed photo to check its provenance.</span></div>",
                unsafe_allow_html=True,
            )
    with right, st.container(border=True):
        st.subheader("Verification, without extra key files")
        st.caption(
            "The public key is recovered from the proof automatically. To check a specific "
            "person's identity, you can optionally compare a key you already trust."
        )
        with st.expander("Optional signer identity check"):
            trusted_upload = st.file_uploader(
                "Trusted public key", type=["pem"], key="trusted_upload"
            )
            current = st.checkbox(
                "Trust my current session’s public key",
                disabled="private_key" not in st.session_state,
            )
        search_registry = st.checkbox("Look for matches in my photo registry", value=True)
        expected_id = st.text_input(
            "Unique photo ID (optional)",
            max_chars=64,
            placeholder="Paste the full SHA-256 record ID to narrow the search",
        )
        verify = st.button(
            "Verify photograph  ↗", type="primary", width="stretch", disabled=data is None
        )
        if verify and data:
            try:
                if trusted_upload and current:
                    raise PhotoSignError(
                        "Choose one trusted key source: the uploaded key or your session key."
                    )
                trusted = (
                    load_public_key(trusted_upload.getvalue())
                    if trusted_upload
                    else st.session_state.private_key.public_key()
                    if current
                    else None
                )
                with st.spinner("Checking signatures and registered visual fingerprints…"):
                    report = inspect_photo(
                        data,
                        trusted_key=trusted,
                        registry=Registry() if search_registry else None,
                        record_id=expected_id.strip(),
                    )
                if report["status"] in ["exact", "registered_exact"]:
                    st.success("Signature verified · image intact")
                elif report["status"] == "watermark":
                    st.success("Authentic invisible watermark recovered")
                    st.warning(
                        "Perceptual match — edits may be present. This does not certify unchanged pixels."
                    )
                elif report["status"] == "trustmark":
                    st.success("Adobe TrustMark + signed registry record verified")
                    st.warning(
                        "Durable visual match — edits may be present. This does not certify unchanged pixels."
                    )
                elif report["status"] in (
                    "trustmark_unresolved",
                    "trustmark_mismatch",
                    "candidates",
                ):
                    st.warning(report["message"])
                elif report["status"] == "c2pa":
                    st.info("C2PA Content Credentials found. See the validation result below.")
                else:
                    st.error(report["message"])
                show_c2pa(report["c2pa"])
                if report["status"] in ["exact", "registered_exact", "watermark", "trustmark"]:
                    if report["identity_trusted"]:
                        st.success("Signer matches your trusted public key.")
                    else:
                        st.info(
                            "Signature checked using its included key. The signer's real-world identity is unconfirmed."
                        )
                    if report["manifest"]:
                        show_manifest(report["manifest"])
                    elif report["record_id"]:
                        st.caption(
                            "Import the photo record in Photo registry to recover its name and EXIF details."
                        )
                if report["fingerprint"]:
                    show_fingerprint(report["fingerprint"])
                if report.get("normalization", "none") != "none":
                    st.caption("Watermark recovered after normalizing rotation or reflection.")
                if report["provenance_conflicts"]:
                    st.warning(
                        "Matching photos are also registered under other signing keys. "
                        "This signature does not establish who created or owns the photo. "
                        "Review the records; collaboration or key changes can also explain this."
                    )
                    with st.expander("Review matching records from other signers", expanded=True):
                        for conflict in report["provenance_conflicts"]:
                            st.write("Registered name:", conflict["photographer"])
                            st.code(conflict["record_id"], language=None, wrap_lines=True)
                            st.caption("Signing key: " + conflict["fingerprint"])
                if report["record_id"]:
                    st.caption("RECOVERED UNIQUE PHOTO ID")
                    st.code(report["record_id"], language=None, wrap_lines=True)
                if report["status"] == "candidates":
                    for match in report["candidates"]:
                        record = match["record"]
                        with st.container(border=True):
                            st.write("Possible match:", record["manifest"]["photographer"])
                            st.code(record["record_id"], language=None, wrap_lines=True)
                            st.caption(
                                f"Method: {match['method']} · perceptual distance: {match['phash_distance']} · "
                                f"geometric inliers: {match['geometric_inliers']}"
                            )
                            st.caption(
                                "Record signature verified. A visual match is not an authenticated signature on this copy."
                            )
                            if trusted is not None:
                                if record_fingerprint(record) == fingerprint(trusted):
                                    st.caption("Candidate record signer matches your trusted key.")
                                else:
                                    st.warning(
                                        "Candidate record signer does not match your trusted key."
                                    )
                st.download_button(
                    "↓ Download verification report",
                    json.dumps(report, indent=2),
                    "verification-report.json",
                    "application/json",
                    on_click="ignore",
                )
            except PhotoSignError as exc:
                st.error(str(exc))
    st.caption(
        "Names, EXIF details, and signing times are statements made by the signer. "
        "They are not independently certified or proof of copyright ownership."
    )

elif page == "Photo registry":
    heading(
        "RECOGNIZE YOUR WORK",
        "A lasting record. A unique photo ID.",
        "Keep signed details and visual fingerprints so you can look for edited copies, "
        "even when their embedded watermark is gone.",
    )
    st.write("")
    render_registry()

elif page == "Your keys":
    heading(
        "YOUR SIGNING IDENTITY",
        "One key. A body of work.",
        "Keep your private key safe. Share your public key so others can recognize your signature.",
    )
    st.write("")
    left, right = st.columns(2, gap="large")
    with left:
        with st.container(border=True):
            st.subheader("Your active key")
            if "private_key" in st.session_state:
                st.success("Ed25519 signing key is ready")
                show_fingerprint(fingerprint(st.session_state.private_key))
                st.download_button(
                    "↓ Save public key",
                    public_pem(st.session_state.private_key),
                    "photosigning-public.pem",
                    width="stretch",
                )
                st.markdown("**Back up your private key**")
                st.caption(
                    "Your key disappears when this session ends. Save this encrypted backup to sign with the same identity later."
                )
                password = st.text_input("Backup password", type="password", key="backup_password")
                if len(password) >= 8:
                    st.download_button(
                        "↓ Save encrypted private key",
                        export_private_key(st.session_state.private_key, password),
                        "photosigning-private.pem",
                        type="primary",
                        width="stretch",
                    )
                else:
                    st.caption("Enter at least 8 characters to enable the encrypted backup.")
            else:
                st.caption("A key pair connects your photos to a consistent signing identity.")
                if st.button("Create my first key", type="primary", width="stretch"):
                    st.session_state.private_key = generate_key()
                    st.rerun()
        if "private_key" in st.session_state:
            with st.expander("Replace session key"):
                confirm = st.checkbox("I have backed up my current key and want a new identity.")
                if st.button("Generate a replacement key", disabled=not confirm):
                    st.session_state.private_key = generate_key()
                    st.rerun()
    with right:
        with st.container(border=True):
            st.subheader("Bring your existing key")
            st.caption(
                "Import an Ed25519 PEM private key to continue signing as the same photographer."
            )
            with st.form("import_key", clear_on_submit=True):
                key_upload = st.file_uploader("Private key file", type=["pem", "key"])
                password = st.text_input("Key password", type="password")
                acknowledge = st.checkbox(
                    "Replace the current session key (if any). I have saved its backup."
                )
                imported = st.form_submit_button("Unlock & use key", width="stretch")
            if imported:
                if key_upload is None:
                    st.error("Choose your private key file first.")
                elif "private_key" in st.session_state and not acknowledge:
                    st.error("Confirm that you have saved your current key before replacing it.")
                else:
                    try:
                        st.session_state.private_key = load_private_key(
                            key_upload.getvalue(), password
                        )
                        st.rerun()
                    except PhotoSignError as exc:
                        st.error(str(exc))
        st.info(
            "Public key → share with anyone who needs to verify your work.\n\n"
            "Private key + password → keep to yourself. Anyone with these can sign as you."
        )
    with st.expander("C2PA signing certificate (optional)"):
        st.caption(
            "Without an import, C2PA uses a local certificate for your pixel-signing key. "
            "For recognition of this signing product by external viewers, supply an appropriate "
            "issued C2PA certificate chain and its matching private key. This is different from "
            "proving the photographer's personal identity. Importing does not automatically make "
            "a certificate trusted. This is a separate C2PA signer; your pixel-signing key stays the same. "
            "Credentials remain in this server session. No timestamp authority or online revocation check is used."
        )
        if st.session_state.get("c2pa_credentials"):
            st.success("Imported C2PA signer is selected for new exports.")
            if st.button("Use local C2PA certificate instead"):
                del st.session_state.c2pa_credentials
                st.rerun()
        with st.form("c2pa_import", clear_on_submit=True):
            chain = st.file_uploader(
                "C2PA certificate chain · leaf certificate first", type=["pem", "crt"]
            )
            c2pa_key = st.file_uploader("C2PA private key", type=["pem", "key"])
            c2pa_password = st.text_input("C2PA key password", type="password")
            import_c2pa = st.form_submit_button("Use C2PA credentials")
        if import_c2pa:
            if chain is None or c2pa_key is None:
                st.error("Choose both the C2PA certificate chain and its matching private key.")
            else:
                try:
                    st.session_state.c2pa_credentials = load_credentials(
                        chain.getvalue(), c2pa_key.getvalue(), c2pa_password
                    )
                    st.rerun()
                except PhotoSignError as exc:
                    st.error(str(exc))
    with st.expander("Tie photographs to a verified person or organization"):
        st.write(
            "The public key already travels with each proof, so an extra key file is not needed "
            "for cryptographic verification. A key created on this computer has no independent "
            "evidence of who owns it, which is why the verifier reports an unknown identity."
        )
        st.markdown(
            "For public real-world attribution, obtain a **CAWG identity credential** from an "
            "identity provider. It can attest to a verified name or document, a controlled website, "
            "an organization affiliation, or a social account. Apply that identity after exporting "
            "from PhotoSigning with a compatible service such as "
            "[Adobe Content Authenticity](https://contentauthenticity.adobe.com/). The resulting "
            "Content Credential carries the provider's signed identity evidence."
        )
        st.info(
            "PhotoSigning cannot honestly mark a typed name as verified. It does not perform ID "
            "checks or operate an identity authority. For a private group, members can instead "
            "exchange and approve public-key fingerprints through an already trusted channel."
        )

else:
    heading(
        "A LITTLE SCIENCE. A LOT OF OWNERSHIP.",
        "The signature is in the pixels.",
        "PhotoSigning binds your chosen details to a photograph using a public/private key pair.",
    )
    st.write("")
    for title, description in [
        (
            "01 / Give your photo a signing identity",
            "Create or import an Ed25519 key. Your private key signs; your public key verifies. Back up your private key before leaving the session.",
        ),
        (
            "02 / Sign the photograph and its details",
            "We read selected EXIF fields for you to review. Your name, camera, lens, and other chosen details are signed together with a SHA-256 digest of the image pixels.",
        ),
        (
            "03 / Choose resilience or exact integrity",
            "Exact signatures detect pixel edits. Maximum resilience uses an invisible TrustMark plus an authenticated registry match for common resizing and compression without the visibly blocky legacy DCT layer. Registry-only stores a signed recognition record and leaves the photo unchanged.",
        ),
        (
            "04 / Verify without a separate public key",
            "Keys travel in the embedded proof or signed registry record. Verification automatically tries exact integrity, then invisible watermark recovery, then registry recognition. An optional trusted key checks the expected signer. A unique SHA-256 photo ID locates a signed record; it does not make an edited image's hash stay unchanged.",
        ),
        (
            "05 / Include standard Content Credentials",
            "C2PA is enabled by default for signed PNG exports. Its certificate and signed manifest travel inside the file. A local certificate is untrusted by external viewers. A CAWG identity credential from an independent provider is needed for verified creator identity. Metadata stripping can remove C2PA while the pixel watermark may still be recoverable.",
        ),
    ]:
        with st.container(border=True):
            st.subheader(title)
            st.write(description)
    st.warning(
        "No watermark survives every manipulation. Tiny thumbnails, major crops, heavy filters, overlays, and deliberate removal can defeat recovery. The invisible watermark is tested against common resizing and recompression, but actual social-media pipelines vary. Registry recognition can find some cropped or rotated copies and reports candidates, not proof that they are unchanged."
    )
    st.info(
        "A valid signature establishes control of a key. Names, camera details, and timestamps are signer-supplied claims. They do not independently prove identity, capture time, or legal ownership."
    )
    st.caption(
        "Exact signing authenticates pixels and signed details. Invisible watermarking authenticates a perceptual fingerprint and record ID. Registry records authenticate their stored claims and features; visual similarity alone cannot prove authorship. Signed PNG exports omit original EXIF, GPS, and serial numbers. Registry-only returns your original file unchanged, including its metadata."
    )
    st.markdown(
        "The image watermark is a modified Python adaptation of "
        "[Majik Signature](https://github.com/Majikah/majik-signature), Apache-2.0. "
        "It uses a distinct PhotoSigning format and does not implement the full Majik SDK."
    )

st.markdown(
    '<div class="footer">◈ &nbsp; PHOTOSIGNING &nbsp; / &nbsp; '
    "Invisible in the image. Verifiable in the details.</div>",
    unsafe_allow_html=True,
)
