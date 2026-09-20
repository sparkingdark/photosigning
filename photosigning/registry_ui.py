"""Python UI for portable signed records and the local recognition registry."""

import json

import streamlit as st

from .core import PhotoSignError
from .registry import Registry, import_record, record_fingerprint


def render_registry():
    st.caption(
        "Records persist on this app's machine. They contain signed details and visual "
        "fingerprints, including a small grayscale representation, not full-resolution photos or private keys. "
        "Back up the record JSON files to use them on another installation."
    )
    registry = Registry()
    with st.expander("Import a signed record", expanded=False):
        uploaded = st.file_uploader("Photo record JSON", type=["json"], key="registry_import")
        if st.button("Authenticate & import record", disabled=uploaded is None):
            try:
                record = import_record(uploaded.getvalue())
                registry.save(record)
                st.success("Record signature and hash verified. Added to this local registry.")
            except PhotoSignError as exc:
                st.error(str(exc))
    try:
        records = registry.records()
        st.metric("Registered photos", len(records))
        lookup = st.text_input(
            "Find by unique SHA-256 photo ID",
            max_chars=64,
            placeholder="Paste the full 64-character photo ID",
        )
        if lookup:
            selected = registry.get(lookup)
            if selected is None:
                st.info("That ID is not in this registry. Import its record JSON first.")
        elif records:
            selected_id = st.selectbox(
                "Photo record",
                [r["record_id"] for r in records],
                format_func=lambda value: next(
                    f"{r['manifest']['photographer']} · {value[:16]}…"
                    for r in records
                    if r["record_id"] == value
                ),
            )
            selected = next(r for r in records if r["record_id"] == selected_id)
        else:
            selected = None
            st.info("Sign or register a photo, or import a signed record, to begin.")
        if selected:
            st.success("Record signature verified")
            st.caption("UNIQUE PHOTO ID · SHA-256 of the signed record's manifest")
            st.code(selected["record_id"], language=None, wrap_lines=True)
            st.write("Photographer:", selected["manifest"]["photographer"])
            st.write("Signed details:", selected["manifest"]["details"])
            st.caption("Signer fingerprint")
            st.code(record_fingerprint(selected), language=None, wrap_lines=True)
            st.download_button(
                "↓ Back up photo record",
                json.dumps(selected, indent=2),
                f"{selected['record_id'][:16]}.photosigning.json",
                "application/json",
            )
            st.caption(
                "The unique ID locates this signed record. It is not a secret, proof of identity, "
                "or a hash that remains identical when photo pixels change."
            )
    except PhotoSignError as exc:
        st.error(str(exc))
