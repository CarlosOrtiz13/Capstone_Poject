"""
Streamlit user interface for the AI-Assisted Diamond Model of Intrusion Analysis application.
Orchestrates user input, analysis session execution, result display, and attempt history.
"""

import json

import streamlit as st

from core.analysis_session import AnalysisSession
from core.attempt_history_manager import AttemptHistoryManager
from core.validator import Validator
from services.analysis_importer import AnalysisImporter
from services.export_manager import ExportManager
from services.file_handler import FileHandler
from services.stix_importer import StixImporter
from services.stix_mapper import StixMapper


# ---------------------------------------------------------------------------
# Session state helpers
# ---------------------------------------------------------------------------

def _store_result(result: dict) -> None:
    """
    Write an analysis result dictionary into session state, clearing
    any stale STIX editor content from a previous run.

    Args:
        result: Normalized result dictionary from a session run or import.
    """
    st.session_state.pop("stix_bundle_text", None)
    st.session_state.selected_vertex = None
    st.session_state.last_result     = result


def _load_attempt_into_session(attempt: dict) -> None:
    """
    Reconstruct a session-compatible result dictionary from a history
    attempt record and store it as the current session.

    Args:
        attempt: A history entry dictionary as stored by AttemptHistoryManager.
    """
    model_dict = attempt.get("final_model") or {}
    validation = attempt.get("validation_results") or {}
    evidence   = attempt.get("extracted_evidence") or {}
    scenario   = attempt.get("scenario_text", "")
    attempt_id = attempt.get("attempt_id", "imported")
    timestamp  = attempt.get("timestamp", "")

    result = {
        "attempt_id":  attempt_id,
        "timestamp":   timestamp,
        "clean_text":  scenario,
        "evidence":    evidence,
        "model":       None,
        "model_dict":  model_dict,
        "validation":  validation,
        "parsed_ai":   {},
    }

    try:
        temp_model = _dict_to_diamond_model(model_dict)
        if temp_model is not None:
            result["model"]      = temp_model
            result["validation"] = Validator().validate(temp_model)
    except Exception:
        pass

    _store_result(result)


def _dict_to_diamond_model(model_dict: dict):
    """
    Attempt to reconstruct a DiamondModel from a model_dict.
    Returns None on failure.

    Args:
        model_dict: A serialized DiamondModel dictionary.

    Returns:
        A DiamondModel instance or None.
    """
    try:
        from models import DiamondModel

        model = DiamondModel()

        def _apply(field_obj, d: dict) -> None:
            if not isinstance(d, dict):
                return
            v = d.get("value")
            if isinstance(v, str) and v.strip():
                field_obj.value      = v.strip()
                field_obj.source     = d.get("source", "user")
                field_obj.confidence = float(d.get("confidence", 0.0))
                field_obj.evidence   = d.get("evidence") or []

        def _safe_list(val) -> list[str]:
            if isinstance(val, list):
                return [str(i) for i in val if str(i).strip()]
            return []

        adv = model_dict.get("adversary") or {}
        _apply(model.adversary.name,        adv.get("name", {}))
        _apply(model.adversary.motivation,  adv.get("motivation", {}))
        _apply(model.adversary.attribution, adv.get("attribution", {}))
        _apply(model.adversary.intent,      adv.get("intent", {}))
        model.adversary.aliases = _safe_list(adv.get("aliases"))

        vic = model_dict.get("victim") or {}
        _apply(model.victim.organization, vic.get("organization", {}))
        _apply(model.victim.sector,       vic.get("sector", {}))
        _apply(model.victim.geography,    vic.get("geography", {}))
        _apply(model.victim.role,         vic.get("role", {}))
        _apply(model.victim.impact,       vic.get("impact", {}))

        cap = model_dict.get("capability") or {}
        _apply(model.capability.description, cap.get("description", {}))
        model.capability.tools           = _safe_list(cap.get("tools"))
        model.capability.malware         = _safe_list(cap.get("malware"))
        model.capability.ttps            = _safe_list(cap.get("ttps"))
        model.capability.vulnerabilities = _safe_list(cap.get("vulnerabilities"))

        inf = model_dict.get("infrastructure") or {}
        _apply(model.infrastructure.description, inf.get("description", {}))
        model.infrastructure.domains         = _safe_list(inf.get("domains"))
        model.infrastructure.ips             = _safe_list(inf.get("ips"))
        model.infrastructure.urls            = _safe_list(inf.get("urls"))
        model.infrastructure.email_addresses = _safe_list(inf.get("email_addresses"))
        model.infrastructure.hosts           = _safe_list(inf.get("hosts"))

        meta = model_dict.get("meta") or {}
        model.meta.summary             = meta.get("summary", "")
        model.meta.timestamps          = _safe_list(meta.get("timestamps"))
        model.meta.analyst_notes       = _safe_list(meta.get("analyst_notes"))
        model.meta.validation_warnings = _safe_list(meta.get("validation_warnings"))

        return model
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tab renderers
# ---------------------------------------------------------------------------

def _field_row(label: str, field: dict) -> None:
    """Render a single FieldValue dict as a labelled detail row."""
    value      = field.get("value") or "—"
    confidence = field.get("confidence", 0.0)
    source     = field.get("source", "unknown")
    evidence   = field.get("evidence", [])
    notes      = field.get("notes")

    st.markdown(f"**{label}**")
    col_val, col_conf, col_src = st.columns([3, 1, 1])
    with col_val:
        st.write(value)
    with col_conf:
        st.caption(f"Confidence: {confidence:.0%}")
    with col_src:
        if source == "explicit":
            badge = "🔵 explicit"
        elif source == "inferred":
            badge = "🟡 inferred"
        else:
            badge = f"⚪ {source}"
        st.caption(badge)

    if evidence:
        with st.expander("Evidence", expanded=False):
            for e in evidence:
                st.markdown(f"- _{e}_")
    if notes:
        st.info(f"📝 Note: {notes}")
    st.divider()


def _vertex_label(model_dict: dict, vertex: str) -> str:
    """Return a short display label for a vertex button."""
    labels = {
        "adversary":      model_dict.get("adversary", {}).get("name", {}).get("value"),
        "victim":         model_dict.get("victim", {}).get("organization", {}).get("value"),
        "capability":     model_dict.get("capability", {}).get("description", {}).get("value"),
        "infrastructure": model_dict.get("infrastructure", {}).get("description", {}).get("value"),
    }
    raw = labels.get(vertex) or ""
    if len(raw) > 48:
        raw = raw[:45] + "…"
    return raw or "—"


def _render_vertex_detail(vertex: str, model_dict: dict) -> None:
    """Render the detail panel for the selected Diamond Model vertex."""
    data  = model_dict.get(vertex, {})
    icons = {
        "adversary":      "🎭",
        "victim":         "🏢",
        "capability":     "⚙️",
        "infrastructure": "🌐",
    }
    st.markdown(f"### {icons.get(vertex, '')} {vertex.capitalize()} — Detail")

    if vertex == "adversary":
        _field_row("Name",        data.get("name", {}))
        _field_row("Motivation",  data.get("motivation", {}))
        _field_row("Attribution", data.get("attribution", {}))
        _field_row("Intent",      data.get("intent", {}))
        aliases = data.get("aliases", [])
        if aliases:
            st.markdown(f"**Aliases:** {', '.join(aliases)}")

    elif vertex == "victim":
        _field_row("Organization", data.get("organization", {}))
        _field_row("Sector",       data.get("sector", {}))
        _field_row("Geography",    data.get("geography", {}))
        _field_row("Role",         data.get("role", {}))
        _field_row("Impact",       data.get("impact", {}))

    elif vertex == "capability":
        _field_row("Description", data.get("description", {}))
        for list_field, label in [
            ("tools",           "🔧 Tools"),
            ("malware",         "🦠 Malware"),
            ("ttps",            "📋 TTPs"),
            ("vulnerabilities", "🔓 Vulnerabilities"),
        ]:
            items = data.get(list_field, [])
            if items:
                st.markdown(f"**{label}**")
                for item in items:
                    st.markdown(f"- {item}")
                st.divider()

    elif vertex == "infrastructure":
        _field_row("Description", data.get("description", {}))
        for list_field, label in [
            ("domains",         "🌍 Domains"),
            ("ips",             "📡 IP Addresses"),
            ("urls",            "🔗 URLs"),
            ("email_addresses", "📧 Email Addresses"),
            ("hosts",           "💻 Hosts"),
        ]:
            items = data.get(list_field, [])
            if items:
                st.markdown(f"**{label}**")
                for item in items:
                    st.markdown(f"- `{item}`")
                st.divider()


def _render_diamond_tab(model_dict: dict) -> None:
    """Render the visual Diamond Model layout with selectable vertices."""
    if "selected_vertex" not in st.session_state:
        st.session_state.selected_vertex = None

    st.markdown("#### Select a vertex to explore")
    st.markdown("")

    _, top_col, _ = st.columns([2, 2, 2])
    with top_col:
        adv_label = _vertex_label(model_dict, "adversary")
        if st.button(
            f"🎭 Adversary\n\n{adv_label}",
            key="btn_adversary",
            use_container_width=True,
        ):
            st.session_state.selected_vertex = "adversary"

    st.markdown("")

    left_col, spacer, right_col = st.columns([2, 1, 2])
    with left_col:
        inf_label = _vertex_label(model_dict, "infrastructure")
        if st.button(
            f"🌐 Infrastructure\n\n{inf_label}",
            key="btn_infrastructure",
            use_container_width=True,
        ):
            st.session_state.selected_vertex = "infrastructure"
    with spacer:
        st.markdown(
            "<div style='text-align:center; font-size:2rem;"
            " padding-top:0.6rem; opacity:0.3;'>◆</div>",
            unsafe_allow_html=True,
        )
    with right_col:
        cap_label = _vertex_label(model_dict, "capability")
        if st.button(
            f"⚙️ Capability\n\n{cap_label}",
            key="btn_capability",
            use_container_width=True,
        ):
            st.session_state.selected_vertex = "capability"

    st.markdown("")

    _, bot_col, _ = st.columns([2, 2, 2])
    with bot_col:
        vic_label = _vertex_label(model_dict, "victim")
        if st.button(
            f"🏢 Victim\n\n{vic_label}",
            key="btn_victim",
            use_container_width=True,
        ):
            st.session_state.selected_vertex = "victim"

    st.markdown("---")

    selected = st.session_state.selected_vertex
    if selected:
        _render_vertex_detail(selected, model_dict)
    else:
        st.info("Click a vertex above to explore its details.")

    with st.expander("🛠 Raw JSON (debug)", expanded=False):
        st.json(model_dict)


def _render_stix_tab() -> None:
    """Render the STIX editor tab."""
    result = st.session_state.get("last_result")
    if not result:
        st.info("Run an analysis first to generate a STIX bundle.")
        return

    model = result.get("model")
    if model is None:
        st.warning(
            "No live DiamondModel in session — STIX editing requires a model object. "
            "Please re-run the analysis or import a STIX file."
        )
        return

    if "stix_bundle_text" not in st.session_state:
        try:
            bundle = StixMapper().to_bundle(model)
            st.session_state.stix_bundle_text = json.dumps(bundle, indent=2)
        except Exception as e:
            st.error(f"Failed to generate STIX bundle: {e}")
            return

    st.markdown("### 📦 STIX Bundle Editor")
    st.caption(
        "The bundle below was generated from the current Diamond Model. "
        "You may edit it directly, then click **Apply STIX Changes** to update the model."
    )

    edited_text = st.text_area(
        label="STIX Bundle JSON",
        value=st.session_state.stix_bundle_text,
        height=500,
        key="stix_editor_area",
    )

    col_apply, col_reset = st.columns([1, 1])

    with col_apply:
        if st.button("✅ Apply STIX Changes", use_container_width=True):
            try:
                parsed_bundle = json.loads(edited_text)
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON: {e}")
                return
            try:
                updated_model = StixImporter().from_bundle(parsed_bundle)
            except ValueError as e:
                st.error(f"STIX import failed: {e}")
                return
            except Exception as e:
                st.error(f"Unexpected error during import: {e}")
                return

            updated_model_dict = updated_model.to_dict()
            st.session_state.last_result["model"]      = updated_model
            st.session_state.last_result["model_dict"] = updated_model_dict

            try:
                validation = Validator().validate(updated_model)
                st.session_state.last_result["validation"] = validation
            except Exception:
                pass

            try:
                refreshed = StixMapper().to_bundle(updated_model)
                st.session_state.stix_bundle_text = json.dumps(refreshed, indent=2)
            except Exception:
                st.session_state.stix_bundle_text = edited_text

            st.session_state.selected_vertex = None
            st.success("STIX changes applied. Diamond Model updated.")
            st.rerun()

    with col_reset:
        if st.button("🔄 Reset STIX Editor", use_container_width=True):
            try:
                bundle = StixMapper().to_bundle(model)
                st.session_state.stix_bundle_text = json.dumps(bundle, indent=2)
                st.success("STIX editor reset to current model.")
                st.rerun()
            except Exception as e:
                st.error(f"Failed to reset STIX editor: {e}")


def _render_export_tab() -> None:
    """Render the Export tab with download buttons for PDF, JSON, and STIX."""
    st.markdown("### 📤 Export Analysis")

    result = st.session_state.get("last_result")
    if not result:
        st.info("Run an analysis first to enable exports.")
        return

    model         = result.get("model")
    evidence      = result.get("evidence", {})
    validation    = result.get("validation", {})
    scenario_text = result.get("clean_text", "")
    attempt_id    = result.get("attempt_id", "unknown")
    timestamp     = result.get("timestamp", "")

    if model is None:
        st.warning(
            "Export requires a live DiamondModel object. "
            "Please re-run the analysis or load a history entry to restore the model."
        )
        return

    st.markdown(
        "Download the current analysis in your preferred format. "
        "All exports reflect the latest model state, including any STIX edits."
    )
    st.markdown("")

    try:
        exporter = ExportManager()
    except Exception as e:
        st.error(f"Failed to initialize export manager: {e}")
        return

    col_pdf, col_json, col_stix = st.columns(3)

    with col_pdf:
        st.markdown("#### 📄 PDF Report")
        st.caption(
            "A human-readable report covering the full Diamond Model, "
            "extracted evidence, and validation results."
        )
        try:
            pdf_bytes = exporter.export_pdf(
                model=model,
                evidence=evidence,
                validation=validation,
                scenario_text=scenario_text,
                attempt_id=attempt_id,
                timestamp=timestamp,
            )
            st.download_button(
                label="⬇ Download PDF Report",
                data=pdf_bytes,
                file_name=f"diamond_report_{attempt_id}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"PDF generation failed: {e}")

    with col_json:
        st.markdown("#### 🗂 JSON Export")
        st.caption(
            "A structured JSON file containing the full model, evidence, "
            "scenario text, and validation results."
        )
        try:
            json_bytes = exporter.export_json(
                model=model,
                evidence=evidence,
                validation=validation,
                scenario_text=scenario_text,
                attempt_id=attempt_id,
                timestamp=timestamp,
            )
            st.download_button(
                label="⬇ Download JSON",
                data=json_bytes,
                file_name=f"diamond_model_{attempt_id}.json",
                mime="application/json",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"JSON export failed: {e}")

    with col_stix:
        st.markdown("#### 🔗 STIX Bundle")
        st.caption(
            "A STIX 2.1-like bundle containing threat-actor, identity, "
            "attack-pattern, infrastructure, and relationship objects."
        )
        try:
            stix_bytes = exporter.export_stix(model=model)
            st.download_button(
                label="⬇ Download STIX",
                data=stix_bytes,
                file_name=f"diamond_bundle_{attempt_id}.stix.json",
                mime="application/json",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"STIX export failed: {e}")


def _render_import_tab() -> None:
    """Render the Import tab for loading previous JSON or STIX analysis files."""
    st.markdown("### 📥 Import Analysis")
    st.caption(
        "Load a previous analysis from a native JSON export or a STIX bundle. "
        "The imported data will replace the current session."
    )

    uploaded = st.file_uploader(
        "Choose a file to import",
        type=["json", "stix"],
        key="import_file_uploader",
    )

    if uploaded is None:
        st.info("Upload a .json, .stix, or .stix.json file to continue.")
        return

    if st.button("📂 Load Imported File", use_container_width=False):
        try:
            handler   = FileHandler()
            file_text = handler.read_uploaded_file(uploaded)
        except ValueError as e:
            st.error(f"File read error: {e}")
            return
        except Exception as e:
            st.error(f"Unexpected error reading file: {e}")
            return

        try:
            importer = AnalysisImporter()
            result   = importer.import_analysis(file_text)
        except ValueError as e:
            st.error(f"Import failed: {e}")
            return
        except Exception as e:
            st.error(f"Unexpected import error: {e}")
            return

        model = result.get("model")
        if model is not None and not result.get("validation"):
            try:
                result["validation"] = Validator().validate(model)
            except Exception:
                result["validation"] = {}

        if not result.get("clean_text"):
            result["clean_text"] = result.get("scenario_text", "")

        _store_result(result)
        st.success(
            f"Successfully imported '{uploaded.name}'. "
            "The Diamond Model tab has been updated."
        )
        st.rerun()


def _render_history_tab() -> None:
    """
    Render a clean, compact history tab showing a summary card for each
    recent attempt with STIX download and session-load actions.
    """
    st.markdown("### 🗃 Analysis History")

    try:
        attempts = AttemptHistoryManager().get_recent_attempts()
    except Exception as e:
        st.error(f"Could not load history: {e}")
        return

    if not attempts:
        st.info("No previous attempts found. Run an analysis to populate history.")
        return

    for i, attempt in enumerate(attempts):
        attempt_id = attempt.get("attempt_id", f"attempt-{i + 1}")
        timestamp  = attempt.get("timestamp", "Unknown time")
        model_dict = attempt.get("final_model") or {}

        adversary_name = (
            model_dict.get("adversary", {})
            .get("name", {})
            .get("value") or "Unknown adversary"
        )
        victim_name = (
            model_dict.get("victim", {})
            .get("organization", {})
            .get("value") or "Unknown victim"
        )
        summary = model_dict.get("meta", {}).get("summary") or ""
        preview = summary[:120] + "…" if len(summary) > 120 else summary

        label = (
            f"🕒 {timestamp[:19]}  ·  "
            f"🎭 {adversary_name}  →  🏢 {victim_name}"
        )

        with st.expander(label, expanded=(i == 0)):
            if preview:
                st.caption(f"📝 {preview}")
            else:
                st.caption("No summary available.")

            st.markdown("")

            col_stix, col_load = st.columns([1, 1])

            with col_stix:
                stix_bytes = None
                try:
                    model_obj = _dict_to_diamond_model(model_dict)
                    if model_obj is not None:
                        bundle     = StixMapper().to_bundle(model_obj)
                        stix_bytes = json.dumps(bundle, indent=2).encode("utf-8")
                except Exception:
                    pass

                if stix_bytes:
                    st.download_button(
                        label="⬇ Download STIX",
                        data=stix_bytes,
                        file_name=f"diamond_bundle_{attempt_id}.stix.json",
                        mime="application/json",
                        key=f"stix_dl_{i}",
                        use_container_width=True,
                    )
                else:
                    st.button(
                        "⬇ Download STIX",
                        disabled=True,
                        key=f"stix_dl_disabled_{i}",
                        use_container_width=True,
                        help="Could not generate STIX for this entry.",
                    )

            with col_load:
                if st.button(
                    "📂 Load Into Session",
                    key=f"load_attempt_{i}",
                    use_container_width=True,
                ):
                    _load_attempt_into_session(attempt)
                    st.success(
                        f"Loaded attempt from {timestamp[:19]} into session."
                    )
                    st.rerun()

            with st.expander("🛠 Raw JSON (debug)", expanded=False):
                st.json(attempt)


# ---------------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------------

def run_app() -> None:
    """
    Entry point for the Streamlit application. Renders the full UI including
    scenario input, file upload, analysis execution, tabbed results, and history.
    """
    st.title("AI-Assisted Diamond Model Analyzer")
    st.write(
        "Analyze cyber incident scenarios using the Diamond Model of Intrusion Analysis, "
        "powered by Gemini AI. Enter a scenario manually or upload a plain text file."
    )

    # --- API Key ---
    api_key = st.text_input(
        "Google Gemini API Key",
        type="password",
        placeholder="Enter your API key...",
    )

    # --- File Upload (scenario) ---
    uploaded_file = st.file_uploader(
        "Upload a scenario file (.txt)",
        type=["txt"],
    )

    file_text = ""
    if uploaded_file is not None:
        try:
            handler   = FileHandler()
            file_text = handler.read_uploaded_file(uploaded_file)
            st.success(f"File '{uploaded_file.name}' loaded successfully.")
        except ValueError as e:
            st.error(f"File error: {e}")
        except Exception as e:
            st.error(f"Unexpected error reading file: {e}")

    # --- Scenario Text Area ---
    scenario_text = st.text_area(
        "Scenario Text",
        value=file_text,
        height=250,
        placeholder="Paste or type your incident scenario here...",
    )

    # --- Analyze Button ---
    if st.button("Analyze Scenario", type="primary"):
        if not api_key.strip():
            st.error("Please enter your Google Gemini API key before analyzing.")
            return
        if not scenario_text.strip():
            st.error(
                "Please provide a scenario — either by typing or uploading a file."
            )
            return

        with st.spinner("Running analysis..."):
            try:
                session = AnalysisSession(api_key=api_key.strip())
                result  = session.run(scenario_text)
            except Exception as e:
                st.error(f"Analysis failed: {e}")
                return

        st.success("Analysis complete.")
        _store_result(result)

        try:
            AttemptHistoryManager().save_attempt({
                "attempt_id":         result["attempt_id"],
                "timestamp":          result["timestamp"],
                "scenario_text":      result["clean_text"],
                "extracted_evidence": result["evidence"],
                "ai_raw_output":      result.get("parsed_ai", {}),
                "final_model":        result["model_dict"],
                "validation_results": result["validation"],
                "human_edits":        {},
            })
        except Exception as e:
            st.warning(f"Could not save attempt history: {e}")

    # --- Render results or fallback tabs ---
    if "last_result" not in st.session_state:
        tab_import, tab_history = st.tabs(["Import", "History"])
        with tab_import:
            _render_import_tab()
        with tab_history:
            _render_history_tab()
        return

    result = st.session_state.last_result

    (
        tab_diamond,
        tab_evidence,
        tab_validation,
        tab_stix,
        tab_export,
        tab_import,
        tab_history,
    ) = st.tabs([
        "Diamond Model",
        "Evidence",
        "Validation",
        "STIX",
        "Export",
        "Import",
        "History",
    ])

    with tab_diamond:
        _render_diamond_tab(result["model_dict"])

    with tab_evidence:
        st.subheader("Extracted Evidence")
        st.json(result["evidence"])

    with tab_validation:
        st.subheader("Validation Report")
        validation = result["validation"]
        score      = validation.get("completeness_score", 0)
        st.metric("Completeness Score", f"{score:.0%}")
        warnings = validation.get("warnings", [])
        if warnings:
            st.warning("Validation warnings detected:")
            for w in warnings:
                st.markdown(f"- {w}")
        else:
            st.success("All four vertices are populated — no warnings.")
        with st.expander("Raw validation JSON", expanded=False):
            st.json(validation)

    with tab_stix:
        _render_stix_tab()

    with tab_export:
        _render_export_tab()

    with tab_import:
        _render_import_tab()

    with tab_history:
        _render_history_tab()