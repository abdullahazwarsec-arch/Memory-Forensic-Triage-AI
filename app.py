# =============================================================================
# MEMORY FORENSIC TRIAGE SYSTEM — app.py
# Explainable AI Dashboard with SHAP, LIME, Audit Logging, PDF Reports
# =============================================================================

# ── SECTION 1: IMPORTS ───────────────────────────────────────────────────────
import os
import re
import json
import uuid
import logging
import hashlib
import hmac
import time
import shutil
from datetime import datetime

import numpy as np
import pandas as pd
import shap
from lime.lime_tabular import LimeTabularExplainer

import streamlit as st


import altair as alt

from hazmem import memdump_extractor
from hazmem import ui_theme as ui
from hazmem import evidence_integrity as ei
from hazmem import input_validation as iv
from hazmem import audit_log
from hazmem import auth
from hazmem import admin_pages
from hazmem import help_page
from hazmem import assistant
from hazmem import hash_checker
from hazmem import timing
from hazmem import report_pdf
from hazmem.knowledge import (get_feature_info, RESPONSE_ACTIONS, SIMPLE_ACTIONS, CLASSIFICATION, risk_tier,
                              plain_name, recipient_label, origin_label)
from hazmem.report_pdf import generate_pdf_report


# ── SECTION 2: PATHS & FOLDER SETUP ──────────────────────────────────────────
# os.path.abspath makes these paths work from ANY terminal location
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATA_DIR    = os.path.join(BASE_DIR, "data")
DATA_PATH   = os.path.join(DATA_DIR, "Obfuscated-MalMem2022.csv")
MODEL_DIR   = os.path.join(BASE_DIR, "models")
MODEL_PATH  = (
    os.path.join(MODEL_DIR, "random_forest_model.pkl")
    if os.path.exists(os.path.join(MODEL_DIR, "random_forest_model.pkl"))
    else os.path.join(BASE_DIR, "random_forest_model.pkl")
)
ISO_PATH    = (
    os.path.join(MODEL_DIR, "isolation_forest.pkl")
    if os.path.exists(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    else os.path.join(BASE_DIR, "isolation_forest.pkl")
)
OUTPUT_DIR  = os.environ.get("HAZMEM_OUTPUT_DIR") or os.path.join(BASE_DIR, "outputs")
LOG_DIR     = os.path.join(BASE_DIR, "logs")
SAMPLES_DIR = os.path.join(DATA_DIR, "test_samples")
CASES_DIR   = os.path.join(OUTPUT_DIR, "cases")   # per-case evidence copies, CSVs, manifests
REPORTS_DIR = os.path.join(OUTPUT_DIR, "reports")  # sealed PDF reports (+ .sha256)

# Create folders if they don't exist yet
os.makedirs(OUTPUT_DIR,  exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOG_DIR,     exist_ok=True)
os.makedirs(SAMPLES_DIR, exist_ok=True)


# ── SECTION 3: AUDIT LOGGER SETUP ────────────────────────────────────────────
# Every prediction is written to a log file with timestamp
# This is chain-of-custody — a record of every analysis ever run.
# Each line is HMAC-chained to the previous one (see audit_log.py).
AUDIT_LOG_PATH = os.environ.get("HAZMEM_AUDIT_LOG") or os.path.join(LOG_DIR, "triage_audit.log")
audit_log.setup(AUDIT_LOG_PATH)
logger = logging.getLogger("triage")
admin_pages.AUDIT_LOG_PATH = AUDIT_LOG_PATH
hash_checker.OUTPUT_DIR = OUTPUT_DIR
report_pdf.REPORTS_DIR = REPORTS_DIR


# ── SECTION 5: CACHED RESOURCE LOADERS ───────────────────────────────────────
# @st.cache_resource means models are loaded ONCE and reused — keeps dashboard fast

@st.cache_resource
def load_rf_model():
    """Load the primary Random Forest classifier."""
    if not os.path.exists(MODEL_PATH):
        st.error(f"Model not found at: {MODEL_PATH}")
        st.stop()
    try:
        model, sha256 = ei.load_verified_model(MODEL_PATH)
    except ei.ModelIntegrityError as e:
        logger.error(f"MODEL INTEGRITY FAILURE | {e}")
        st.error(f"**Model integrity check failed — refusing to load the classifier.** {e}", icon=":material/gpp_bad:")
        st.stop()
    logger.info(f"MODEL VERIFIED | {os.path.basename(MODEL_PATH)} | SHA256={sha256}")
    return model


@st.cache_resource
def load_iso_model():
    """Load the Isolation Forest anomaly detector (optional — won't crash if missing or unverified)."""
    if not os.path.exists(ISO_PATH):
        return None   # Dashboard still works without it
    try:
        model, sha256 = ei.load_verified_model(ISO_PATH)
    except ei.ModelIntegrityError as e:
        logger.error(f"MODEL INTEGRITY FAILURE | {e} | zero-day layer disabled")
        st.warning(f"Isolation Forest not loaded (integrity check failed): {e}", icon=":material/gpp_maybe:")
        return None
    logger.info(f"MODEL VERIFIED | {os.path.basename(ISO_PATH)} | SHA256={sha256}")
    return model


@st.cache_data(ttl=30, show_spinner=False)
def audit_log_status() -> dict:
    """Re-verify the audit log's HMAC chain (cached briefly; the sidebar renders on every rerun)."""
    result = audit_log.verify_log(AUDIT_LOG_PATH)
    if not result["verified"]:
        logger.error(f"AUDIT LOG VERIFICATION FAILED | {'; '.join(result['problems'][:5])}")
    return result


@st.cache_data
def load_background_data(feature_cols_tuple):
    """
    Load training data for LIME background.
    LIME needs real samples to understand what 'normal' looks like.
    Without this, LIME explanations are meaningless (all zeros).
    feature_cols_tuple is a tuple (not list) because @st.cache_data
    requires hashable arguments.
    """
    feature_cols = list(feature_cols_tuple)

    if not os.path.exists(DATA_PATH):
        logger.warning("Background data CSV not found — LIME using zero fallback.")
        return np.zeros((10, len(feature_cols)))

    df = pd.read_csv(DATA_PATH)
    df["label"] = (df["Category"] != "Benign").astype(int)
    df = df.drop(columns=["Category"], errors="ignore")
    df = df.select_dtypes(include=[np.number]).fillna(0)

    # Reindex to exact feature columns expected by the model
    df = df.reindex(columns=feature_cols, fill_value=0)

    # Use up to 500 samples as LIME background (more = slower but better)
    return df.sample(min(500, len(df)), random_state=42).values


# ── SECTION 6: CORE TRIAGE FUNCTION ──────────────────────────────────────────

def run_triage(sample_df: pd.DataFrame, source_filename: str, row_index: int, integrity: dict = None) -> dict:
    """
    Score one memory profile row and return the full triage result dict.
    This is the heart of the system — every other section feeds into or reads from this.
    """

    rf_model  = load_rf_model()
    iso_model = load_iso_model()

    # Align columns to match exactly what the model was trained on
    expected_cols = rf_model.feature_names_in_.tolist()
    sample_df     = sample_df.reindex(columns=expected_cols, fill_value=0)
    sample_arr    = sample_df.values.reshape(1, -1)

    # ── Primary prediction ────────────────────────────────────
    # Pass sample_df directly with feature names to suppress scikit-learn warnings
    prob       = float(rf_model.predict_proba(sample_df)[0][1])   # probability of malware
    prediction = int(rf_model.predict(sample_df)[0])             # 0 = benign, 1 = malware

    # ── Risk tier assignment ──────────────────────────────────
    risk = risk_tier(prob)

    # ── Anomaly detection (zero-day layer) ────────────────────
    is_anomaly = False
    if iso_model is not None:
        try:
            iso_pred = iso_model.predict(sample_df)[0]
        except Exception:
            iso_pred = iso_model.predict(sample_arr)[0]
        is_anomaly = (iso_pred == -1)

    # ── Chain-of-custody metadata ─────────────────────────────
    # Unique analysis ID bound to the evidence content hash, analysed row and time
    integrity     = integrity or {}
    evidence_str  = (f"{integrity.get('case_id', '')}:{integrity.get('evidence_sha256', source_filename)}:"
                     f"row{row_index}:{integrity.get('vector_sha256', '')}:{datetime.now().isoformat()}")
    evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()[:16].upper()
    timestamp     = ei.local_timestamp()

    result = {
        "timestamp":     timestamp,
        "evidence_id":   evidence_hash,
        "source_file":   source_filename,
        "row_index":     row_index,
        "risk":          risk,
        "probability":   prob,
        "prediction":    prediction,
        "is_anomaly":    is_anomaly,
        "sample_df":     sample_df,
        "sample_arr":    sample_arr,
        "feature_cols":  expected_cols,
        "integrity":     integrity,
    }

    # ── Write to audit log ────────────────────────────────────
    logger.info(
        f"ANALYSIS_ID={evidence_hash} | CASE={integrity.get('case_id', '-')} | "
        f"EVIDENCE={integrity.get('evidence_item_id', '-')} | ANALYST={integrity.get('analyst', '-')} | FILE={source_filename} | "
        f"EVIDENCE_SHA256={integrity.get('evidence_sha256', '-')} | "
        f"VECTOR_SHA256={integrity.get('vector_sha256', '-')} | "
        f"ROW={row_index} | RISK={risk} | CONF={prob:.4f} | "
        f"PREDICTION={'MALWARE' if prediction else 'BENIGN'} | "
        f"ANOMALY={is_anomaly}"
    )

    return result


# ── SECTION 7: SHAP EXPLANATION ───────────────────────────────────────────────

def compute_shap(result: dict):
    """SHAP attribution for one sample (top 10 features), cached on the result."""
    if "_shap_df" in result:
        return result["_shap_df"]

    rf_model     = load_rf_model()
    sample_arr   = result["sample_arr"]
    feature_cols = result["feature_cols"]
    try:
        # TreeExplainer is the correct explainer for Random Forest
        explainer   = shap.TreeExplainer(rf_model)
        shap_values = explainer.shap_values(sample_arr)

        # Robust handling of binary classification output shapes across SHAP versions
        if isinstance(shap_values, list):
            vals = shap_values[1][0]
        elif len(shap_values.shape) == 3:
            vals = shap_values[0, :, 1]  # Sample 0, all features, Class 1 (Malware)
        else:
            vals = shap_values[0]

        infos = [get_feature_info(f) for f in feature_cols]
        shap_df = pd.DataFrame({
            "Plain English Indicator": [i["title"] for i in infos],
            "Technical Metric":        feature_cols,
            "SHAP Value":              vals,
            "What This Is":            [i["desc"] for i in infos],
            "Forensic Context":        [i["danger"] for i in infos],
        })
        shap_df["Abs"] = shap_df["SHAP Value"].abs()
        shap_df = shap_df.sort_values("Abs", ascending=False).head(10)
        shap_df["Impact on Verdict"] = shap_df["SHAP Value"].apply(
            lambda v: f"▲ +{v*100:.1f}% toward malware" if v > 0 else f"▼ {v*100:.1f}% toward benign"
        )
    except Exception as e:
        logger.error(f"SHAP error for evidence {result['evidence_id']}: {e}")
        result["_shap_error"] = str(e)
        shap_df = None
    result["_shap_df"] = shap_df
    return shap_df


def compute_lime(result: dict):
    """LIME local decision rules for one sample, cached on the result."""
    if "_lime_df" in result:
        return result["_lime_df"]

    rf_model     = load_rf_model()
    sample_arr   = result["sample_arr"]
    feature_cols = result["feature_cols"]
    try:
        background = load_background_data(tuple(feature_cols))
        explainer = LimeTabularExplainer(
            training_data         = background,
            feature_names         = feature_cols,
            class_names           = ["Benign", "Malware"],
            mode                  = "classification",
            discretize_continuous = True,
            random_state          = 42,
        )

        # Wrap predict_fn with DataFrame to preserve feature names and suppress scikit-learn warnings
        def lime_predict_fn(arr):
            return rf_model.predict_proba(pd.DataFrame(arr, columns=feature_cols))

        lime_exp = explainer.explain_instance(
            data_row     = sample_arr[0],
            predict_fn   = lime_predict_fn,
            num_features = 8,
            num_samples  = 1000,
        )

        lime_rows = []
        for cond, weight in lime_exp.as_list():
            info = get_feature_info(cond)
            lime_rows.append({
                "Plain English Indicator": info["title"],
                "Observed Condition":      cond,
                "LIME Weight":             weight,
                "Direction": (f"▲ +{weight*100:.1f}% toward malware" if weight > 0
                              else f"▼ {weight*100:.1f}% toward benign"),
                "What This Means":         info["desc"],
                "Forensic Context":        info["danger"],
            })
        lime_df = pd.DataFrame(lime_rows)
        lime_df["Abs"] = lime_df["LIME Weight"].abs()
        lime_df = lime_df.sort_values("Abs", ascending=False)
    except Exception as e:
        logger.error(f"LIME error for evidence {result['evidence_id']}: {e}")
        result["_lime_error"] = str(e)
        lime_df = None
    result["_lime_df"] = lime_df
    return lime_df


def polarity_chart(labels, values, metrics, x_title: str):
    """Interactive diverging bar chart: red = toward malware, blue = toward benign."""
    data = pd.DataFrame({
        "Indicator":    list(labels),
        "Contribution": [float(v) * 100 for v in values],
        "Metric":       list(metrics),
    })
    data["Direction"] = np.where(data["Contribution"] > 0, "Toward malware", "Toward benign")
    order = data["Indicator"].tolist()

    bars = alt.Chart(data).mark_bar(cornerRadiusEnd=4, size=20).encode(
        y=alt.Y("Indicator:N", sort=order, title=None,
                axis=alt.Axis(labelLimit=340, labelFontSize=14, labelColor=ui.CHART_TEXT, ticks=False, domain=False,
                              labelPadding=10)),
        x=alt.X("Contribution:Q", title=x_title,
                axis=alt.Axis(labelFontSize=13, titleFontSize=14, titleColor=ui.CHART_TEXT, labelColor=ui.CHART_MUTED,
                              gridColor=ui.CHART_GRID, domain=False, tickColor=ui.CHART_GRID, format="+.1f")),
        color=alt.Color("Direction:N",
                        scale=alt.Scale(domain=["Toward malware", "Toward benign"],
                                        range=[ui.TOWARD_MALWARE, ui.TOWARD_BENIGN]),
                        legend=alt.Legend(orient="top", title=None, labelFontSize=14, labelColor=ui.CHART_TEXT,
                                          symbolType="square", symbolSize=180)),
        tooltip=[
            alt.Tooltip("Indicator:N"),
            alt.Tooltip("Metric:N", title="Volatility metric"),
            alt.Tooltip("Contribution:Q", title="Contribution (%)", format="+.2f"),
            alt.Tooltip("Direction:N"),
        ],
    )
    zero = alt.Chart(pd.DataFrame({"x": [0]})).mark_rule(color=ui.CHART_MUTED, strokeWidth=1).encode(x="x:Q")
    chart = (alt.layer(bars, zero)
             .properties(height=max(220, 38 * len(data) + 50))
             .configure(background="transparent")
             .configure_view(strokeWidth=0))
    st.altair_chart(chart, width="stretch")


def driver_cards(rows: list):
    """rows: list of dicts with title, text, context, toward_malware, impact, metric."""
    cards = []
    for r in rows:
        tone = "critical" if r["toward_malware"] else "good"
        label = "▲ Raises malware risk" if r["toward_malware"] else "▼ Supports clean baseline"
        cards.append(f"""
        <div class="fx-card fx-driver">
          <div>{ui.pill(label, tone, dot=False)}</div>
          <div class="fx-driver-title">{ui.esc(r['title'])}</div>
          <div class="fx-driver-text">{ui.esc(r['text'])}</div>
          <div class="fx-driver-text" style="color: var(--muted); font-size: 0.9rem;"><b style="color: var(--text-2);">Why it matters:</b> {ui.esc(r['context'])}</div>
          <div class="fx-driver-meta"><b style="color: {ui.TONES[tone][0]};">{ui.esc(r['impact'])}</b><br/><code>{ui.esc(r['metric'])}</code></div>
        </div>
        """)
    ui.render_html(f'<div class="fx-grid">{"".join(cards)}</div>')


def render_shap_explanation(result: dict):
    shap_df = compute_shap(result)
    if shap_df is None:
        st.error(f"SHAP calculation failed: {result.get('_shap_error', 'unknown error')}")
        return
    st.caption("How much each memory artefact pushed this verdict toward malware (red) or benign (blue). Hover a bar for details.")
    polarity_chart(shap_df["Plain English Indicator"], shap_df["SHAP Value"], shap_df["Technical Metric"],
                   "Contribution to malware score (percentage points)")
    st.markdown("##### Top decision drivers")
    driver_cards([{
        "title": r["Plain English Indicator"], "text": r["What This Is"], "context": r["Forensic Context"],
        "toward_malware": r["SHAP Value"] > 0, "impact": r["Impact on Verdict"], "metric": r["Technical Metric"],
    } for _, r in shap_df.head(3).iterrows()])
    with st.expander("Full SHAP attribution table", icon=":material/table:"):
        st.dataframe(shap_df[["Plain English Indicator", "Technical Metric", "Impact on Verdict"]],
                     hide_index=True, width="stretch")


def render_lime_explanation(result: dict):
    lime_df = compute_lime(result)
    if lime_df is None:
        st.error(f"LIME calculation failed: {result.get('_lime_error', 'unknown error')}")
        return
    st.caption("Local rules learned around this exact memory profile — an independent check on the SHAP explanation.")
    polarity_chart(lime_df["Plain English Indicator"], lime_df["LIME Weight"], lime_df["Observed Condition"],
                   "Local influence (percentage points)")
    st.markdown("##### Strongest local rules")
    driver_cards([{
        "title": r["Plain English Indicator"], "text": r["What This Means"], "context": r["Forensic Context"],
        "toward_malware": r["LIME Weight"] > 0, "impact": r["Direction"], "metric": r["Observed Condition"],
    } for _, r in lime_df.head(3).iterrows()])
    with st.expander("Full LIME rule table", icon=":material/table:"):
        st.dataframe(lime_df[["Plain English Indicator", "Observed Condition", "Direction"]],
                     hide_index=True, width="stretch")


# ── SECTION 10: STREAMLIT UI & DAVID LANGARICA DESIGN SYSTEM ──────────────────

# ── Case sessions ─────────────────────────────────────────────────────────────
# Every analysis happens inside a case session opened by a named analyst.
# The case record (outputs/cases/<case>/case.json) keeps who worked on the case,
# when each session was opened/closed and which evidence items were acquired.

CASE_NUMBER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]{2,39}$")


def case_dir_name(case_number: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", case_number)


def case_record_path(case_number: str) -> str:
    return os.path.join(CASES_DIR, case_dir_name(case_number), "case.json")


def load_case_record(case_number: str) -> dict:
    path = case_record_path(case_number)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"case_number": case_number, "created_local": ei.local_timestamp(),
            "created_utc": ei._utc_now(), "sessions": [], "evidence": []}


def save_case_record(record: dict):
    path = case_record_path(record["case_number"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)


def expert() -> bool:
    """True when the user switched on "Show technical details" (hashes, ledger, charts, engines)."""
    return bool(st.session_state.get("expert_mode", False))


def active_case():
    return st.session_state.get("case_session")


def open_case_session(case_number: str, analyst: str, organisation: str, notes: str, recipient: dict) -> dict:
    record = load_case_record(case_number)
    session = {
        "case_number":   case_number,
        "analyst":       analyst,
        "organisation":  organisation,
        "notes":         notes,
        "recipient":     recipient,
        "session_id":    uuid.uuid4().hex[:8].upper(),
        "opened_local":  ei.local_timestamp(),
        "opened_utc":    ei._utc_now(),
        "prior_sessions": len(record["sessions"]),
    }
    record["sessions"].append({k: session[k] for k in
                               ("session_id", "analyst", "organisation", "notes", "recipient",
                                "opened_local", "opened_utc")}
                              | {"closed_local": None, "closed_utc": None})
    save_case_record(record)
    logger.info(f"CASE SESSION OPENED | CASE={case_number} | ANALYST={analyst} | ORG={organisation or '-'} | "
                f"SESSION={session['session_id']} | PREPARED_FOR={recipient_label(recipient)} | "
                f"PURPOSE={recipient['purpose']} | OPENED={session['opened_local']} ({session['opened_utc']})")
    # A new session starts with a clean evidence workspace
    for key in ("cases", "evidence", "current_triage", "batch_summary", "last_source_file", "triage_blocked"):
        st.session_state.pop(key, None)
    st.session_state["case_session"] = session
    return session


def close_case_session():
    session = active_case()
    if not session:
        return
    record = load_case_record(session["case_number"])
    for s in record["sessions"]:
        if s["session_id"] == session["session_id"]:
            s["closed_local"], s["closed_utc"] = ei.local_timestamp(), ei._utc_now()
    save_case_record(record)
    logger.info(f"CASE SESSION CLOSED | CASE={session['case_number']} | ANALYST={session['analyst']} | "
                f"SESSION={session['session_id']} | CLOSED={ei.local_timestamp()}")
    for key in ("case_session", "cases", "evidence", "current_triage", "batch_summary",
                "last_source_file", "triage_blocked"):
        st.session_state.pop(key, None)


def register_evidence(chain):
    """Add an acquired evidence item to the case record."""
    record = load_case_record(chain.case_id)
    ev = chain.baseline("evidence")
    record["evidence"].append({
        "evidence_id": chain.evidence_id, "name": chain.evidence_name, "kind": chain.evidence_kind,
        "sha256": ev.get("sha256"), "md5": ev.get("md5"), "size": ev.get("size"),
        "acquired_by": chain.analyst, "acquired_local": ei.local_timestamp(), "acquired_utc": ei._utc_now(),
        "session_id": (active_case() or {}).get("session_id"),
        "provenance": chain.provenance,
    })
    save_case_record(record)


def render_case_details(session: dict, org: str, previous: str):
    """Full case session details (technical view)."""
    ui.render_html(f"""
        <div class="fx-kpis">
          {ui.kpi("Case number", ui.esc(session['case_number']), mono=True, wide=True)}
          {ui.kpi("Analyst", ui.esc(session['analyst']), ui.esc(session['organisation']), small=True)}
          {ui.kpi("Prepared for", ui.esc((session.get('recipient') or {}).get('name', '—')),
                  ui.esc(' · '.join(v for v in ((session.get('recipient') or {}).get('organisation'),
                                                (session.get('recipient') or {}).get('purpose')) if v)),
                  small=True)}
          {ui.kpi("Session opened", ui.esc(session['opened_local']), ui.esc(session['opened_utc']), small=True)}
        </div>
        <div style="color: var(--muted); font-size: 0.9rem; margin-top: 0.5rem;">
          Session <code>{session['session_id']}</code>{org}{previous}{(' · ' + ui.esc(session['notes'])) if session['notes'] else ''}
        </div>
        """)


def render_case_session():
    """Mandatory case session gate. Returns the active session or None."""
    session = active_case()
    if session:
        org = f" · {ui.esc(session['organisation'])}" if session["organisation"] else ""
        previous = (f" · continues case ({session['prior_sessions']} earlier session"
                    f"{'s' if session['prior_sessions'] != 1 else ''})" if session["prior_sessions"] else "")
        col_info, col_close = st.columns([4.2, 1.2], vertical_alignment="center")
        with col_info:
            if not expert():
                recipient = session.get("recipient") or {}
                ui.kpi_row([
                    ui.kpi("Case number", ui.esc(session["case_number"]), mono=True),
                    ui.kpi("Prepared for", ui.esc(recipient.get("name", "—")), ui.esc(recipient.get("purpose", "")),
                           small=True),
                    ui.kpi("Started", ui.esc(session["opened_local"][:16]), small=True),
                ])
            else:
                render_case_details(session, org, previous)
        with col_close:
            if st.button("Close case", width="stretch", icon=":material/lock:"):
                confirm_close_case()
        return session


    user = st.session_state["auth_user"]
    analyst = f"{user['full_name']} ({user['username']})"
    with st.form("open_case_form", border=False):
        c1, c2 = st.columns(2)
        case_number = c1.text_input("Case number *", value=ei.suggest_case_number(),
                                    help="Your reference for this investigation (a number is suggested).")
        recipient_name = c2.text_input("Recipient *", placeholder="Who gets the findings, e.g. DCI Sarah Khan",
                                       help="The person or team the findings and evidence are prepared for.")
        with st.expander("More details (optional)", icon=":material/tune:"):
            d1, d2 = st.columns(2)
            recipient_org = d1.text_input("Recipient organisation", placeholder="e.g. Metro Police Cyber Unit")
            purpose       = d2.selectbox("Purpose", PURPOSES)
            reference     = d1.text_input("Reference no.", placeholder="e.g. REQ-2026-114")
            organisation  = d2.text_input("Your unit / organisation", placeholder="e.g. CSIRT, DFIR Lab")
            notes         = d1.text_input("Case notes", placeholder="e.g. Suspected ransomware on HR-PC-07")
            d2.text_input("Analyst (signed-in account)", value=analyst, disabled=True,
                          help="Case actions are attributed to the signed-in account.")
        st.caption(f"Signed in as **{analyst}** · the start time is recorded automatically.")
        submitted = st.form_submit_button("Start case", type="primary", icon=":material/rocket_launch:")

    if submitted:
        case_number = case_number.strip()
        errors = []
        if not CASE_NUMBER_RE.match(case_number):
            errors.append("Enter a valid **case number** (3-40 characters: letters, digits, - _ . /).")
        if len(recipient_name.strip()) < 3:
            errors.append("Enter the **recipient** the evidence is prepared for (at least 3 characters).")
        if errors:
            for e in errors:
                st.error(e, icon=":material/error:")
            return None
        open_case_session(case_number, analyst, organisation.strip(), notes.strip(), {
            "name": " ".join(recipient_name.split()), "organisation": recipient_org.strip(),
            "purpose": purpose, "reference": reference.strip()})
        st.toast(f"Case {case_number} opened by {analyst}", icon="📂")
        st.rerun()
    return None


@st.dialog("Close this case session?")
def confirm_close_case():
    session = active_case()
    st.write(f"Case **{session['case_number']}** will be closed and the closing time recorded. "
             "You can continue it later from the **Cases** page.")
    c1, c2 = st.columns(2)
    if c1.button("Keep working", width="stretch"):
        st.rerun()
    if c2.button("Close case", type="primary", width="stretch", icon=":material/lock:"):
        close_case_session()
        st.toast("Case session closed and logged", icon=":material/lock:")
        st.rerun()


def open_case(evidence_name: str, kind: str, hashes: dict, action: str, details: str = ""):
    """Register a new evidence item in the active case and record its acquisition hash."""
    session = active_case()
    chain = ei.CustodyChain(session["case_number"], evidence_name, kind, log=logger,
                            evidence_id=ei.new_evidence_id(hashes["sha256"]), analyst=session["analyst"])
    chain.record("Acquisition", action, evidence_name, hashes, role="evidence",
                 details=f"{details} | Case session {session['session_id']} opened {session['opened_local']}".strip(" |"))
    record_provenance(chain, st.session_state.get("pending_origin") or {}, session.get("recipient") or {})
    register_evidence(chain)
    return chain


def record_provenance(chain, origin: dict, recipient: dict):
    """Lock where the evidence came from and who it is for into the custody ledger (tamper-evident)."""
    chain.provenance = {"origin": dict(origin), "prepared_for": dict(recipient)}
    payload = json.dumps(chain.provenance, sort_keys=True).encode("utf-8")
    chain.record("Provenance", "Evidence origin and intended recipient recorded at acquisition",
                 chain.evidence_name, {"sha256": hashlib.sha256(payload).hexdigest()}, role="provenance",
                 details=(f"Origin: {origin_label(origin)} | Collected by {origin.get('collected_by', '-')} "
                          f"at {origin.get('collected_at', '-')} | Location: {origin.get('location') or '-'} | "
                          f"Tool: {origin.get('acquisition_tool', '-')} | Prepared for: {recipient_label(recipient)} "
                          f"| Purpose: {recipient.get('purpose', '-')} | Ref: {recipient.get('reference') or '-'}"))
    reported = origin.get("reported_hash", "")
    if reported:
        ev = chain.baseline("evidence")
        key = ei.detect_algorithm(reported)
        algo = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}[key]
        computed = ev.get(key, "")
        match = hmac.compare_digest(reported, computed)
        chain.record("Acquisition Verification",
                     f"{algo} reported by the acquisition tool compared with the hash computed on arrival",
                     chain.evidence_name, {k: ev.get(k) for k in ("sha256", "md5", "size")},
                     status=ei.STATUS_MATCH if match else ei.STATUS_MISMATCH,
                     details=f"Reported {algo}: {reported} | Computed {algo}: {computed}")
        (logger.info if match else logger.error)(
            f"ACQUISITION HASH {'MATCH' if match else 'MISMATCH'} | CASE={chain.case_id} | "
            f"EVIDENCE={chain.evidence_id} | {algo} reported={reported} computed={computed}")
    logger.info(f"PROVENANCE | CASE={chain.case_id} | EVIDENCE={chain.evidence_id} | "
                f"SOURCE={origin_label(origin)} | COLLECTED_BY={origin.get('collected_by', '-')} | "
                f"COLLECTED_AT={origin.get('collected_at', '-')} | TOOL={origin.get('acquisition_tool', '-')} | "
                f"PREPARED_FOR={recipient_label(recipient)} | PURPOSE={recipient.get('purpose', '-')}")


def case_path(chain, *parts) -> str:
    path = os.path.join(CASES_DIR, case_dir_name(chain.case_id), chain.evidence_id, *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def save_manifest(chain):
    return chain.save_manifest(case_path(chain, "custody_manifest.json"))


def preserve_upload(chain, uploaded_file) -> str:
    """Write the uploaded evidence to a write-protected working copy and verify it."""
    path = case_path(chain, "evidence", os.path.basename(uploaded_file.name))
    uploaded_file.seek(0)
    with open(path, "wb") as f:
        shutil.copyfileobj(uploaded_file, f, length=16 * 1024 * 1024)
    uploaded_file.seek(0)
    ei.make_read_only(path)
    chain.verify_file("Working Copy", "Write-protected working copy preserved in case folder",
                      path, role="evidence")
    return path


def activate_evidence(ctx: dict) -> dict:
    """Remember an evidence context (per key) and make it the active one."""
    st.session_state.setdefault("cases", {})[ctx["key"]] = ctx
    st.session_state["evidence"] = ctx
    save_manifest(ctx["chain"])
    return ctx


def ingest_csv_evidence(key: str, name: str, kind: str, hashes: dict,
                        source_path: str = None, uploaded_file=None) -> dict:
    """Open (or reuse) a case for CSV evidence: acquisition → working copy → load check."""
    existing = st.session_state.get("cases", {}).get(key)
    if existing:
        st.session_state["evidence"] = existing
        return existing

    if uploaded_file is not None:
        chain = open_case(name, kind, hashes, "Evidence CSV received via dashboard upload",
                          details="Hash computed over the exact bytes received from the analyst")
        csv_path = preserve_upload(chain, uploaded_file)
    else:
        chain = open_case(name, kind, hashes, "Evidence CSV loaded from local repository",
                          details=f"Source path: {source_path}")
        csv_path = source_path
    chain.verify_file("Data Load", "Evidence CSV re-hashed as it is parsed for analysis",
                      csv_path, role="evidence")
    return activate_evidence({"key": key, "name": name, "kind": kind, "chain": chain,
                              "evidence_path": csv_path, "csv_path": csv_path,
                              "csv_role": "evidence"})


def timing_stats() -> timing.Timings:
    """Per-machine timing history (outputs/timing_stats.json) used for time estimates."""
    return timing.Timings(os.path.join(OUTPUT_DIR, "timing_stats.json"))


def render_hash_verification(report: dict, ctx: dict):
    """Dump hash before vs after conversion, and the derived CSV hash - with the files to re-verify later."""
    integ = report.get("integrity", {})
    pre, post, csv = integ.get("pre_extraction", {}), integ.get("post_extraction", {}), integ.get("derived_csv", {})
    same = bool(pre) and pre.get("sha256") == post.get("sha256")
    ui.render_html(
        '<div class="fx-card" style="margin:0.6rem 0 0.8rem;">'
        f'<div style="display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;">'
        f'{ui.pill("Dump unchanged by conversion" if same else "DUMP CHANGED DURING CONVERSION", "good" if same else "critical")}'
        f'{ui.pill("CSV fingerprint recorded", "accent")}</div>'
        + ui.hash_line("1 · Memory image SHA-256 — before conversion", pre.get("sha256", "—"))
        + ui.hash_line("2 · Memory image SHA-256 — after conversion (must equal 1)", post.get("sha256", "—"))
        + ui.hash_line(f"3 · Derived CSV SHA-256 — {csv.get('file', '')}", csv.get("sha256", "—"))
        + '</div>')
    st.caption("Keep the CSV together with its .sha256 file and the extraction report: the **Hash checker** page can "
               "later prove the CSV is exactly the one produced from this memory image.")
    folder = os.path.dirname(ctx["csv_path"])
    c1, c2, c3 = st.columns(3)
    for col, (label, path, mime) in zip((c1, c2, c3), [
            ("Feature CSV", ctx["csv_path"], "text/csv"),
            ("CSV .sha256", f"{ctx['csv_path']}.sha256", "text/plain"),
            ("Extraction report", os.path.join(folder, "extraction_report.json"), "application/json")]):
        if os.path.isfile(path):
            with open(path, "rb") as f:
                col.download_button(label, f.read(), file_name=os.path.basename(path), mime=mime,
                                    icon=":material/download:", width="stretch", key=f"dl_{label}_{ctx['key']}")


def reject_intake(key: str, name: str, error: Exception):
    """Show and audit-log an intake rejection (logged once per file, despite Streamlit reruns)."""
    logged = st.session_state.setdefault("rejected_intake", set())
    if key not in logged:
        logged.add(key)
        logger.warning(f"INTAKE REJECTED | CASE={(active_case() or {}).get('case_number', '-')} | "
                       f"FILE={name} | REASON={error}")
    st.error(f"**{name}** was rejected: {error}", icon=":material/block:")


def render_memory_dump_ingestion():
    """
    Memory dump ingestion: accepts an uploaded dump or a local path, hashes it,
    runs the Volatility 3 feature extractor with before/after integrity checks
    and returns the evidence context. Returns None until features are available.
    """
    col_up, col_path = st.columns(2, gap="large")
    with col_up:
        uploaded_dump = st.file_uploader(
            label = "Upload memory image",
            type  = memdump_extractor.DUMP_EXTENSIONS,
            help  = "Raw Windows memory image (DumpIt, WinPmem, FTK Imager, VMware .vmem).",
        )
    with col_path:
        local_path = st.text_input(
            "…or path on this machine (best for large dumps)",
            placeholder = r"C:\Evidence\host01_memory.raw",
        ).strip().strip('"')

    if uploaded_dump is not None:
        dump_key = f"dump-upload:{uploaded_dump.name}:{uploaded_dump.size}"
        dump_name = uploaded_dump.name
        dump_size = uploaded_dump.size
        try:
            dump_format = iv.check_memory_image(uploaded_dump, uploaded_dump.size, dump_name,
                                                memdump_extractor.DUMP_EXTENSIONS)
            iv.check_disk_space(CASES_DIR, uploaded_dump.size)
        except iv.UploadRejected as e:
            reject_intake(dump_key, dump_name, e)
            return None
    elif local_path:
        if not os.path.isfile(local_path):
            st.error(f"File not found: `{local_path}`")
            return None
        dump_key = f"dump-path:{os.path.abspath(local_path)}:{os.path.getsize(local_path)}:{os.path.getmtime(local_path)}"
        dump_name = os.path.basename(local_path)
        dump_size = os.path.getsize(local_path)
        try:
            dump_format = iv.check_memory_image(local_path, dump_size, dump_name,
                                                memdump_extractor.DUMP_EXTENSIONS)
        except iv.UploadRejected as e:
            reject_intake(dump_key, dump_name, e)
            return None
    else:
        ui.empty_state("memory", "Add a Windows memory image",
                       "It is hashed (SHA-256 + MD5), Volatility 3 extracts 55 memory features, "
                       "and every step is re-verified up to the final report.")
        return None

    ctx = st.session_state.get("cases", {}).get(dump_key)
    if ctx is None:
        tm = timing_stats()
        acquire_s = tm.hash_seconds(dump_size) * (2 if uploaded_dump is not None else 1)   # hash (+ copy)
        extract_s = tm.extraction_seconds(dump_size)
        estimate = acquire_s + extract_s
        st.info(f"**{dump_name}** passed intake checks ({dump_format}, {ei.format_size(dump_size)}). "
                f"**Estimated time: {timing.approx(estimate)}** — fingerprinting "
                f"{timing.approx(acquire_s)}, 9 Volatility plugins {timing.approx(extract_s)}. "
                "The first analysis of a new Windows version takes longer (symbol download).",
                icon=":material/timer:")
        if not st.button("Extract features", type="primary", icon=":material/memory:"):
            return None

        eta = timing.ProgressETA(estimate, "Computing acquisition hash of memory image (SHA-256 + SHA-1 + MD5)...")
        acquire_w = acquire_s / max(estimate, 1)
        hash_progress = lambda done, total: eta.update(acquire_w * 0.5 * done / max(total, 1),
                                                       f"Fingerprinting memory image... {done * 100 // max(total, 1)}%")
        try:
            t_acquire = time.time()
            if uploaded_dump is not None:
                chain = open_case(dump_name, "memory-dump", ei.hash_stream(uploaded_dump, progress=hash_progress),
                                  "Memory image received via dashboard upload",
                                  details=f"Hash computed over the exact bytes received from the analyst | "
                                          f"Intake check: {dump_format}")
                eta.update(acquire_w * 0.5, "Writing write-protected working copy of the memory image...", force=True)
                dump_path = preserve_upload(chain, uploaded_dump)
            else:
                dump_path = os.path.abspath(local_path)
                chain = open_case(dump_name, "memory-dump", ei.hash_file(dump_path, progress=hash_progress),
                                  "Memory image referenced in place (read-only, not copied)",
                                  details=f"Source path: {dump_path} | Intake check: {dump_format}")

            tm.record_hash(dump_size, time.time() - t_acquire)
            logger.info(f"Memory dump extraction started: CASE={chain.case_id} | {dump_name}")
            t_extract = time.time()
            _, csv_path, report = memdump_extractor.extract_features(
                dump_path,
                out_dir     = os.path.dirname(case_path(chain, "extraction", "_")),
                progress_cb = lambda frac, msg: eta.update(acquire_w + (1 - acquire_w) * frac, msg),
            )
            tm.record_extraction(dump_size, time.time() - t_extract)
        except memdump_extractor.ExtractionError as e:
            eta.empty()
            logger.error(f"Memory dump extraction failed for {dump_name}: {e}")
            st.error(f"❌ {e}")
            return None
        eta.empty()

        integ = report["integrity"]
        chain.record("Pre-Extraction", "Image hash verified immediately before Volatility processing",
                     dump_name, integ["pre_extraction"], role="evidence")
        chain.record("Post-Extraction", "Image re-hashed after 9 Volatility plugins (read-only processing)",
                     dump_name, integ["post_extraction"], role="evidence")
        chain.record("Derived Data", "55-feature CSV generated from the verified memory image",
                     os.path.basename(csv_path), integ["derived_csv"], role="csv",
                     details=f"Derived from evidence SHA-256 {chain.baseline('evidence').get('sha256')}")
        chain.verify_file("Data Load", "Feature CSV re-hashed as it is parsed for analysis",
                          csv_path, role="csv")
        report["dump"] = dump_name if uploaded_dump is not None else report["dump"]
        logger.info(f"Memory dump extraction finished: CASE={chain.case_id} | CSV={csv_path}")

        activate_evidence({"key": dump_key, "name": dump_name, "kind": "memory-dump", "chain": chain,
                           "evidence_path": dump_path, "csv_path": csv_path, "csv_role": "csv",
                           "report": report})
        st.rerun()   # Redraw without the "ready / extract" prompt

    st.session_state["evidence"] = ctx
    report = ctx["report"]
    os_info = report.get("os_info", {})
    os_label = (os_info.get("NTBuildLab") or "Windows").rstrip(".")
    arch = "x64" if str(os_info.get("Is64Bit")) == "True" else "x86"
    st.success(f"**{ctx['name']}** → {len(memdump_extractor.FEATURE_COLUMNS)} features extracted · {os_label} ({arch})",
               icon=":material/check_circle:")
    for w in report.get("warnings", []):
        st.warning(w)
    render_hash_verification(report, ctx)

    with st.expander("Volatility extraction details", icon=":material/memory:"):
        plugin_rows = [
            {"Plugin": p, "Status": v.get("status"), "Rows": v.get("rows"),
             "Seconds": round(v["seconds"], 1) if "seconds" in v else None,
             "Error": v.get("error", "")}
            for p, v in report.get("plugins", {}).items()
        ]
        st.dataframe(pd.DataFrame(plugin_rows), width="stretch", hide_index=True)
        if os_info.get("SystemTime"):
            st.caption(f"Memory acquired at (system time): {os_info.get('SystemTime')}")
        st.caption(f"Raw plugin output & CSV saved in: `{report.get('output_dir')}`")

    return ctx


def verify_artifacts(ctx: dict, stage: str, purpose: str):
    """Re-hash the original evidence (and derived CSV) against their baselines."""
    chain = ctx["chain"]
    chain.verify_file(stage, f"Original evidence re-hashed {purpose}", ctx["evidence_path"], role="evidence")
    if ctx["csv_role"] != "evidence":
        chain.verify_file(stage, f"Derived feature CSV re-hashed {purpose}", ctx["csv_path"], role="csv")


def verify_before_analysis(ctx: dict, sample_df: pd.DataFrame, row_index: int, expected_cols: list) -> dict:
    """
    Pre-analysis checkpoint: re-verify the evidence files, then prove the exact
    feature vector submitted to the models equals the row in the verified file.
    """
    chain = ctx["chain"]
    verify_artifacts(ctx, "Pre-Analysis", "before ML inference")

    file_row = iv.feature_matrix(pd.read_csv(ctx["csv_path"]), expected_cols).iloc[[row_index]]
    role  = f"vector:row{row_index}"
    label = f"Row {row_index} feature vector ({len(expected_cols)} features)"
    chain.record("Analysis Input", "Feature vector read from the hash-verified evidence file", label,
                 {"sha256": ei.hash_feature_row(file_row)}, role=role)
    vector = chain.record("Analysis Input", "Feature vector submitted to the ML models", label,
                          {"sha256": ei.hash_feature_row(sample_df)}, role=role)
    save_manifest(chain)

    ev, csv = chain.baseline("evidence"), chain.baseline("csv")
    return {
        "case_id":         chain.case_id,
        "evidence_item_id": chain.evidence_id,
        "analyst":         chain.analyst,
        "organisation":    (active_case() or {}).get("organisation", ""),
        "provenance":      chain.provenance,
        "session_id":      (active_case() or {}).get("session_id", ""),
        "session_opened":  (active_case() or {}).get("opened_local", ""),
        "evidence_name":   ctx["name"],
        "evidence_kind":   ctx["kind"],
        "evidence_sha256": ev.get("sha256", ""),
        "evidence_md5":    ev.get("md5", ""),
        "evidence_size":   ev.get("size", 0),
        "csv_name":        csv.get("artifact", ""),
        "csv_sha256":      csv.get("sha256", ""),
        "csv_md5":         csv.get("md5", ""),
        "vector_sha256":   vector["sha256"],
        "verified_utc":    vector["timestamp"],
        "input_validation": iv.summary(ctx["validation"]) if ctx.get("validation") else "",
    }


def seal_report(ctx: dict, report_path: str) -> dict:
    """Hash the generated PDF, write a .sha256 sidecar and record it in the ledger."""
    chain  = ctx["chain"]
    hashes = ei.hash_file(report_path)
    ei.write_hash_sidecar(report_path, hashes)
    chain.record("Report", "Forensic PDF report generated and sealed (hash recorded)",
                 os.path.basename(report_path), hashes, role=f"report:{os.path.basename(report_path)}")
    ctx.setdefault("reports", []).append(report_path)
    save_manifest(chain)
    return hashes


STATUS_ICONS = {
    ei.STATUS_RECORDED: "🔵 RECORDED",
    ei.STATUS_MATCH:    "🟢 MATCH",
    ei.STATUS_MISMATCH: "🔴 MISMATCH",
    ei.STATUS_MISSING:  "🟠 NOT ACCESSIBLE",
}

RISK_TONES = {"HIGH RISK": "critical", "SUSPICIOUS": "warning", "NORMAL": "good"}
RISK_ICONS = {"HIGH RISK": "⛔", "SUSPICIOUS": "⚠️", "NORMAL": "✅"}
RISK_GLYPHS = {"HIGH RISK": "gpp_bad", "SUSPICIOUS": "warning", "NORMAL": "verified_user"}
KIND_LABELS = {"memory-dump": "Memory dump", "csv-upload": "CSV upload", "csv-sample": "Sample profile"}
ACQUISITION_TOOLS = ["DumpIt", "WinPmem", "FTK Imager", "Magnet RAM Capture", "Belkasoft RAM Capturer",
                     "VM snapshot (VMware / VirtualBox / Hyper-V)", "Volatility feature export",
                     "Research dataset", "Other"]
PURPOSES = ["Incident response", "Internal investigation", "Law enforcement request", "Court / legal proceedings",
            "Regulatory / compliance", "Client engagement", "Research / training", "Other"]
SAMPLE_ORIGIN = {
    "source_device": "CIC-MalMem2022 reference profile", "custodian": "Canadian Institute for Cybersecurity",
    "location": "Public research dataset (UNB CIC)", "collected_by": "Dataset authors",
    "acquisition_tool": "Research dataset",
}

SAMPLE_PRESETS = {
    "fresh_aggressive_ransomware.csv": "🔴 Active ransomware",
    "clean_system_baseline.csv":       "🟢 Clean workstation baseline",
    "fresh_stealth_rootkit.csv":       "🟣 DKOM kernel rootkit",
    "fresh_fileless_miner.csv":        "🟠 Injected cryptominer",
    "guaranteed_malware.csv":          "🔴 Benchmark malware (MalMem2022)",
    "guaranteed_benign.csv":           "🟢 Benchmark benign (MalMem2022)",
    "real_benign_sample.csv":          "🟢 Live host baseline",
}


def render_custody_ledger(ctx: dict):
    """Full chain-of-custody ledger with verification controls."""
    chain = ctx["chain"]
    n = len(chain.events)
    matches = sum(e["status"] == ei.STATUS_MATCH for e in chain.events)

    if chain.is_intact:
        st.success(
            f"**Integrity verified** — {matches} re-checks across {n} checkpoints match the acquisition hashes, "
            f"and the ledger's hash links are intact. The evidence was not modified inside this tool.",
            icon=":material/verified_user:",
        )
    else:
        bad = ", ".join(f"#{e['seq']} {e['stage']} ({e['artifact']})" for e in chain.mismatches) or "ledger link broken"
        st.error(f"**Integrity violation** — hash mismatch at: {bad}.", icon=":material/gpp_bad:")
    missing = [e for e in chain.events if e["status"] == ei.STATUS_MISSING]
    if missing:
        st.warning(f"{len(missing)} checkpoint(s) could not re-read their file (e.g. the original was moved). "
                   f"Earlier hashes remain valid.", icon=":material/warning:")

    ledger = chain.events_dataframe()
    ledger["Status"] = ledger["Status"].map(STATUS_ICONS).fillna(ledger["Status"])
    ledger = ledger[["#", "Stage", "Status", "Artefact", "SHA-256", "Time (UTC)", "Analyst", "Action"]]
    st.dataframe(
        ledger, hide_index=True, width="stretch",
        column_config={
            "#":          st.column_config.NumberColumn(width=40),
            "Stage":      st.column_config.TextColumn(width=130),
            "Status":     st.column_config.TextColumn(width=140),
            "Artefact":   st.column_config.TextColumn(width=220),
            "SHA-256":    st.column_config.TextColumn(width=540),
            "Time (UTC)": st.column_config.TextColumn(width=180),
            "Analyst":    st.column_config.TextColumn(width=150),
            "Action":     st.column_config.TextColumn(width=420),
        },
    )

    col_m, col_v = st.columns(2)
    with col_m:
        manifest_path = save_manifest(chain)
        with open(manifest_path, "rb") as f:
            st.download_button("Download custody manifest", data=f.read(),
                               file_name=f"{case_dir_name(chain.case_id)}_{chain.evidence_id}_custody_manifest.json",
                               mime="application/json", width="stretch", icon=":material/download:",
                               key=f"manifest_{chain.evidence_id}_{n}")
    with col_v:
        if st.button("Re-verify all hashes now", width="stretch", icon=":material/fact_check:",
                     key=f"reverify_{chain.evidence_id}"):
            verify_artifacts(ctx, "On-Demand Check", "on analyst request")
            for rep_path in ctx.get("reports", []):
                chain.verify_file("On-Demand Check", "Sealed PDF report re-hashed on analyst request",
                                  rep_path, role=f"report:{os.path.basename(rep_path)}")
            save_manifest(chain)
            st.toast("Hashes re-verified" if chain.is_intact else "Integrity violation detected!",
                     icon="✅" if chain.is_intact else "⛔")
            st.rerun()

    st.caption(
        f"Evidence folder: `{os.path.join(CASES_DIR, case_dir_name(chain.case_id), chain.evidence_id)}` · Verify any file independently with "
        f"`certutil -hashfile \"<file>\" SHA256` (Windows) or `sha256sum <file>`."
    )


def render_evidence_summary(ctx: dict, df: pd.DataFrame):
    """KPI strip + fingerprint card for the active evidence."""
    chain = ctx["chain"]
    ev, csv = chain.baseline("evidence"), chain.baseline("csv")
    intact = chain.is_intact
    integrity = (ui.pill("Verified", "good") if intact else ui.pill("Compromised", "critical"))
    ui.kpi_row([
        ui.kpi("Evidence", ui.esc(ctx["name"]), KIND_LABELS.get(ctx["kind"], ctx["kind"]), small=True, wide=True),
        ui.kpi("Size", ei.format_size(ev.get("size", 0) or 0)),
        ui.kpi("Snapshots", f"{len(df):,}", "ready to analyse" if not expert() else f"{len(df.columns)} features each"),
        ui.kpi("Integrity", integrity, "unchanged since it arrived" if intact and not expert()
               else f"{len(chain.events)} checkpoints"),
    ])
    if not expert():
        return
    hashes = (ui.hash_line("Evidence item ID", chain.evidence_id)
              + ui.hash_line("Evidence SHA-256", ev.get("sha256", "")) + ui.hash_line("Evidence MD5", ev.get("md5", "")))
    if csv:
        hashes += ui.hash_line(f"Derived CSV SHA-256 · {csv.get('artifact', '')}", csv.get("sha256", ""))
    with st.expander("Technical fingerprints — evidence ID and hashes", icon=":material/fingerprint:"):
        ui.render_html(f'<div style="padding-top: 0.1rem;">{hashes}</div>')
    prov = chain.provenance or {}
    if prov:
        origin, recipient = prov.get("origin") or {}, prov.get("prepared_for") or {}
        ui.render_html(
            '<div class="fx-prov-strip">'
            f'<div>{ui.icon("travel_explore")}<span>From</span><b>{ui.esc(origin_label(origin))}</b>'
            f'<em>collected by {ui.esc(origin.get("collected_by", "-"))} · {ui.esc(origin.get("collected_at", "-"))}</em></div>'
            f'<div>{ui.icon("outgoing_mail")}<span>For</span><b>{ui.esc(recipient_label(recipient))}</b>'
            f'<em>{ui.esc(recipient.get("purpose", "-"))}'
            f'{(" · ref " + ui.esc(recipient["reference"])) if recipient.get("reference") else ""}</em></div>'
            '</div>')


def render_feature_validation(ctx: dict, df: pd.DataFrame) -> bool:
    """
    Feature gate: check the evidence against the model's 55 features. Returns True
    when analysis may proceed (passed, or warnings acknowledged by the analyst).
    The check and any acknowledgement are recorded in the custody ledger.
    """
    chain  = ctx["chain"]
    report = iv.check_features(df, load_rf_model().feature_names_in_.tolist())
    ctx["validation"] = report
    label  = f"{ctx['name']} feature validation ({report['expected']} model features)"
    if ctx.get("validation_recorded") != report["sha256"]:
        ctx["validation_recorded"] = report["sha256"]
        chain.record("Input Validation", "Feature table checked against the model's expected features",
                     label, {"sha256": report["sha256"]}, role="validation", details=iv.summary(report))
        save_manifest(chain)
        log_fn = logger.info if report["severity"] == iv.SEVERITY_OK else logger.warning
        log_fn(f"INPUT VALIDATION | CASE={chain.case_id} | EVIDENCE={chain.evidence_id} | {iv.summary(report)}")

    if report["severity"] == iv.SEVERITY_OK:
        if expert():
            st.success(f"**Input validation passed** — all {report['expected']} model features present, numeric, "
                       f"finite and non-negative.", icon=":material/fact_check:")
        else:
            st.success("**Evidence checked** — complete and ready to analyse.", icon=":material/fact_check:")
        return True

    problems = "\n".join(f"- {p}" for p in report["problems"])
    if report["missing"] or report["no_data"]:
        with st.expander(f"Unusable features ({len(report['missing']) + len(report['no_data'])})",
                         icon=":material/list:"):
            st.code("\n".join(report["missing"] + report["no_data"]), language=None)
    if report["severity"] == iv.SEVERITY_BLOCK:
        st.error(f"**Analysis blocked — the evidence failed input validation.**\n\n{problems}",
                 icon=":material/gpp_bad:")
        return False

    st.warning(f"**Incomplete evidence** — the verdict may be unreliable:\n\n{problems}",
               icon=":material/warning:")
    acknowledged = st.checkbox("I have reviewed these issues and accept that the affected values are treated as 0",
                               key=f"ack_validation:{ctx['key']}:{report['sha256'][:12]}")
    if acknowledged and ctx.get("validation_ack") != report["sha256"]:
        ctx["validation_ack"] = report["sha256"]
        chain.record("Input Validation", "Analyst acknowledged validation warnings before analysis",
                     label, {"sha256": report["sha256"]}, role="validation",
                     details=f"Acknowledged by {chain.analyst}: {'; '.join(report['problems'])}")
        save_manifest(chain)
        logger.warning(f"INPUT VALIDATION ACKNOWLEDGED | CASE={chain.case_id} | EVIDENCE={chain.evidence_id} | "
                       f"ANALYST={chain.analyst}")
    return acknowledged


def render_evidence_origin(source: str):
    """
    'Where did this evidence come from?' Returns the origin dict, or None while a
    required field is missing. Values are locked into the ledger at acquisition.
    """
    defaults = SAMPLE_ORIGIN if source == "sample" else {}
    k = lambda field: f"origin_{source}_{field}"
    with st.expander("Where did this evidence come from?", icon=":material/travel_explore:",
                     expanded=source != "sample"):
        c1, c2, c3 = st.columns(3)
        device    = c1.text_input("Device / computer name *", value=defaults.get("source_device", ""),
                                  placeholder="e.g. HR-PC-07", key=k("device"))
        collector = c2.text_input("Collected by *", value=defaults.get("collected_by", ""),
                                  placeholder="Who copied the evidence", key=k("collector"))
        reported  = c3.text_input("Expected hash (optional)", key=k("hash"),
                                  placeholder="SHA-256, SHA-1 or MD5 from the acquisition tool or a .sha256 file",
                                  help="Works for memory dumps and CSV files. It is compared with the hash computed "
                                       "when the evidence arrives; a mismatch blocks analysis. Paste a whole "
                                       ".sha256 line or tool log if you like - the hash is picked out.")
        found = ei.parse_hash_text(reported)
        reported = found[0][0] if found else reported.strip().lower()
        custodian, location, notes = (defaults.get("custodian", ""), defaults.get("location", ""), "")
        day, at = datetime.now().date(), datetime.now().time().replace(microsecond=0)
        tool = defaults.get("acquisition_tool", "DumpIt")
        if st.toggle("Add more details (owner, location, date, tool)", key=k("more"), value=expert()):
            m1, m2, m3 = st.columns(3)
            custodian = m1.text_input("Owner / custodian", value=custodian, placeholder="e.g. John Smith, HR",
                                      key=k("custodian"))
            location  = m2.text_input("Collected from (location)", value=location,
                                      placeholder="e.g. HQ, 3rd floor", key=k("location"))
            tool      = m3.selectbox("Acquisition tool", ACQUISITION_TOOLS, key=k("tool"),
                                     index=ACQUISITION_TOOLS.index(tool))
            m4, m5, m6 = st.columns([1, 0.7, 2])
            day       = m4.date_input("Collection date", key=k("date"))
            at        = m5.time_input("Time", key=k("time"))
            notes     = m6.text_input("Notes", placeholder="e.g. Seized under warrant 22/114", key=k("notes"))
        st.caption("Saved with the evidence when it is added. Changes made afterwards apply to the next item.")
    if reported and not ei.detect_algorithm(reported):
        st.error("The expected hash must be an MD5 (32), SHA-1 (40) or SHA-256 (64 hex characters).",
                 icon=":material/error:")
        st.session_state.pop("pending_origin", None)
        return None
    if len(device.strip()) < 2 or len(collector.strip()) < 2:
        st.session_state.pop("pending_origin", None)
        return None
    collected_at = datetime.combine(day, at).astimezone()
    origin = {
        "source_device": device.strip(), "custodian": custodian.strip(), "location": location.strip(),
        "collected_by": " ".join(collector.split()), "acquisition_tool": tool, "notes": notes.strip(),
        "reported_hash": reported,
        "collected_at": ei.local_timestamp(collected_at),
    }
    st.session_state["pending_origin"] = origin
    return origin


def render_provenance_tab(evidence: dict):
    prov = evidence["chain"].provenance or {}
    origin, recipient = prov.get("origin") or {}, prov.get("prepared_for") or {}
    if not origin and not recipient:
        st.info("No provenance was recorded for this evidence item (acquired before provenance tracking).")
        return
    st.caption("Recorded at acquisition and sealed in the custody ledger (stage **Provenance**).")
    c_from, c_to = st.columns(2, gap="large")
    with c_from:
        ui.render_html(f'<div class="fx-prov-head">{ui.mac_icon("travel_explore", 34)}'
                       f'<div><div class="fx-prov-title">Where the evidence came from</div>'
                       f'<div class="fx-prov-sub">Origin &amp; acquisition</div></div></div>')
        ui.kpi_row([
            ui.kpi("Source device / host", ui.esc(origin.get("source_device", "—")), small=True, wide=True),
            ui.kpi("Owner / custodian", ui.esc(origin.get("custodian") or "—"), small=True),
            ui.kpi("Location", ui.esc(origin.get("location") or "—"), small=True),
            ui.kpi("Collected by", ui.esc(origin.get("collected_by", "—")), small=True),
            ui.kpi("Collected at", ui.esc(origin.get("collected_at", "—")), small=True),
            ui.kpi("Acquisition tool", ui.esc(origin.get("acquisition_tool", "—")), small=True, wide=True),
        ])
        if origin.get("notes"):
            st.caption(f"Notes: {origin['notes']}")
    with c_to:
        ui.render_html(f'<div class="fx-prov-head">{ui.mac_icon("outgoing_mail", 34)}'
                       f'<div><div class="fx-prov-title">Who it is prepared for</div>'
                       f'<div class="fx-prov-sub">Recipient &amp; purpose</div></div></div>')
        ui.kpi_row([
            ui.kpi("Recipient", ui.esc(recipient.get("name") or "—"), small=True, wide=True),
            ui.kpi("Organisation", ui.esc(recipient.get("organisation") or "—"), small=True),
            ui.kpi("Purpose", ui.esc(recipient.get("purpose") or "—"), small=True),
            ui.kpi("Reference", ui.esc(recipient.get("reference") or "—"), small=True, wide=True),
        ])


def render_ingestion():
    """Evidence intake. Returns the active evidence context, or None while waiting."""
    source = st.segmented_control(
        "Evidence source",
        options=["sample", "csv", "dump"],
        format_func={"sample": ":material/science: Try a sample", "csv": ":material/table_view: Feature file (CSV)",
                     "dump": ":material/memory: Memory dump"}.get,
        default="sample",
        key="ingest_source",
    ) or "sample"

    if render_evidence_origin(source) is None:
        st.info("Complete the required **evidence origin** fields (*) to enable intake.", icon=":material/info:")
        return None

    if source == "sample":
        available = [s for s in SAMPLE_PRESETS if os.path.exists(os.path.join(SAMPLES_DIR, s))]
        if not available and os.path.exists(SAMPLES_DIR):
            available = [f for f in os.listdir(SAMPLES_DIR) if f.endswith(".csv")]
        if not available:
            st.error("No sample profiles found in `data/test_samples/`.")
            return None
        selected = st.selectbox("Choose a sample", available, format_func=lambda s: SAMPLE_PRESETS.get(s, s))
        path = os.path.join(SAMPLES_DIR, selected)
        hashes = ei.hash_file(path)
        return ingest_csv_evidence(key=f"sample:{selected}:{hashes['sha256']}", name=selected,
                                   kind="csv-sample", hashes=hashes, source_path=path)

    if source == "dump":
        return render_memory_dump_ingestion()

    uploaded = st.file_uploader("Volatility feature CSV", type=["csv"],
                                help="A CSV with the 55 Volatility memory features (one row per memory snapshot).")
    if uploaded is None:
        ui.empty_state("upload_file", "Drop a Volatility CSV to begin",
                       "It is fingerprinted on arrival and re-verified at every step.")
        return None
    try:
        iv.check_csv_upload(uploaded, uploaded.size, load_rf_model().feature_names_in_.tolist())
    except iv.UploadRejected as e:
        reject_intake(f"csv-upload:{uploaded.name}:{uploaded.size}", uploaded.name, e)
        return None
    hashes = ei.hash_stream(uploaded)
    return ingest_csv_evidence(key=f"csv-upload:{uploaded.name}:{hashes['sha256']}", name=uploaded.name,
                               kind="csv-upload", hashes=hashes, uploaded_file=uploaded)


def evidence_bytes(evidence: dict) -> int:
    """Bytes re-hashed before every analysis: the original evidence (+ the derived CSV for dumps)."""
    chain = evidence["chain"]
    size = chain.baseline("evidence").get("size") or 0
    if evidence.get("csv_role") != "evidence":
        size += chain.baseline("csv").get("size") or 0
    return int(size)


def run_selected_triage(evidence: dict, df: pd.DataFrame, row_index: int):
    """Integrity checkpoint + model inference for the selected row."""
    rf_model      = load_rf_model()
    expected_cols = rf_model.feature_names_in_.tolist()
    sample_df = iv.feature_matrix(df, expected_cols).iloc[[row_index]]

    tm, size = timing_stats(), evidence_bytes(evidence)
    estimate = tm.triage_seconds(size)
    hash_w = min(tm.hash_seconds(size) / max(estimate, 0.1), 0.9)
    eta = timing.ProgressETA(estimate, f"Re-verifying evidence hashes ({ei.format_size(size)})...")
    integrity = verify_before_analysis(evidence, sample_df, row_index, expected_cols)
    if not evidence["chain"].is_intact:
        eta.empty()
        st.session_state["current_triage"] = None
        logger.error(f"ANALYSIS BLOCKED | CASE={evidence['chain'].case_id} | integrity verification failed")
        st.session_state["triage_blocked"] = True
        return
    st.session_state["triage_blocked"] = False

    step = lambda frac, msg: eta.update(hash_w + (1 - hash_w) * frac, msg, force=True)
    step(0.0, "Running the Random Forest and the zero-day detector...")
    result = run_triage(sample_df, evidence["name"], row_index, integrity)
    result["evidence_key"] = evidence["key"]
    step(0.15, "Explaining the verdict with SHAP...")
    compute_shap(result)
    step(0.45, "Cross-checking the explanation with LIME...")
    compute_lime(result)
    eta.empty()
    tm.record_triage(eta.elapsed, size)
    st.session_state["current_triage"] = result
    st.toast(f"Triage complete — {result['risk']}", icon=RISK_ICONS[result["risk"]])


def render_batch_results(summary: pd.DataFrame):
    st.dataframe(
        summary, hide_index=True, width="stretch", height=min(400, 38 * len(summary) + 40),
        column_config={
            "Row": st.column_config.NumberColumn(width=70),
            "Malware confidence": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.1f%%"),
        },
    )


def render_verdict(result: dict, chain):
    risk = result["risk"]
    tone = RISK_TONES[risk]
    pct = result["probability"] * 100
    label = CLASSIFICATION[risk]
    banner = {
        "HIGH RISK":  ("Critical — contain the host", "Active malicious indicators found in memory. Isolate the endpoint and escalate."),
        "SUSPICIOUS": ("Suspicious — analyst review needed", "Memory metrics deviate from normal. Review before releasing the host."),
        "NORMAL":     ("Clean — normal baseline", "Memory behaviour matches a healthy Windows system."),
    }[risk]
    anomaly_html = ""
    if result["is_anomaly"]:
        anomaly_html = ui.banner("radar", "Zero-day anomaly", "Isolation Forest flagged this profile as an outlier versus known baselines.", "accent")
    if not expert():
        tiles = "".join([
            ui.kpi("Risk level", f"{ui.icon(RISK_GLYPHS[risk])} {PLAIN_VERDICT[risk][1]}", color=ui.TONES[tone][0]),
            ui.kpi("New or unknown threat?", f"{ui.icon('radar')} Possibly" if result["is_anomaly"]
                   else f"{ui.icon('check_circle')} No", color=ui.WARNING if result["is_anomaly"] else ui.GOOD),
            ui.kpi("Evidence", f"{ui.icon('lock')} Unchanged" if chain.is_intact else f"{ui.icon('lock_open')} Changed!",
                   "exactly as it was when it arrived" if chain.is_intact else "do not rely on this result",
                   color=ui.GOOD if chain.is_intact else ui.CRITICAL, wide=True),
        ])
        ui.render_html(f'<div class="fx-card"><div class="fx-verdict"><div>{ui.gauge(pct, tone, "Malware risk")}'
                       f'</div><div><div class="fx-kpis">{tiles}</div></div></div></div>')
        return
    tiles = "".join([
        ui.kpi("Risk level", f"{ui.icon(RISK_GLYPHS[risk])} {risk}", color=ui.TONES[tone][0]),
        ui.kpi("Classification", f"{ui.icon({'MALWARE': 'coronavirus', 'UNCERTAIN': 'help', 'BENIGN': 'shield'}[label])} "
                                 f"{label}", color=ui.TONES[tone][0]),
        ui.kpi("Zero-day check", f"{ui.icon('radar')} Anomaly" if result["is_anomaly"] else f"{ui.icon('check_circle')} Normal",
               color=ui.WARNING if result["is_anomaly"] else ui.GOOD),
        ui.kpi("Evidence integrity", f"{ui.icon('lock')} Verified" if chain.is_intact else f"{ui.icon('lock_open')} Compromised",
               color=ui.GOOD if chain.is_intact else ui.CRITICAL),
    ])
    ui.render_html(f"""
    <div class="fx-card">
      <div class="fx-verdict">
        <div>{ui.gauge(pct, tone, "Malware score")}</div>
        <div>
          <div class="fx-kpis">{tiles}</div>
          {ui.banner(RISK_GLYPHS[risk], banner[0], banner[1], tone)}
          {anomaly_html}
        </div>
      </div>
    </div>
    """)


PLAIN_VERDICT = {
    "NORMAL": ("verified_user", "Looks clean", "The memory looks like a healthy Windows computer. No action is needed."),
    "SUSPICIOUS": ("warning", "Needs a closer look",
                   "Some memory measurements look unusual. A person should review this computer before it is "
                   "used again."),
    "HIGH RISK": ("gpp_bad", "Likely infected",
                  "This memory shows strong signs of malware. Disconnect the computer from the network and "
                  "escalate to your security team."),
}


def render_overview_tab(result: dict):
    shap_df = result.get("_shap_df")
    glyph, title, text = PLAIN_VERDICT[result["risk"]]
    if result.get("is_anomaly"):
        text += " It also looks unlike anything the system has seen before, which can mean a new kind of threat."
    ui.render_html(ui.banner(glyph, title, ui.esc(text), RISK_TONES[result["risk"]]))
    col_a, col_b = st.columns([1.05, 1], gap="large")
    with col_a:
        st.markdown("##### What to do next")
        tone = RISK_TONES[result["risk"]]
        fg, bg, border = ui.TONES[tone]
        items = []
        for i, action in enumerate((RESPONSE_ACTIONS if expert() else SIMPLE_ACTIONS)[result["risk"]], start=1):
            text = re.sub(r'^[^\w]+', '', action).strip()
            items.append(f'<div class="fx-action"><div class="fx-action-num" style="color:{fg};background:{bg};'
                         f'border:1px solid {border};">{i}</div><div class="fx-action-text">{ui.esc(text)}</div></div>')
        ui.render_html("".join(items))
    with col_b:
        st.markdown("##### Main reasons")
        if shap_df is None:
            st.info("Explanation unavailable for this run.")
        else:
            rows = []
            for _, r in shap_df.head(5).iterrows():
                up = r["SHAP Value"] > 0
                color = ui.TOWARD_MALWARE if up else ui.TOWARD_BENIGN
                detail = (f'{r["SHAP Value"]*100:+.1f} pts · <code>{ui.esc(r["Technical Metric"])}</code>' if expert()
                          else ("points towards malware" if up else "points towards a clean system"))
                rows.append(
                    f'<div class="fx-action"><div class="fx-action-num" style="color:{color};border:1px solid {color};">'
                    f'{"▲" if up else "▼"}</div><div style="min-width:0;"><div class="fx-action-text">'
                    f'{ui.esc(r["Plain English Indicator"] if expert() else plain_name(r["Plain English Indicator"]))}'
                    f'</div><div style="font-size:0.88rem;color:var(--muted);">{detail}</div></div></div>'
                )
            ui.render_html("".join(rows))
            st.caption("▲ points towards malware · ▼ points towards a clean system."
                       + (" Details in the Explainability tab." if expert() else ""))


def ensure_report(evidence: dict, result: dict) -> dict:
    """Generate (once) and seal the PDF for this analysis; returns its state."""
    pdf_key = f"pdf_ready_{result['evidence_id']}"
    if pdf_key not in st.session_state:
        with st.spinner("Re-verifying evidence and compiling the PDF report..."):
            verify_artifacts(evidence, "Pre-Report", "before the report is compiled")
            if not evidence["chain"].is_intact:
                st.session_state[pdf_key] = {"error": "Evidence integrity verification failed — report NOT produced."}
                logger.error(f"REPORT BLOCKED | CASE={evidence['chain'].case_id} | integrity verification failed")
            else:
                try:
                    path, data = generate_pdf_report(result, shap_df=result.get("_shap_df"),
                                                     lime_df=result.get("_lime_df"), chain=evidence["chain"])
                    hashes = seal_report(evidence, path)
                    st.session_state[pdf_key] = {"path": path, "bytes": data, "filename": os.path.basename(path),
                                                 "sha256": hashes["sha256"], "md5": hashes["md5"]}
                except Exception as e:
                    st.session_state[pdf_key] = {"error": str(e)}
                    logger.error(f"PDF error for {result['evidence_id']}: {e}")
    return st.session_state[pdf_key]


def render_report_tab(result: dict, pdf_state: dict):
    pdf_key = f"pdf_ready_{result['evidence_id']}"
    if "error" in pdf_state:
        st.error(f"Report generation failed: {pdf_state['error']}", icon=":material/error:")
        if st.button("Retry", type="primary", icon=":material/refresh:", key=f"retry_{result['evidence_id']}"):
            del st.session_state[pdf_key]
            st.rerun()
        return

    ui.render_html(f"""
    <div class="fx-card" style="display:flex; gap:1.1rem; align-items:center; flex-wrap:wrap;">
      <div style="font-size:2.4rem;">📑</div>
      <div style="flex:1 1 320px; min-width:0;">
        <div style="font-size:1.2rem; font-weight:700;">Forensic incident report</div>
        <div style="color:var(--muted); font-size:0.95rem; margin-top:0.15rem;">Verdict, explainability, response playbook and the full chain-of-custody ledger.</div>
        <div style="margin-top:0.4rem;"><code>{ui.esc(pdf_state['filename'])}</code></div>
      </div>
      {ui.pill("Sealed", "good")}
    </div>
    """)
    st.write("")
    col_d, col_r = st.columns([2, 1])
    with col_d:
        st.download_button("Download PDF report", data=pdf_state["bytes"], file_name=pdf_state["filename"],
                           mime="application/pdf", type="primary", width="stretch", icon=":material/download:",
                           key=f"dl_btn_{result['evidence_id']}")
    with col_r:
        if st.button("Regenerate", width="stretch", icon=":material/refresh:", key=f"regen_{result['evidence_id']}"):
            del st.session_state[pdf_key]
            st.rerun()
    ui.render_html(
        '<div class="fx-card" style="margin-top:0.8rem;">'
        + ui.hash_line("Report SHA-256", pdf_state.get("sha256", ""))
        + ui.hash_line("Report MD5", pdf_state.get("md5", ""))
        + f'<div style="color:var(--muted); font-size:0.9rem; margin-top:0.8rem;">Recorded in the custody ledger, the audit log '
          f'and <code>{ui.esc(pdf_state["filename"])}.sha256</code>. Any change to the PDF changes this hash.</div></div>'
    )
    st.caption(f"Saved to `{pdf_state['path']}`")


def render_custody_tab(result: dict, evidence: dict):
    integ = result.get("integrity", {}) or {}
    ui.kpi_row([
        ui.kpi("Case number", ui.esc(integ.get("case_id", "—")), mono=True),
        ui.kpi("Analyst", ui.esc(integ.get("analyst", "—")), ui.esc(integ.get("organisation", ""))),
        ui.kpi("Evidence item", ui.esc(integ.get("evidence_item_id", "—")), mono=True, wide=True),
        ui.kpi("Analysis ID", ui.esc(result["evidence_id"]), mono=True),
        ui.kpi("Analysed", f"Row {result['row_index']}", f"{len(result.get('feature_cols', []))} features"),
        ui.kpi("Analysis time", ui.esc(result["timestamp"]), small=True, wide=True),
    ])
    hashes = (ui.hash_line("Evidence SHA-256 (at acquisition)", integ.get("evidence_sha256", "—"))
              + ui.hash_line("Evidence MD5", integ.get("evidence_md5", "—")))
    if integ.get("csv_sha256"):
        hashes += ui.hash_line(f"Derived CSV SHA-256 · {integ.get('csv_name', '')}", integ["csv_sha256"])
    hashes += ui.hash_line("Analysed feature vector SHA-256", integ.get("vector_sha256", "—"))
    ui.render_html(f'<div class="fx-card" style="margin: 0.8rem 0 1rem; padding-top: 0.4rem;">{hashes}</div>')
    render_custody_ledger(evidence)


def render_audit_tab():
    log_path = AUDIT_LOG_PATH
    if not os.path.exists(log_path):
        st.info("No audit records yet.")
        return
    with open(log_path, "r", encoding="utf-8", errors="replace") as lf:
        lines = lf.readlines()
    st.caption(f"Last 30 of {len(lines):,} entries · `logs/triage_audit.log`")
    st.code("".join(lines[-30:]) or "Audit log is empty.", language="text")


def render_sidebar(case, evidence, result, pdf_ready: bool):
    rf_found, iso_found = os.path.exists(MODEL_PATH), os.path.exists(ISO_PATH)
    with st.sidebar:
        ui.render_html('<div class="fx-side-label">Active case</div>')
        if case:
            ellipsis = "max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text);"
            rows = f'<div class="fx-side-row"><span>Case</span><code>{ui.esc(case["case_number"])}</code></div>'
            if expert():
                rows += (f'<div class="fx-side-row"><span>Analyst</span><span style="{ellipsis}">{ui.esc(case["analyst"])}</span></div>'
                         f'<div class="fx-side-row"><span>Opened</span><span style="font-size:0.85rem;">{ui.esc(case["opened_local"][5:16])}</span></div>')
            if evidence:
                chain = evidence["chain"]
                rows += f'<div class="fx-side-row"><span>Evidence</span><span style="{ellipsis}">{ui.esc(evidence["name"])}</span></div>'
                if expert():
                    rows += f'<div class="fx-side-row"><span>SHA-256</span><code>{chain.baseline("evidence").get("sha256", "")[:12]}…</code></div>'
                rows += (f'<div class="fx-side-row"><span>Integrity</span>'
                         f'{ui.pill("Verified", "good") if chain.is_intact else ui.pill("Compromised", "critical")}</div>')
            ui.render_html(rows)
        else:
            st.caption("No case open.")

        log_check = audit_log_status()
        if not log_check["verified"]:
            st.error("Audit log verification failed: " + "; ".join(log_check["problems"][:3]), icon=":material/gpp_bad:")
        if not expert():
            return
        ui.render_html('<div class="fx-side-label">Engines</div>')
        ui.render_html(
            f'<div class="fx-side-row"><span>Random Forest</span>{ui.pill("Online" if rf_found else "Offline", "good" if rf_found else "critical")}</div>'
            f'<div class="fx-side-row"><span>Isolation Forest</span>{ui.pill("Online" if iso_found else "Disabled", "good" if iso_found else "warning")}</div>'
            f'<div class="fx-side-row"><span>Volatility 3</span>{ui.pill("Ready", "good")}</div>'
        )
        ui.render_html(
            f'<div class="fx-side-row"><span>Audit log chain</span>'
            f'{ui.pill("Intact", "good") if log_check["verified"] else ui.pill("Broken", "critical")}</div>')
        st.caption("Audit log: `logs/triage_audit.log`  \nCases: `outputs/cases/`")


def render_dashboard(state: dict):
    # ── 0. Case session (mandatory) ───────────────────────────
    ui.section("1 · Start a case", "Give the case a number and say who the findings are for.", "folder_open")
    with st.container(border=True):
        session = render_case_session()
    if session is None:
        st.markdown("##### New here? This is how it works")
        ui.guide_steps([
            ("rocket_launch", "Start a case", "Type a case number and who the findings are for."),
            ("upload_file", "Add evidence", "Try a sample, or add a feature file (CSV) or a memory dump."),
            ("troubleshoot", "Analyse", "Press Analyse evidence - you get a verdict in plain words."),
            ("picture_as_pdf", "Download the report", "Get the sealed PDF to share with the recipient."),
        ])
        st.caption("Need more detail? Open **Help** in the top menu for a glossary and FAQ.")
        return
    state["case"] = session

    # ── 1. Evidence intake ────────────────────────────────────
    ui.section("2 · Add evidence", "Try a sample, or add a feature file (CSV) or a Windows memory dump.",
               "inventory_2")
    with st.container(border=True):
        evidence = render_ingestion()
    if evidence is None:
        return
    state["evidence"] = evidence

    try:
        df = pd.read_csv(evidence["csv_path"])   # always the hash-verified file on disk
    except Exception as e:
        st.error(f"Could not read evidence `{evidence['name']}`: {e}")
        return
    if df.empty:
        st.error("The evidence file contains no records.")
        return

    if st.session_state.get("last_source_file") != evidence["key"]:
        st.session_state["current_triage"] = None
        st.session_state["batch_summary"]  = None
        st.session_state["triage_blocked"] = False
        st.session_state["last_source_file"] = evidence["key"]

    render_evidence_summary(evidence, df)
    if expert():
        with st.expander("Preview evidence data", icon=":material/table_view:"):
            st.dataframe(df.head(10), width="stretch")
    if not render_feature_validation(evidence, df):
        return

    # ── 2. Triage controls ────────────────────────────────────
    ui.section("3 · Analyse", "Check the evidence and get a verdict in plain words.", "troubleshoot")
    with st.container(border=True):
        multi = len(df) > 1
        parts = (["row"] if multi or expert() else []) + ["run"] + (["scan"] if multi else []) + (["reset"] if expert() else [])
        widths = {"row": 2, "run": 1.8, "scan": 1.45, "reset": 1}
        slot = dict(zip(parts, st.columns([widths[p] for p in parts], vertical_alignment="bottom")))
        row_index, scan_clicked = 0, False
        if "row" in slot:
            with slot["row"]:
                row_index = st.selectbox("Which snapshot?", options=list(range(len(df))),
                                         format_func=lambda i: f"Snapshot {i + 1}" + (f" of {len(df)}" if multi else ""))
        with slot["run"]:
            run_clicked = st.button("Analyse evidence", type="primary", width="stretch", icon=":material/play_arrow:",
                                    help="Checks the evidence has not changed, then asks the AI models for a verdict "
                                         "and explains it.")
        if "scan" in slot:
            with slot["scan"]:
                scan_clicked = st.button("Scan all snapshots", width="stretch", icon=":material/radar:",
                                         help="Quickly scores every snapshot so you can pick the riskiest one.")
        if "reset" in slot:
            with slot["reset"]:
                if st.button("Reset", width="stretch", icon=":material/restart_alt:",
                             help="Clears the results on screen. Nothing is deleted from the case."):
                    st.session_state["current_triage"] = None
                    st.session_state["batch_summary"] = None
                    st.rerun()
        size = evidence_bytes(evidence)
        st.caption(f":material/timer: Takes {timing.approx(timing_stats().triage_seconds(size))}"
                   + (f" — includes re-verifying {ei.format_size(size)} of evidence." if expert() else "."))

        if scan_clicked:
            rf_model = load_rf_model()
            batch_df = iv.feature_matrix(df, rf_model.feature_names_in_.tolist())
            probs = rf_model.predict_proba(batch_df)[:, 1]
            st.session_state["batch_summary"] = pd.DataFrame({
                "Row": range(len(df)),
                "Malware confidence": probs * 100,
                "Verdict": [{"MALWARE": "🦠 Malware", "UNCERTAIN": "❔ Uncertain", "BENIGN": "🛡️ Benign"}[
                                CLASSIFICATION[risk_tier(p)]] for p in probs],
                "Risk": [f"{RISK_ICONS[risk_tier(p)]} {risk_tier(p)}" for p in probs],
            })
        if st.session_state.get("batch_summary") is not None:
            render_batch_results(st.session_state["batch_summary"])

    if run_clicked:
        run_selected_triage(evidence, df, row_index)

    if st.session_state.get("triage_blocked"):
        state["blocked"] = True
        st.error("**Analysis blocked** — a hash recomputed before analysis does not match the acquisition hash. "
                 "The evidence may have been modified.", icon=":material/gpp_bad:")
        render_custody_ledger(evidence)
        return

    result = st.session_state.get("current_triage")
    if result is None or result.get("evidence_key") != evidence["key"]:
        ui.empty_state("biotech", "Ready to analyse",
                       "Choose a snapshot above and press <b>Analyse evidence</b> to get the verdict, explanation and report.")
        return
    state["result"] = result

    if result["row_index"] != row_index:
        st.info(f"Showing results for **row {result['row_index']}**. Press **Analyse evidence** to analyse row {row_index}.",
                icon=":material/info:")

    # ── 3. Results ────────────────────────────────────────────
    ui.section("Result", f"{result['source_file']} · snapshot {result['row_index'] + 1} · {result['timestamp']}", "gavel")
    render_verdict(result, evidence["chain"])

    pdf_state = ensure_report(evidence, result)       # before the ledger so it includes the report seal
    state["pdf_ready"] = "sha256" in pdf_state

    st.write("")
    if not expert():
        t_over, t_report = st.tabs([":material/lightbulb: What it means", ":material/picture_as_pdf: Report"])
        with t_over:
            render_overview_tab(result)
        with t_report:
            render_report_tab(result, pdf_state)
        st.caption("Want the evidence hashes, explanation charts or custody ledger? Turn on "
                   "**Show technical details** in the sidebar.")
        return
    t_over, t_xai, t_prov, t_custody, t_report, t_log = st.tabs([
        ":material/lightbulb: What it means",
        ":material/psychology: Explainability",
        ":material/travel_explore: Provenance",
        ":material/verified_user: Chain of custody",
        ":material/picture_as_pdf: Report",
        ":material/receipt_long: Audit log",
    ])
    with t_over:
        render_overview_tab(result)
    with t_xai:
        s_shap, s_lime = st.tabs(["SHAP · global drivers", "LIME · local rules"])
        with s_shap:
            render_shap_explanation(result)
        with s_lime:
            render_lime_explanation(result)
    with t_prov:
        render_provenance_tab(evidence)
    with t_custody:
        render_custody_tab(result, evidence)
    with t_report:
        render_report_tab(result, pdf_state)
    with t_log:
        render_audit_tab()


def triage_page():
    rf_found = os.path.exists(MODEL_PATH)
    ui.page_header(
        "Haz", "Mem",
        "Explainable AI triage for Windows memory forensics",
        ([ui.pill("Models online" if rf_found else "Model missing", "good" if rf_found else "critical"),
          ui.pill("Chain of custody: SHA-256", "accent", dot=False)] if expert() else
         [ui.pill("Ready" if rf_found else "AI model missing", "good" if rf_found else "critical")]),
    )
    stepper_slot = st.empty()

    state = {"case": None, "evidence": None, "result": None, "pdf_ready": False, "blocked": False}
    try:
        render_dashboard(state)
    finally:
        evidence, result = state["evidence"], state["result"]
        intact = bool(evidence) and evidence["chain"].is_intact
        steps = [
            ("Case", "Start a case", "done" if state["case"] else "active"),
            ("Evidence", "Add evidence", "done" if evidence else ("active" if state["case"] else "pending")),
            ("Check", "Unchanged?",
             "blocked" if (evidence and not intact) or state["blocked"] else "done" if intact else "pending"),
            ("Analyse", "Get a verdict", "done" if result else ("active" if intact else "pending")),
            ("Report", "Download PDF", "done" if state["pdf_ready"] else ("active" if result else "pending")),
        ]
        with stepper_slot.container():
            ui.stepper(steps)
        render_sidebar(state["case"], evidence, result, state["pdf_ready"])


# ── Cases page ────────────────────────────────────────────────────────────────
PAGES = {}   # navigation pages, filled in main() (used to jump back to Triage)


def list_case_records() -> list:
    records = []
    if os.path.isdir(CASES_DIR):
        for name in os.listdir(CASES_DIR):
            path = os.path.join(CASES_DIR, name, "case.json")
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    rec = json.load(f)
            except (OSError, ValueError):
                continue
            rec["_dir"] = os.path.join(CASES_DIR, name)
            records.append(rec)
    return sorted(records, key=lambda r: r.get("created_utc", ""), reverse=True)


def latest_recipient(rec: dict) -> dict:
    return next((s["recipient"] for s in reversed(rec.get("sessions", [])) if s.get("recipient")), {}) or {}


def manifest_status(case_dir: str, evidence_id: str):
    path = os.path.join(case_dir, evidence_id, "custody_manifest.json")
    if not os.path.isfile(path):
        return "Ledger missing", "warning", None
    check = ei.verify_manifest(path)
    with open(path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    if check["verified"]:
        return "Verified", "good", manifest
    if any("legacy" in p for p in check["problems"]):
        return "Legacy ledger", "neutral", manifest
    return "Compromised", "critical", manifest


def case_reports(manifest: dict) -> list:
    reports = []
    for e in (manifest or {}).get("events", []):
        if e["stage"] == "Report":
            name = os.path.basename(e["artifact"])
            path = next((p for p in (os.path.join(REPORTS_DIR, name), os.path.join(OUTPUT_DIR, name))
                         if os.path.isfile(p)), os.path.join(REPORTS_DIR, name))   # older reports: outputs/
            exists = os.path.isfile(path)
            reports.append({"name": e["artifact"], "path": path, "time": e["timestamp"], "exists": exists,
                            "intact": exists and ei.hash_file(path)["sha256"] == e["sha256"]})
    return reports


def continue_case(rec: dict):
    user = st.session_state["auth_user"]
    if active_case():
        close_case_session()
    last = (rec.get("sessions") or [{}])[-1]
    open_case_session(rec["case_number"], f"{user['full_name']} ({user['username']})",
                      last.get("organisation", ""), "Continued from the Cases page",
                      latest_recipient(rec) or {"name": "-", "organisation": "", "purpose": "Other", "reference": ""})
    st.switch_page(PAGES["triage"])


def cases_page():
    ui.section("Cases", "Every case in this lab — evidence, integrity, reports and who it was prepared for.",
               "folder_shared")
    records = list_case_records()
    if not records:
        ui.empty_state("folder_open", "No cases yet", "Open a case on the <b>Triage</b> page — it will appear here.")
        return

    rows = []
    for r in records:
        sessions, evidence = r.get("sessions", []), r.get("evidence", [])
        times = [t for s in sessions for t in (s.get("opened_utc"), s.get("closed_utc")) if t]
        times += [e.get("acquired_utc") for e in evidence if e.get("acquired_utc")]
        rows.append({
            "Case": r["case_number"],
            "Prepared for": admin_recipient(latest_recipient(r)),
            "Analysts": ", ".join(sorted({s.get("analyst", "") for s in sessions if s.get("analyst")})),
            "Evidence": len(evidence),
            "Sessions": len(sessions),
            "Created": r.get("created_local", "")[:16],
            "Last activity": max(times)[:16] if times else "",
        })
    table = pd.DataFrame(rows)
    query = st.text_input("Search cases", placeholder="Case number, analyst, recipient…", key="case_search",
                          icon=":material/search:")
    if query:
        mask = table.apply(lambda r: query.lower() in " ".join(map(str, r.values)).lower(), axis=1)
        table = table[mask]
    ui.kpi_row([
        ui.kpi("Cases", f"{len(records)}"),
        ui.kpi("Evidence items", f"{sum(len(r.get('evidence', [])) for r in records)}"),
        ui.kpi("Analysts", f"{len({s.get('analyst') for r in records for s in r.get('sessions', [])})}"),
    ])
    st.write("")
    st.dataframe(table, hide_index=True, width="stretch",
                 column_config={"Evidence": st.column_config.NumberColumn(width=90),
                                "Sessions": st.column_config.NumberColumn(width=90)})
    if table.empty:
        st.caption("No case matches your search.")
        return

    choice = st.selectbox("Case details", table["Case"].tolist(), key="case_pick")
    rec = next(r for r in records if r["case_number"] == choice)
    recipient = latest_recipient(rec)
    with st.container(border=True):
        top_l, top_r = st.columns([4, 1.3], vertical_alignment="center")
        with top_l:
            ui.kpi_row([
                ui.kpi("Case", ui.esc(rec["case_number"]), mono=True),
                ui.kpi("Prepared for", ui.esc(recipient.get("name") or "—"),
                       ui.esc(" · ".join(v for v in (recipient.get("organisation"), recipient.get("purpose")) if v)),
                       small=True),
                ui.kpi("Created", ui.esc(rec.get("created_local", "—")[:16]), small=True),
            ])
        with top_r:
            current = (active_case() or {}).get("case_number") == rec["case_number"]
            if st.button("Open in Triage" if current else "Continue this case", type="primary", width="stretch",
                         icon=":material/play_arrow:", help="Starts a new recorded session for this case."):
                if current:
                    st.switch_page(PAGES["triage"])
                continue_case(rec)

        st.markdown("**Evidence items**")
        if not rec.get("evidence"):
            st.caption("No evidence was acquired in this case yet.")
        for ev in rec.get("evidence", []):
            label, tone, manifest = manifest_status(rec["_dir"], ev["evidence_id"])
            origin = ((ev.get("provenance") or {}).get("origin")) or {}
            with st.expander(f"{ev['name']}  ·  {KIND_LABELS.get(ev.get('kind'), ev.get('kind', ''))}  ·  {label}",
                             icon=":material/description:"):
                ui.render_html(
                    f'<div style="display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:.6rem;">{ui.pill(label, tone)}'
                    f'{ui.pill(ev["evidence_id"], "neutral", dot=False)}</div>')
                ui.kpi_row([
                    ui.kpi("Acquired by", ui.esc(ev.get("acquired_by", "—")), ui.esc(ev.get("acquired_local", "")),
                           small=True),
                    ui.kpi("Source", ui.esc(origin.get("source_device") or "—"),
                           ui.esc(f"collected by {origin['collected_by']}" if origin.get("collected_by") else ""),
                           small=True),
                    ui.kpi("Size", ei.format_size(ev.get("size") or 0)),
                ])
                ui.render_html(ui.hash_line("SHA-256 at acquisition", ev.get("sha256", "")))
                reports = case_reports(manifest)
                if reports:
                    st.markdown("**Sealed reports**")
                for i, rep in enumerate(reports):
                    c1, c2 = st.columns([4, 1.2], vertical_alignment="center")
                    seal = ("🟢 seal intact" if rep["intact"] else "🔴 modified since sealing" if rep["exists"]
                            else "⚪ file not found")
                    c1.markdown(f"`{rep['name']}` · {rep['time']} · {seal}")
                    if rep["exists"]:
                        with open(rep["path"], "rb") as f:
                            c2.download_button("Download", f.read(), file_name=rep["name"], mime="application/pdf",
                                               icon=":material/download:", width="stretch",
                                               key=f"dl_{ev['evidence_id']}_{i}")

        with st.expander(f"Sessions ({len(rec.get('sessions', []))})", icon=":material/history:"):
            st.dataframe(pd.DataFrame([{
                "Session": s.get("session_id"), "Analyst": s.get("analyst"),
                "Opened": s.get("opened_local", ""), "Closed": s.get("closed_local") or "—",
                "Notes": s.get("notes", ""),
            } for s in rec.get("sessions", [])]), hide_index=True, width="stretch")


def admin_recipient(recipient: dict) -> str:
    return recipient_label(recipient) if recipient else "—"


# ── Authentication & sessions ─────────────────────────────────────────────────
def start_session(user: dict):
    """A successful sign-in starts a fresh, empty workspace."""
    st.session_state.clear()
    st.session_state["auth"] = {
        "username": user["username"], "session_id": uuid.uuid4().hex[:8].upper(),
        "login_ts": time.time(), "last_seen": time.time(), "login_local": ei.local_timestamp(),
    }
    st.session_state["appearance"] = (user.get("preferences") or {}).get("theme", "auto")
    st.session_state["expert_mode"] = (user.get("preferences") or {}).get("view") == "expert"
    auth.audit("LOGIN_SUCCESS", user["username"], role=user["role"],
               session=st.session_state["auth"]["session_id"], client=admin_pages.client_ip())


def end_session(event: str, notice: str = None, level: int = logging.INFO, **fields):
    """Close any open case, record the sign-out and wipe the session state."""
    sess = st.session_state.get("auth")
    if sess:
        close_case_session()
        minutes = (time.time() - sess["login_ts"]) / 60
        auth.audit(event, sess["username"], level, session=sess["session_id"],
                   duration=f"{minutes:.0f} min", client=admin_pages.client_ip(), **fields)
    st.session_state.clear()
    if notice:
        st.session_state["login_notice"] = notice


def current_user():
    """Re-validate the signed-in user on every run (idle timeout, disabled account, role changes)."""
    sess = st.session_state.get("auth")
    if not sess:
        return None
    user = auth.get_user(sess["username"])
    if user is None or not user["active"]:
        end_session("SESSION_REVOKED", "Your account was disabled — contact an administrator.",
                    logging.WARNING, reason="account disabled or removed")
        return None
    if auth.session_expired(sess["last_seen"]):
        idle = datetime.fromtimestamp(sess["last_seen"]).strftime("%H:%M:%S")
        end_session("SESSION_TIMEOUT", f"You were signed out after {auth.IDLE_TIMEOUT_MIN} minutes of inactivity.",
                    idle_since=idle)
        return None
    sess["last_seen"] = time.time()
    st.session_state["auth_user"] = user
    return user


def assistant_context(user: dict) -> dict:
    """
    What the offline assistant may know: progress and a summary of the current
    result (risk, score, top reasons, integrity). Deliberately no hashes, file
    names, provenance or raw evidence.
    """
    evidence, result = st.session_state.get("evidence"), st.session_state.get("current_triage")
    if result and (not evidence or result.get("evidence_key") != evidence.get("key")):
        result = None
    ctx = {
        "role": user["role"], "name": user["full_name"], "username": user["username"],
        "case_open": bool(active_case()), "evidence_loaded": bool(evidence),
        "integrity_ok": evidence["chain"].is_intact if evidence else None,
        "checkpoints": len(evidence["chain"].events) if evidence else 0,
        "validation": (evidence.get("validation") or {}).get("severity") if evidence else None,
        "report_ready": bool(result) and "sha256" in st.session_state.get(f"pdf_ready_{result['evidence_id']}", {}),
        "result": None,
    }
    if result:
        shap_df = result.get("_shap_df")
        drivers = [] if shap_df is None else [
            (r["Plain English Indicator"], r["SHAP Value"] > 0, r["SHAP Value"] * 100)
            for _, r in shap_df.head(3).iterrows()]
        ctx["result"] = {"risk": result["risk"], "score": result["probability"] * 100,
                         "malware": result["probability"] >= 0.5, "anomaly": bool(result["is_anomaly"]),
                         "drivers": drivers, "actions": RESPONSE_ACTIONS[result["risk"]]}
    return ctx


def save_appearance():
    """Remember the chosen Light / Dark / Auto mode on the account (re-select if it was toggled off)."""
    user = st.session_state.get("auth_user") or {}
    saved = (user.get("preferences") or {}).get("theme", "auto")
    choice = st.session_state.get("appearance")
    if choice is None:                      # clicking the active option deselects it - keep the saved mode
        st.session_state["appearance"] = saved
    elif choice != saved and user:
        auth.set_preference(user["username"], "theme", choice)


def save_view():
    """Remember Simple / technical view on the account."""
    user = st.session_state.get("auth_user") or {}
    if user:
        auth.set_preference(user["username"], "view", "expert" if st.session_state.get("expert_mode") else "simple")


def render_user_panel(user: dict):
    with st.sidebar:
        ui.sidebar_brand()
        sess = st.session_state["auth"]
        ui.render_html('<div class="fx-side-label">Signed in</div>'
                       f'<div class="fx-side-row"><span>User</span><span>{ui.esc(user["full_name"])}</span></div>'
                       f'<div class="fx-side-row"><span>Account</span><code>{ui.esc(user["username"])}</code></div>'
                       f'<div class="fx-side-row"><span>Role</span>'
                       f'{ui.pill(admin_pages.ROLE_LABELS[user["role"]], "accent" if user["role"] == "admin" else "neutral")}</div>'
                       f'<div class="fx-side-row"><span>Since</span><span style="font-size:0.85rem;">'
                       f'{ui.esc(sess["login_local"][11:16])}</span></div>')
        ui.render_html('<div class="fx-side-label">Appearance</div>')
        ui.appearance_control("appearance", on_change=save_appearance, compact=True)
        st.toggle("Show technical details", key="expert_mode", on_change=save_view,
                  help="Hashes, custody ledger, explanation charts, data previews and engine status.")
        if st.button("Sign out", icon=":material/logout:", width="stretch", key="sign_out"):
            end_session("LOGOUT", "You have been signed out.")
            st.rerun()


def main():
    st.set_page_config(page_title="HazMem · Memory Forensics", page_icon=ui.ICON_PNG, layout="wide")
    ui.inject_theme()
    ui.inject_background()
    signed_in = "auth" in st.session_state
    ui.inject_appearance(st.session_state.get("appearance" if signed_in else "appearance_login"))

    try:
        if not auth.has_users():
            admin_pages.render_first_run_setup()
            return
        user = current_user()
        if user is None:
            user = admin_pages.render_login()
            if user is None:
                return
            start_session(user)
            st.rerun()
    except auth.UserStoreTampered as e:
        logger.error(f"AUTH | EVENT=USER_STORE_TAMPERED | USER=- | DETAIL={e}")
        st.error(f"**Account store integrity failure.** {e}", icon=":material/gpp_bad:")
        return

    if user.get("must_change_password"):
        render_user_panel(user)
        ui.section("Set a new password", "Required before first use of this account.", "key")
        admin_pages.render_password_change(user, forced=True)
        return

    PAGES["triage"] = st.Page(triage_page, title="Analyse", icon=":material/biotech:", url_path="triage", default=True)
    pages = [PAGES["triage"],
             st.Page(cases_page, title="Cases", icon=":material/folder_shared:", url_path="cases"),
             st.Page(hash_checker.render_hash_checker_page, title="Hash checker", icon=":material/fingerprint:",
                     url_path="hash-checker")]
    if user["role"] == "admin":
        pages += [st.Page(admin_pages.render_audit_page, title="Audit log", icon=":material/policy:", url_path="audit"),
                  st.Page(admin_pages.render_users_page, title="Users", icon=":material/group:", url_path="users")]
    pages += [st.Page(admin_pages.render_account_page, title="Account", icon=":material/person:",
                      url_path="account"),
              st.Page(help_page.render_help_page, title="Help", icon=":material/help:", url_path="help")]
    page = st.navigation(pages, position="top")
    render_user_panel(user)
    page.run()
    assistant.render(assistant_context(user))   # after the page, so it sees this run's result


# ── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    from streamlit.runtime import exists

    if exists():
        main()
    else:
        # Enables running `python app.py` directly or clicking VS Code 'Run' button
        from streamlit.web import cli as stcli
        sys.argv = ["streamlit", "run", os.path.abspath(__file__)]
        sys.exit(stcli.main())
