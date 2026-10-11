# =============================================================================
# MEMORY FORENSIC TRIAGE SYSTEM — app.py
# Explainable AI Dashboard with SHAP, LIME, Audit Logging, PDF Reports
# =============================================================================

# ── SECTION 1: IMPORTS ───────────────────────────────────────────────────────
import os
import re
import json
import uuid
import html
import logging
import hashlib
import time
import shutil
from datetime import datetime

import numpy as np
import pandas as pd
import shap
from lime.lime_tabular import LimeTabularExplainer

import streamlit as st

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

import altair as alt

import memdump_extractor
import ui_theme as ui
import evidence_integrity as ei
import input_validation as iv
import audit_log
import auth
import admin_pages


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
OUTPUT_DIR  = os.path.join(BASE_DIR, "outputs")
LOG_DIR     = os.path.join(BASE_DIR, "logs")
SAMPLES_DIR = os.path.join(DATA_DIR, "test_samples")
CASES_DIR   = os.path.join(OUTPUT_DIR, "cases")   # per-case evidence copies, CSVs, manifests

# Create folders if they don't exist yet
os.makedirs(OUTPUT_DIR,  exist_ok=True)
os.makedirs(LOG_DIR,     exist_ok=True)
os.makedirs(SAMPLES_DIR, exist_ok=True)


# ── SECTION 3: AUDIT LOGGER SETUP ────────────────────────────────────────────
# Every prediction is written to a log file with timestamp
# This is chain-of-custody — a record of every analysis ever run.
# Each line is HMAC-chained to the previous one (see audit_log.py).
AUDIT_LOG_PATH = os.environ.get("MEMTRIAGE_AUDIT_LOG") or os.path.join(LOG_DIR, "triage_audit.log")
audit_log.setup(AUDIT_LOG_PATH)
logger = logging.getLogger("triage")
admin_pages.AUDIT_LOG_PATH = AUDIT_LOG_PATH


# ── SECTION 4: FORENSIC FEATURE DICTIONARY & HUMAN TRANSLATOR ────────────────
# Translates raw Volatility memory artifacts into plain English for non-technical users & analysts
FEATURE_MEANINGS = {
    "svcscan.nservices": {
        "title": "Windows System Services Count",
        "desc": "Number of background services registered in the system service database.",
        "danger": "Malware registers hidden services for persistence or disables security tools."
    },
    "svcscan.shared_process_services": {
        "title": "Shared Service Host Processes (svchost)",
        "desc": "Count of background services sharing standard Windows svchost.exe processes.",
        "danger": "Fileless malware hijacks legitimate svchost process pools to hide covert operations."
    },
    "svcscan.process_services": {
        "title": "Dedicated Process Services",
        "desc": "Windows services operating inside their own dedicated background processes.",
        "danger": "Unusual counts often reveal persistent backdoor utilities running as services."
    },
    "svcscan.kernel_drivers": {
        "title": "Kernel Driver Registrations",
        "desc": "System records tracking active Windows ring-0 kernel drivers.",
        "danger": "Rootkits load unsigned or vulnerable drivers to bypass all endpoint security controls."
    },
    "handles.avg_handles_per_proc": {
        "title": "Average Resource Handles per Process",
        "desc": "Rate of files, keys, and sockets actively accessed by running applications.",
        "danger": "Spikes indicate aggressive file enumeration, ransomware sweeps, or spyware data harvesting."
    },
    "handles.nhandles": {
        "title": "Total Open Resource Handles",
        "desc": "Overall volume of operating system resource handles allocated in memory.",
        "danger": "Massive handle counts reflect rapid filesystem traversals or memory leak exploits."
    },
    "handles.nfile": {
        "title": "Active File Access Handles",
        "desc": "Number of open file descriptors maintained across all running processes.",
        "danger": "Ransomware encrypting files or exfiltration utilities generate abnormal file handles."
    },
    "handles.nevent": {
        "title": "Thread Synchronization Events",
        "desc": "Internal Windows event signaling objects used for inter-thread coordination.",
        "danger": "Malware synchronization routines, command beacons, and injected loaders alter event counts."
    },
    "handles.nmutant": {
        "title": "Mutex (Mutant) Synchronization Objects",
        "desc": "Mutual exclusion objects used by software to ensure only one instance runs.",
        "danger": "Trojans and ransomware commonly register unique hardcoded Mutexes to avoid re-infection."
    },
    "handles.nsection": {
        "title": "Shared Memory Section Handles",
        "desc": "Shared memory mappings used to exchange data or execute shared code.",
        "danger": "Attackers map shared memory sections to inject shellcode across process boundaries."
    },
    "handles.nthread": {
        "title": "Active Execution Thread Handles",
        "desc": "System references to running CPU execution threads.",
        "danger": "High counts indicate thread injection, reflective loaders, or covert beacon loops."
    },
    "pslist.avg_threads": {
        "title": "Process Thread Concurrency Density",
        "desc": "Average execution threads running concurrently inside each active process.",
        "danger": "Atypical thread density points to injected shellcode, cryptominers, or active C2 beacons."
    },
    "pslist.nproc": {
        "title": "Total Active Process Count",
        "desc": "Number of active applications and background programs running in memory.",
        "danger": "Abnormal drops (killed security software) or spikes (malware tools) signal an intrusion."
    },
    "pslist.nppid": {
        "title": "Parent-Child Process Tree Hierarchy (PPID)",
        "desc": "Authentic parentage tree showing which application launched each child program.",
        "danger": "PPID spoofing disguises malicious tools to appear as if launched by legitimate Windows parents."
    },
    "malfind.ninjections": {
        "title": "Direct Memory Code Injections",
        "desc": "Executable memory regions detected floating in RAM with no file on the hard drive.",
        "danger": "Strongest indicator of fileless malware, Cobalt Strike beacons, or in-memory shellcode payloads."
    },
    "malfind.commitCharge": {
        "title": "Injected Memory Committed Pages",
        "desc": "Physical RAM pages committed to suspicious unbacked executable memory regions.",
        "danger": "Directly indicates the size and memory footprint of an active in-memory exploit."
    },
    "malfind.protection": {
        "title": "Executable Memory Permissions (PAGE_EXECUTE)",
        "desc": "Virtual memory regions marked with Read-Write-Execute (RWX) permissions.",
        "danger": "Self-modifying exploits and loaders require RWX permissions to unpack malware in memory."
    },
    "psxview.not_in_eprocess": {
        "title": "Hidden Unlinked Process (DKOM Rootkit)",
        "desc": "A process exists in low-level CPU scheduler memory but was unlinked from the official task list.",
        "danger": "Rootkits use Direct Kernel Object Manipulation (DKOM) to hide malware from Task Manager & antivirus."
    },
    "psxview.not_in_pspCidTable": {
        "title": "Process Hidden from Handle Table",
        "desc": "Process present in scheduler structures but omitted from the kernel CID handle table.",
        "danger": "High-stealth evasion technique designed to conceal active backdoor processes."
    },
    "ldrmodules.not_in_load": {
        "title": "Reflective DLL Module Injection",
        "desc": "A dynamic link library is executing in RAM without being registered in standard Windows load tables.",
        "danger": "Hallmark signature of reflective DLL injection running completely fileless in physical memory."
    },
    "ldrmodules.not_in_init": {
        "title": "Uninitialized Memory Module",
        "desc": "A code module mapped into memory without completing standard Windows OS initialization.",
        "danger": "Stealth module loading bypassing standard operating system safety checks."
    },
    "dlllist.avg_dlls_per_proc": {
        "title": "Average Loaded DLLs per Process",
        "desc": "Number of dynamic link library modules linked into active software.",
        "danger": "DLL search-order hijacking and side-loading attacks inflate loaded DLL counts."
    },
    "dlllist.ndlls": {
        "title": "Total Loaded DLL Modules",
        "desc": "Overall count of dynamic libraries mapped across all system memory spaces.",
        "danger": "Large variations indicate widespread library tampering across running utilities."
    },
    "callbacks.ncallbacks": {
        "title": "Kernel Callback Notification Routines",
        "desc": "Low-level system notification hooks registered by drivers to monitor OS events.",
        "danger": "Evasion modules and rootkits install callbacks to monitor or blind security scanners."
    },
    "callbacks.nanonymous": {
        "title": "Anonymous Kernel Callbacks",
        "desc": "Kernel callback pointers referencing raw memory not belonging to any known driver on disk.",
        "danger": "Severe rootkit indicator: malicious code executing directly within kernel space."
    }
}

def get_feature_info(raw_name: str) -> dict:
    """Returns human-friendly title, description, and threat context for any Volatility feature."""
    tokens = re.findall(r'[a-zA-Z][a-zA-Z0-9_\.]*', str(raw_name))
    clean = tokens[0] if tokens else str(raw_name).strip()
    clean_dot = clean.replace('_', '.')
    clean_under = clean.replace('.', '_')
    
    for key in (clean, clean_dot, clean_under):
        if key in FEATURE_MEANINGS:
            return FEATURE_MEANINGS[key]
            
    prefix = clean.split('.')[0].lower()
    fallbacks = {
        "svcscan": {
            "title": f"Windows Service Telemetry ({clean})",
            "desc": "Metrics tracking background Windows services and their host process configurations.",
            "danger": "Altered service telemetry may indicate persistence setups or stopped security tools."
        },
        "handles": {
            "title": f"Resource Handle Allocation ({clean})",
            "desc": "Telemetry measuring file, registry, and memory handle allocation rates.",
            "danger": "Unusual handle usage indicates aggressive file scanning, credential theft, or memory tampering."
        },
        "pslist": {
            "title": f"Process & Thread Hierarchy ({clean})",
            "desc": "Operating system process scheduling, execution threads, and task allocations.",
            "danger": "Irregularities reflect injected background processes, spoofed parentage, or hidden tools."
        },
        "malfind": {
            "title": f"Memory Injection Signature ({clean})",
            "desc": "Detection of executable memory regions lacking disk image backing.",
            "danger": "Hallmark sign of in-memory beacons, unpackers, or injected shellcode."
        },
        "callbacks": {
            "title": f"Kernel Callback Routine ({clean})",
            "desc": "Low-level event notification routines registered with the Windows kernel.",
            "danger": "Rogue callbacks are employed by rootkits to evade AV detection or blind endpoint sensors."
        },
        "dlllist": {
            "title": f"Dynamic Link Library (DLL) Telemetry ({clean})",
            "desc": "Dynamic shared libraries loaded into process memory spaces.",
            "danger": "Deviations indicate module hijacking, rogue DLL injection, or sideloaded malware."
        },
        "ldrmodules": {
            "title": f"Module Loader Tracking ({clean})",
            "desc": "Internal Windows loader tables accounting for active process modules.",
            "danger": "Unlinked modules indicate reflective code injection running completely in physical RAM."
        },
        "psxview": {
            "title": f"Cross-View Process Inspection ({clean})",
            "desc": "Multi-table cross-validation of active processes to detect unlinked rootkits.",
            "danger": "Discrepancies indicate hidden processes obscured via Direct Kernel Object Manipulation (DKOM)."
        }
    }
    
    if prefix in fallbacks:
        return fallbacks[prefix]
        
    return {
        "title": f"Memory Artifact: {clean}",
        "desc": f"Observed variance in RAM telemetry metric '{clean}'.",
        "danger": "Telemetry value deviates from verified clean baseline operating parameters."
    }

# Risk-level colours used in Streamlit status boxes
RISK_COLOURS = {
    "HIGH RISK":   "red",
    "SUSPICIOUS":  "orange",
    "NORMAL":      "green",
}

# Incident response recommendations per risk tier
RESPONSE_ACTIONS = {
    "HIGH RISK": [
        "🔴 Isolate endpoint from network immediately",
        "🔴 Preserve full memory dump using Volatility3 or WinPmem",
        "🔴 Extract and hash all injected process regions",
        "🔴 Escalate to Tier 2 analyst and open incident ticket",
        "🔴 Correlate with SIEM and threat intelligence feeds",
    ],
    "SUSPICIOUS": [
        "🟡 Do NOT take automated action — human review required",
        "🟡 Run additional Volatility plugins: malfind, pstree, netscan",
        "🟡 Compare process tree against known-good baseline",
        "🟡 Submit sample to sandbox (Any.run / Hybrid Analysis)",
    ],
    "NORMAL": [
        "🟢 No immediate action required",
        "🟢 Continue standard monitoring schedule",
        "🟢 Archive this triage result for baseline comparison",
    ],
}


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
    if prob >= 0.75:
        risk = "HIGH RISK"
    elif prob >= 0.40:
        risk = "SUSPICIOUS"
    else:
        risk = "NORMAL"

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
                axis=alt.Axis(labelLimit=340, labelFontSize=14, labelColor=ui.TEXT_2, ticks=False, domain=False,
                              labelPadding=10)),
        x=alt.X("Contribution:Q", title=x_title,
                axis=alt.Axis(labelFontSize=13, titleFontSize=14, titleColor=ui.TEXT_2, labelColor=ui.MUTED,
                              gridColor=ui.BORDER, domain=False, tickColor=ui.BORDER, format="+.1f")),
        color=alt.Color("Direction:N",
                        scale=alt.Scale(domain=["Toward malware", "Toward benign"],
                                        range=[ui.TOWARD_MALWARE, ui.TOWARD_BENIGN]),
                        legend=alt.Legend(orient="top", title=None, labelFontSize=14, labelColor=ui.TEXT_2,
                                          symbolType="square", symbolSize=180)),
        tooltip=[
            alt.Tooltip("Indicator:N"),
            alt.Tooltip("Metric:N", title="Volatility metric"),
            alt.Tooltip("Contribution:Q", title="Contribution (%)", format="+.2f"),
            alt.Tooltip("Direction:N"),
        ],
    )
    zero = alt.Chart(pd.DataFrame({"x": [0]})).mark_rule(color=ui.MUTED, strokeWidth=1).encode(x="x:Q")
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


# ── SECTION 9: PDF REPORT GENERATOR ──────────────────────────────────────────

def generate_pdf_report(result: dict, shap_df: pd.DataFrame = None, lime_df: pd.DataFrame = None,
                        chain: "ei.CustodyChain" = None):
    """
    Build a comprehensive forensic PDF incident brief and save it to outputs/.
    Returns (output_path, pdf_bytes) so the dashboard can offer immediate download.
    Includes full explainability findings (SHAP global attribution + LIME local rules)
    translated into plain English for non-technical users and forensic investigators.
    """
    timestamp_clean = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename        = f"forensic_report_{result['evidence_id']}_{timestamp_clean}.pdf"
    output_path     = os.path.join(OUTPUT_DIR, filename)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    styles = getSampleStyleSheet()

    # Custom Report Typography
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=15,
        leading=18,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=2
    )
    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=8
    )
    h2_style = ParagraphStyle(
        'DocH2',
        parent=styles['Heading2'],
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=6,
        spaceAfter=3
    )
    cell_style = ParagraphStyle(
        'CellNorm',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#334155')
    )
    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#1E293B')
    )
    cell_danger = ParagraphStyle(
        'CellDanger',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#DC2626')
    )
    cell_warning = ParagraphStyle(
        'CellWarning',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#D97706')
    )
    cell_normal = ParagraphStyle(
        'CellNormal',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#16A34A')
    )

    cell_header = ParagraphStyle('CellHeader', parent=cell_bold, textColor=colors.white)

    def xml_esc(val):
        """Escape XML entities for ReportLab Paragraph rendering."""
        return html.escape(str(val) if val is not None else "", quote=False)

    story = []

    # ── Header ────────────────────────────────────────────────
    story.append(Paragraph("MEMORY FORENSIC TRIAGE &amp; XAI INVESTIGATION REPORT", title_style))
    story.append(Paragraph("Explainable AI Memory Forensics Framework &bull; Autonomous Telemetry Analysis &bull; Confidential", subtitle_style))

    # ── 1. Chain of custody ───────────────────────────────────
    story.append(Paragraph("1. Chain of Custody &amp; Evidence Metadata", h2_style))
    r_idx = result["row_index"]
    n_feat = len(result.get("feature_cols", []))
    integ = result.get("integrity", {}) or {}
    hash_style = ParagraphStyle('HashMono', parent=cell_style, fontName='Courier', fontSize=7.2, leading=9)
    meta_data = [
        [Paragraph("Case Number", cell_bold), Paragraph(xml_esc(integ.get("case_id", "N/A")), cell_style)],
        [Paragraph("Examiner / Analyst", cell_bold), Paragraph(
            xml_esc(integ.get("analyst", "N/A") + (f" ({integ['organisation']})" if integ.get("organisation") else "")),
            cell_style)],
        [Paragraph("Case Session", cell_bold), Paragraph(
            xml_esc(f"{integ.get('session_id', '')} - opened {integ.get('session_opened', '')}"), cell_style)],
        [Paragraph("Evidence Item ID", cell_bold), Paragraph(xml_esc(integ.get("evidence_item_id", "N/A")), cell_style)],
        [Paragraph("Analysis ID", cell_bold), Paragraph(xml_esc(result["evidence_id"]), cell_style)],
        [Paragraph("Analysis Timestamp", cell_bold), Paragraph(xml_esc(result["timestamp"]), cell_style)],
        [Paragraph("Source Evidence File", cell_bold), Paragraph(
            f"{xml_esc(result['source_file'])} ({xml_esc(integ.get('evidence_kind', ''))}, "
            f"{ei.format_size(integ.get('evidence_size', 0) or 0)})", cell_style)],
        [Paragraph("Evidence Origin", cell_bold), Paragraph(xml_esc(
            (lambda o: f"{o.get('source_device', 'N/A')}"
                       f"{(' - custodian ' + o['custodian']) if o.get('custodian') else ''}"
                       f"{(' - ' + o['location']) if o.get('location') else ''}")(
                (integ.get("provenance") or {}).get("origin") or {})), cell_style)],
        [Paragraph("Collected By / When / Tool", cell_bold), Paragraph(xml_esc(
            (lambda o: f"{o.get('collected_by', 'N/A')} - {o.get('collected_at', 'N/A')} - "
                       f"{o.get('acquisition_tool', 'N/A')}")(
                (integ.get("provenance") or {}).get("origin") or {})), cell_style)],
        [Paragraph("Prepared For", cell_bold), Paragraph(xml_esc(
            (lambda r: f"{recipient_label(r)} - {r.get('purpose', 'N/A')}"
                       f"{(' - ref ' + r['reference']) if r.get('reference') else ''}")(
                (integ.get("provenance") or {}).get("prepared_for") or {})), cell_style)],
        [Paragraph("Evidence SHA-256", cell_bold), Paragraph(xml_esc(integ.get("evidence_sha256", "N/A")), hash_style)],
        [Paragraph("Evidence MD5", cell_bold), Paragraph(xml_esc(integ.get("evidence_md5", "N/A")), hash_style)],
    ]
    if integ.get("csv_sha256"):
        meta_data.append([Paragraph("Derived Feature CSV SHA-256", cell_bold), Paragraph(
            f"{xml_esc(integ['csv_sha256'])}<br/><font face='Helvetica'>{xml_esc(integ.get('csv_name', ''))}</font>",
            hash_style)])
    meta_data += [
        [Paragraph("Analysed Vector SHA-256", cell_bold), Paragraph(xml_esc(integ.get("vector_sha256", "N/A")), hash_style)],
        [Paragraph("Evaluated Record / Row", cell_bold), Paragraph(f"Row {r_idx}", cell_style)],
        [Paragraph("Telemetry Features", cell_bold), Paragraph(f"{n_feat} memory telemetry indicators", cell_style)],
        [Paragraph("Input Validation", cell_bold), Paragraph(xml_esc(integ.get("input_validation") or "N/A"),
                                                              cell_style if integ.get("input_validation", "").startswith("PASSED")
                                                              else cell_warning)],
        [Paragraph("Analysis Engines", cell_bold), Paragraph("Random Forest Classifier (150 trees) + Isolation Forest (Zero-Day Anomaly Detector)", cell_style)],
    ]
    if chain is not None:
        n_match = sum(e["status"] == ei.STATUS_MATCH for e in chain.events)
        integrity_text = (
            f"VERIFIED - {n_match} re-verification(s) across {len(chain.events)} custody checkpoints match the "
            f"acquisition hashes; ledger hash-links intact. Evidence was not modified by this tool."
            if chain.is_intact else
            "COMPROMISED - one or more hash re-verifications did not match. See Section 7."
        )
        meta_data.append([Paragraph("Integrity Status", cell_bold),
                          Paragraph(xml_esc(integrity_text), cell_normal if chain.is_intact else cell_danger)])
    meta_table = Table(meta_data, colWidths=[140, 400])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 6))

    # ── 2. Verdict ────────────────────────────────────────────
    story.append(Paragraph("2. Automated Forensic Triage Verdict", h2_style))
    risk_style = (
        cell_danger if result["risk"] == "HIGH RISK" else
        cell_warning if result["risk"] == "SUSPICIOUS" else
        cell_normal
    )
    anomaly_text = (
        "ANOMALY DETECTED (Memory profile deviates significantly from known baseline - potential zero-day)"
        if result.get("is_anomaly")
        else "No novel memory anomaly detected (consistent with baseline distributions)"
    )
    anomaly_style = cell_danger if result.get("is_anomaly") else cell_style
    p_conf = result["probability"] * 100

    verdict_data = [
        [Paragraph("Risk Classification", cell_bold), Paragraph(xml_esc(result["risk"]), risk_style)],
        [Paragraph("Malware Confidence", cell_bold), Paragraph(f"{p_conf:.2f}%", cell_style)],
        [Paragraph("Primary Prediction", cell_bold), Paragraph("MALWARE" if result["prediction"] else "BENIGN", risk_style)],
        [Paragraph("Zero-Day Anomaly Check", cell_bold), Paragraph(xml_esc(anomaly_text), anomaly_style)],
    ]
    verdict_table = Table(verdict_data, colWidths=[140, 400])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 6))

    # ── 3. SHAP ───────────────────────────────────────────────
    story.append(Paragraph("3. Explainable AI: Key Decision Drivers (SHAP Global Attribution)", h2_style))
    if shap_df is not None and not shap_df.empty:
        shap_table_data = [
            [
                Paragraph("Plain-English Indicator", cell_header),
                Paragraph("Telemetry Metric", cell_header),
                Paragraph("Verdict Impact", cell_header),
                Paragraph("Forensic Meaning &amp; Threat Danger", cell_header)
            ]
        ]
        for _, row in shap_df.head(5).iterrows():
            is_mal = row["SHAP Value"] > 0
            imp_style = cell_danger if is_mal else cell_normal
            sv = row["SHAP Value"] * 100
            imp_text = f"+{sv:.1f}% (Malware)" if is_mal else f"{sv:.1f}% (Benign)"
            desc = row.get("What This Is", "")
            dng = row.get("Forensic Context", "")
            explanation = f"{desc} Threat Context: {dng}"
            shap_table_data.append([
                Paragraph(xml_esc(row["Plain English Indicator"]), cell_bold),
                Paragraph(xml_esc(row["Technical Metric"]), cell_style),
                Paragraph(imp_text, imp_style),
                Paragraph(xml_esc(explanation), cell_style),
            ])
        shap_table = Table(shap_table_data, colWidths=[130, 95, 95, 220])
        shap_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(shap_table)
    else:
        story.append(Paragraph("SHAP global attribution details not available for this run.", cell_style))
    story.append(Spacer(1, 6))

    # ── 4. LIME ───────────────────────────────────────────────
    story.append(Paragraph("4. Explainable AI: Corroborating Evidence (LIME Local Rules)", h2_style))
    if lime_df is not None and not lime_df.empty:
        lime_table_data = [
            [
                Paragraph("Plain-English Indicator", cell_header),
                Paragraph("Observed Telemetry Rule", cell_header),
                Paragraph("Local Weight", cell_header),
                Paragraph("Forensic Interpretation", cell_header)
            ]
        ]
        for _, row in lime_df.head(4).iterrows():
            is_mal = row["LIME Weight"] > 0
            w_style = cell_danger if is_mal else cell_normal
            lw = row["LIME Weight"] * 100
            w_text = f"+{lw:.1f}% (Malware)" if is_mal else f"{lw:.1f}% (Benign)"
            obs_cond = str(row.get("Observed Condition", ""))
            desc = row.get("What This Means", "")
            dng = row.get("Forensic Context", "")
            explanation = f"{desc} Danger: {dng}"
            lime_table_data.append([
                Paragraph(xml_esc(row["Plain English Indicator"]), cell_bold),
                Paragraph(xml_esc(obs_cond), cell_style),
                Paragraph(w_text, w_style),
                Paragraph(xml_esc(explanation), cell_style),
            ])
        lime_table = Table(lime_table_data, colWidths=[130, 110, 80, 220])
        lime_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(lime_table)
    else:
        story.append(Paragraph("LIME local decision rule data not available for this run.", cell_style))
    story.append(Spacer(1, 6))

    # ── 5. Incident response ──────────────────────────────────
    story.append(Paragraph("5. Recommended Incident Response Playbook", h2_style))
    actions = RESPONSE_ACTIONS.get(result["risk"], [])
    for act in actions:
        clean_act = re.sub(r'^[^\w\s]+', '', act).strip()
        story.append(Paragraph(f"&bull; {xml_esc(clean_act)}", cell_style))
    story.append(Spacer(1, 6))

    # ── 6. Disclaimer ─────────────────────────────────────────
    story.append(Paragraph("6. Legal &amp; Forensic Disclaimer", h2_style))
    story.append(Paragraph(
        "This triage report is generated by an Explainable AI Memory Forensics System to assist incident "
        "responders and forensic investigators. Automated assessments do not constitute sole definitive "
        "legal evidence. All findings must be corroborated by a qualified human forensic analyst.",
        cell_style
    ))

    # ── 7. Evidence integrity ledger ──────────────────────────
    if chain is not None:
        story.append(Spacer(1, 6))
        story.append(Paragraph("7. Evidence Integrity Verification &amp; Chain-of-Custody Ledger", h2_style))
        story.append(Paragraph(
            "Every artefact handled by the tool was hashed (SHA-256) when first received and re-hashed at each "
            "processing stage. MATCH means the recomputed hash equals the hash recorded at acquisition. Each "
            "ledger entry is chained to the previous entry by an HMAC-SHA256 link keyed with the lab's secret "
            f"ledger key (key ID {xml_esc(ei.ledger_key_id())}), so the ledger cannot be altered and re-chained "
            "without that key.",
            cell_style
        ))
        story.append(Spacer(1, 4))
        ledger_style = ParagraphStyle('Ledger', parent=cell_style, fontSize=6.6, leading=8.2)
        ledger_hash  = ParagraphStyle('LedgerHash', parent=ledger_style, fontName='Courier', fontSize=6.2, leading=7.8)
        ledger_data = [[Paragraph(h, cell_bold) for h in ("#", "Time (UTC)", "Stage / Action", "Artefact", "SHA-256", "Status")]]
        status_styles = {ei.STATUS_MATCH: cell_normal, ei.STATUS_MISMATCH: cell_danger, ei.STATUS_MISSING: cell_warning}
        for e in chain.events:
            ledger_data.append([
                Paragraph(str(e["seq"]), ledger_style),
                Paragraph(xml_esc(e["timestamp"].replace(" UTC", "")), ledger_style),
                Paragraph(f"<b>{xml_esc(e['stage'])}</b><br/>{xml_esc(e['action'])}", ledger_style),
                Paragraph(xml_esc(e["artifact"]), ledger_style),
                Paragraph(xml_esc(e["sha256"] or "-"), ledger_hash),
                Paragraph(xml_esc(e["status"]), status_styles.get(e["status"], cell_bold)),
            ])
        ledger_table = Table(ledger_data, colWidths=[18, 62, 150, 85, 165, 60], repeatRows=1)
        ledger_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(ledger_table)
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f"Ledger head hash: <font face='Courier'>{xml_esc(chain.head_hash)}</font><br/>"
            "Report seal: a document cannot contain its own hash. The SHA-256 of this PDF is computed immediately "
            "after generation and recorded in the custody manifest (custody_manifest.json), the audit log "
            "(logs/triage_audit.log) and a '&lt;report&gt;.pdf.sha256' sidecar file. To verify this copy, run "
            "<font face='Courier'>certutil -hashfile &lt;report.pdf&gt; SHA256</font> (Windows) or "
            "<font face='Courier'>sha256sum &lt;report.pdf&gt;</font> and compare with those records.",
            cell_style
        ))

    # ── Examiner declaration ──────────────────────────────────
    story.append(Spacer(1, 10))
    story.append(Paragraph("Examiner Declaration", h2_style))
    story.append(Paragraph(
        f"I, {xml_esc(integ.get('analyst', '________________'))}, examined the evidence listed above under case "
        f"{xml_esc(integ.get('case_id', '________'))}. The findings in this report were produced by the tool "
        "and reviewed by me.", cell_style))
    story.append(Spacer(1, 16))
    story.append(Paragraph("Signature: ______________________________ &nbsp;&nbsp;&nbsp; Date: ________________", cell_style))

    # Build document
    doc.build(story)

    # Read binary bytes for Streamlit download button
    with open(output_path, "rb") as f:
        pdf_bytes = f.read()

    logger.info(f"PDF report saved: {output_path} | EVIDENCE_ID={result['evidence_id']}")
    return output_path, pdf_bytes


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


def render_case_session():
    """Mandatory case session gate. Returns the active session or None."""
    session = active_case()
    if session:
        org = f" · {ui.esc(session['organisation'])}" if session["organisation"] else ""
        previous = (f" · continues case ({session['prior_sessions']} earlier session"
                    f"{'s' if session['prior_sessions'] != 1 else ''})" if session["prior_sessions"] else "")
        col_info, col_close = st.columns([4.2, 1.2], vertical_alignment="center")
        with col_info:
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
        with col_close:
            if st.button("Close case", width="stretch", icon=":material/lock:"):
                close_case_session()
                st.toast("Case session closed and logged", icon="🔒")
                st.rerun()
        return session

    with st.form("open_case_form", border=False):
        c1, c2 = st.columns(2)
        with c1:
            case_number = st.text_input("Case number *", value=ei.suggest_case_number(),
                                        help="Your lab's case reference. Letters, digits, - _ . / (3-40 characters).")
            organisation = st.text_input("Unit / organisation", placeholder="e.g. CSIRT, DFIR Lab")
        with c2:
            user = st.session_state["auth_user"]
            analyst = f"{user['full_name']} ({user['username']})"
            st.text_input("Analyst (signed-in account)", value=analyst, disabled=True,
                          help="Case actions are attributed to the authenticated user.")
            notes = st.text_input("Case notes", placeholder="e.g. Suspected ransomware on HR-PC-07")
        st.markdown("**Prepared for** — who will receive the findings and evidence")
        r1, r2, r3, r4 = st.columns([1.2, 1.2, 1.1, 0.9])
        recipient_name = r1.text_input("Recipient *", placeholder="e.g. DCI Sarah Khan")
        recipient_org  = r2.text_input("Recipient organisation", placeholder="e.g. Metro Police Cyber Unit")
        purpose        = r3.selectbox("Purpose", PURPOSES)
        reference      = r4.text_input("Request / reference no.", placeholder="e.g. REQ-2026-114")
        st.caption(f"The session start time is recorded automatically: **{ei.local_timestamp()}** "
                   f"(every custody event is also stamped in UTC).")
        submitted = st.form_submit_button("Open case session", type="primary", icon=":material/folder_open:")

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


def recipient_label(recipient: dict) -> str:
    name, org = recipient.get("name", ""), recipient.get("organisation", "")
    return f"{name} ({org})" if name and org else name or org or "-"


def origin_label(origin: dict) -> str:
    who = f" (custodian: {origin['custodian']})" if origin.get("custodian") else ""
    return f"{origin.get('source_device', '-')}{who}"


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
        st.info(f"**{dump_name}** passed intake checks ({dump_format}, {ei.format_size(dump_size)}). "
                f"Extraction runs 9 Volatility plugins and can take a few minutes.",
                icon=":material/memory:")
        if not st.button("Extract features", type="primary", icon=":material/memory:"):
            return None

        progress_bar = st.progress(0.0, text="Computing acquisition hash of memory image (SHA-256 + MD5)...")
        try:
            if uploaded_dump is not None:
                chain = open_case(dump_name, "memory-dump", ei.hash_stream(uploaded_dump),
                                  "Memory image received via dashboard upload",
                                  details=f"Hash computed over the exact bytes received from the analyst | "
                                          f"Intake check: {dump_format}")
                progress_bar.progress(0.02, text="Writing write-protected working copy of the memory image...")
                dump_path = preserve_upload(chain, uploaded_dump)
            else:
                dump_path = os.path.abspath(local_path)
                chain = open_case(dump_name, "memory-dump", ei.hash_file(dump_path),
                                  "Memory image referenced in place (read-only, not copied)",
                                  details=f"Source path: {dump_path} | Intake check: {dump_format}")

            logger.info(f"Memory dump extraction started: CASE={chain.case_id} | {dump_name}")
            _, csv_path, report = memdump_extractor.extract_features(
                dump_path,
                out_dir     = os.path.dirname(case_path(chain, "extraction", "_")),
                progress_cb = lambda frac, msg: progress_bar.progress(min(frac, 1.0), text=msg),
            )
        except memdump_extractor.ExtractionError as e:
            progress_bar.empty()
            logger.error(f"Memory dump extraction failed for {dump_name}: {e}")
            st.error(f"❌ {e}")
            return None
        progress_bar.empty()

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

        with open(ctx["csv_path"], "rb") as f:
            st.download_button("Download extracted CSV", data=f.read(), icon=":material/download:",
                               file_name=os.path.basename(ctx["csv_path"]), mime="text/csv")

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
        ui.kpi("Evidence file", ui.esc(ctx["name"]), KIND_LABELS.get(ctx["kind"], ctx["kind"]), small=True, wide=True),
        ui.kpi("Size", ei.format_size(ev.get("size", 0) or 0)),
        ui.kpi("Records", f"{len(df):,}", f"{len(df.columns)} features each"),
        ui.kpi("Integrity", integrity, f"{len(chain.events)} checkpoints"),
    ])
    hashes = (ui.hash_line("Evidence item ID", chain.evidence_id)
              + ui.hash_line("Evidence SHA-256", ev.get("sha256", "")) + ui.hash_line("Evidence MD5", ev.get("md5", "")))
    if csv:
        hashes += ui.hash_line(f"Derived CSV SHA-256 · {csv.get('artifact', '')}", csv.get("sha256", ""))
    ui.render_html(f'<div class="fx-card" style="margin: 0.8rem 0 0.9rem; padding-top: 0.4rem;">{hashes}</div>')
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
        st.success(f"**Input validation passed** — all {report['expected']} model features present, numeric, "
                   f"finite and non-negative.", icon=":material/fact_check:")
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
    with st.expander("Evidence origin — where did this evidence come from?", icon=":material/travel_explore:",
                     expanded=source != "sample"):
        c1, c2, c3 = st.columns(3)
        device    = c1.text_input("Source device / host *", value=defaults.get("source_device", ""),
                                  placeholder="e.g. HR-PC-07 (Dell OptiPlex, S/N 4XK2)", key=k("device"))
        custodian = c2.text_input("Owner / custodian", value=defaults.get("custodian", ""),
                                  placeholder="e.g. John Smith, HR department", key=k("custodian"))
        location  = c3.text_input("Collected from (location)", value=defaults.get("location", ""),
                                  placeholder="e.g. HQ, 3rd floor, desk 14", key=k("location"))
        c4, c5, c6, c7 = st.columns([1.3, 1, 0.8, 1.3])
        collector = c4.text_input("Collected by *", value=defaults.get("collected_by", ""),
                                  placeholder="Name of the person who acquired it", key=k("collector"))
        day       = c5.date_input("Collection date", key=k("date"))
        at        = c6.time_input("Time", key=k("time"))
        tool      = c7.selectbox("Acquisition tool", ACQUISITION_TOOLS, key=k("tool"),
                                 index=ACQUISITION_TOOLS.index(defaults.get("acquisition_tool", "DumpIt")))
        notes     = st.text_input("Origin notes", placeholder="e.g. Seized under warrant 22/114; machine was running",
                                  key=k("notes"))
        st.caption("Recorded in the custody ledger when the evidence is acquired. Changes made afterwards apply "
                   "to the next evidence item only.")
    if len(device.strip()) < 2 or len(collector.strip()) < 2:
        st.session_state.pop("pending_origin", None)
        return None
    collected_at = datetime.combine(day, at).astimezone()
    origin = {
        "source_device": device.strip(), "custodian": custodian.strip(), "location": location.strip(),
        "collected_by": " ".join(collector.split()), "acquisition_tool": tool, "notes": notes.strip(),
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
        format_func={"sample": ":material/science: Sample profile", "csv": ":material/table_view: Volatility CSV",
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
        selected = st.selectbox("Sample memory profile", available, format_func=lambda s: SAMPLE_PRESETS.get(s, s))
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


def run_selected_triage(evidence: dict, df: pd.DataFrame, row_index: int):
    """Integrity checkpoint + model inference for the selected row."""
    rf_model      = load_rf_model()
    expected_cols = rf_model.feature_names_in_.tolist()
    sample_df = iv.feature_matrix(df, expected_cols).iloc[[row_index]]

    with st.spinner("Re-verifying evidence hashes..."):
        integrity = verify_before_analysis(evidence, sample_df, row_index, expected_cols)
    if not evidence["chain"].is_intact:
        st.session_state["current_triage"] = None
        logger.error(f"ANALYSIS BLOCKED | CASE={evidence['chain'].case_id} | integrity verification failed")
        st.session_state["triage_blocked"] = True
        return
    st.session_state["triage_blocked"] = False

    with st.spinner("Running ML inference, anomaly detection and explainability..."):
        result = run_triage(sample_df, evidence["name"], row_index, integrity)
        result["evidence_key"] = evidence["key"]
        compute_shap(result)
        compute_lime(result)
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
    is_malware = bool(result["prediction"])
    banner = {
        "HIGH RISK":  ("Critical — contain the host", "Active malicious indicators found in memory. Isolate the endpoint and escalate."),
        "SUSPICIOUS": ("Suspicious — analyst review needed", "Memory metrics deviate from normal. Review before releasing the host."),
        "NORMAL":     ("Clean — normal baseline", "Memory behaviour matches a healthy Windows system."),
    }[risk]
    anomaly_html = ""
    if result["is_anomaly"]:
        anomaly_html = ui.banner("radar", "Zero-day anomaly", "Isolation Forest flagged this profile as an outlier versus known baselines.", "accent")
    tiles = "".join([
        ui.kpi("Risk level", f"{ui.icon(RISK_GLYPHS[risk])} {risk}", color=ui.TONES[tone][0]),
        ui.kpi("Classification", f"{ui.icon('coronavirus')} MALWARE" if is_malware else f"{ui.icon('shield')} BENIGN",
               color=ui.CRITICAL if is_malware else ui.GOOD),
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


def render_overview_tab(result: dict):
    shap_df = result.get("_shap_df")
    col_a, col_b = st.columns([1.05, 1], gap="large")
    with col_a:
        st.markdown("##### Recommended response")
        tone = RISK_TONES[result["risk"]]
        fg, bg, border = ui.TONES[tone]
        items = []
        for i, action in enumerate(RESPONSE_ACTIONS[result["risk"]], start=1):
            text = re.sub(r'^[^\w]+', '', action).strip()
            items.append(f'<div class="fx-action"><div class="fx-action-num" style="color:{fg};background:{bg};'
                         f'border:1px solid {border};">{i}</div><div class="fx-action-text">{ui.esc(text)}</div></div>')
        ui.render_html("".join(items))
    with col_b:
        st.markdown("##### Why the model decided this")
        if shap_df is None:
            st.info("Explanation unavailable for this run.")
        else:
            rows = []
            for _, r in shap_df.head(5).iterrows():
                up = r["SHAP Value"] > 0
                color = ui.TOWARD_MALWARE if up else ui.TOWARD_BENIGN
                rows.append(
                    f'<div class="fx-action"><div class="fx-action-num" style="color:{color};border:1px solid {color};">'
                    f'{"▲" if up else "▼"}</div><div style="min-width:0;"><div class="fx-action-text">'
                    f'{ui.esc(r["Plain English Indicator"])}</div><div style="font-size:0.88rem;color:var(--muted);">'
                    f'{r["SHAP Value"]*100:+.1f} pts · <code>{ui.esc(r["Technical Metric"])}</code></div></div></div>'
                )
            ui.render_html("".join(rows))
            st.caption("▲ pushes toward malware · ▼ pushes toward benign — see the Explainability tab for details.")


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
            rows = (f'<div class="fx-side-row"><span>Case</span><code>{ui.esc(case["case_number"])}</code></div>'
                    f'<div class="fx-side-row"><span>Analyst</span><span style="{ellipsis}">{ui.esc(case["analyst"])}</span></div>'
                    f'<div class="fx-side-row"><span>Opened</span><span style="font-size:0.85rem;">{ui.esc(case["opened_local"][5:16])}</span></div>')
            if evidence:
                chain = evidence["chain"]
                rows += (f'<div class="fx-side-row"><span>Evidence</span><span style="{ellipsis}">{ui.esc(evidence["name"])}</span></div>'
                         f'<div class="fx-side-row"><span>SHA-256</span><code>{chain.baseline("evidence").get("sha256", "")[:12]}…</code></div>'
                         f'<div class="fx-side-row"><span>Integrity</span>'
                         f'{ui.pill("Verified", "good") if chain.is_intact else ui.pill("Compromised", "critical")}</div>')
            ui.render_html(rows)
        else:
            st.caption("No case open.")

        ui.render_html('<div class="fx-side-label">Workflow</div>')
        checks = [
            ("Case opened by analyst", bool(case)),
            ("Evidence acquired & hashed", bool(evidence)),
            ("Integrity verified", bool(evidence) and evidence["chain"].is_intact),
            ("Triage completed", result is not None),
            ("Report sealed", pdf_ready),
        ]
        ui.render_html("".join(
            f'<div class="fx-check"><span style="color:{ui.GOOD if ok else ui.MUTED};font-size:1.05rem;">'
            f'{"●" if ok else "○"}</span>{ui.esc(label)}</div>' for label, ok in checks))

        ui.render_html('<div class="fx-side-label">Engines</div>')
        ui.render_html(
            f'<div class="fx-side-row"><span>Random Forest</span>{ui.pill("Online" if rf_found else "Offline", "good" if rf_found else "critical")}</div>'
            f'<div class="fx-side-row"><span>Isolation Forest</span>{ui.pill("Online" if iso_found else "Disabled", "good" if iso_found else "warning")}</div>'
            f'<div class="fx-side-row"><span>Volatility 3</span>{ui.pill("Ready", "good")}</div>'
        )
        log_check = audit_log_status()
        ui.render_html(
            f'<div class="fx-side-row"><span>Audit log chain</span>'
            f'{ui.pill("Intact", "good") if log_check["verified"] else ui.pill("Broken", "critical")}</div>')
        if not log_check["verified"]:
            st.error("Audit log verification failed: " + "; ".join(log_check["problems"][:3]), icon=":material/gpp_bad:")
        st.caption("Audit log: `logs/triage_audit.log`  \nCases: `outputs/cases/`")


def render_dashboard(state: dict):
    # ── 0. Case session (mandatory) ───────────────────────────
    ui.section("Case session", "Every analysis is recorded under a case number and a named analyst.", "folder_open")
    with st.container(border=True):
        session = render_case_session()
    if session is None:
        ui.empty_state("lock", "Open a case to start",
                       "Enter the case number and analyst name. Evidence intake unlocks once the session is open.")
        return
    state["case"] = session

    # ── 1. Evidence intake ────────────────────────────────────
    ui.section("Evidence intake", "Load a sample, a Volatility CSV or a raw Windows memory dump.", "inventory_2")
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
    with st.expander("Preview evidence data", icon=":material/table_view:"):
        st.dataframe(df.head(10), width="stretch")
    if not render_feature_validation(evidence, df):
        return

    # ── 2. Triage controls ────────────────────────────────────
    ui.section("Run triage", "Pick a memory snapshot (row) and analyse it.", "troubleshoot")
    with st.container(border=True):
        c_row, c_run, c_scan, c_reset = st.columns([2, 1.6, 1.45, 1], vertical_alignment="bottom")
        with c_row:
            row_index = st.selectbox("Memory snapshot", options=list(range(len(df))),
                                     format_func=lambda i: f"Row {i}" + (f" of {len(df)}" if len(df) > 1 else ""))
        with c_run:
            run_clicked = st.button("Analyse snapshot", type="primary", width="stretch", icon=":material/play_arrow:")
        with c_scan:
            scan_clicked = st.button("Scan all rows", width="stretch", icon=":material/radar:")
        with c_reset:
            if st.button("Reset", width="stretch", icon=":material/restart_alt:"):
                st.session_state["current_triage"] = None
                st.session_state["batch_summary"] = None
                st.rerun()

        if scan_clicked:
            rf_model = load_rf_model()
            batch_df = iv.feature_matrix(df, rf_model.feature_names_in_.tolist())
            probs = rf_model.predict_proba(batch_df)[:, 1]
            st.session_state["batch_summary"] = pd.DataFrame({
                "Row": range(len(df)),
                "Malware confidence": probs * 100,
                "Verdict": ["🦠 Malware" if p >= 0.5 else "🛡️ Benign" for p in probs],
                "Risk": [f"{RISK_ICONS[r]} {r}" for r in
                         ["HIGH RISK" if p >= 0.75 else "SUSPICIOUS" if p >= 0.40 else "NORMAL" for p in probs]],
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
                       "Choose a snapshot above and press <b>Analyse snapshot</b> to get the verdict, explanation and report.")
        return
    state["result"] = result

    if result["row_index"] != row_index:
        st.info(f"Showing results for **row {result['row_index']}**. Press **Analyse snapshot** to analyse row {row_index}.",
                icon=":material/info:")

    # ── 3. Results ────────────────────────────────────────────
    ui.section("Verdict", f"{result['source_file']} · row {result['row_index']} · {result['timestamp']}", "gavel")
    render_verdict(result, evidence["chain"])

    pdf_state = ensure_report(evidence, result)       # before the ledger so it includes the report seal
    state["pdf_ready"] = "sha256" in pdf_state

    st.write("")
    t_over, t_xai, t_prov, t_custody, t_report, t_log = st.tabs([
        ":material/space_dashboard: Overview",
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
        "MemTriage", "XAI",
        "Explainable AI triage for Windows memory forensics",
        [ui.pill("Models online" if rf_found else "Model missing", "good" if rf_found else "critical"),
         ui.pill("Chain of custody: SHA-256", "accent", dot=False)],
    )
    stepper_slot = st.empty()

    state = {"case": None, "evidence": None, "result": None, "pdf_ready": False, "blocked": False}
    try:
        render_dashboard(state)
    finally:
        evidence, result = state["evidence"], state["result"]
        intact = bool(evidence) and evidence["chain"].is_intact
        steps = [
            ("Case", "Open session", "done" if state["case"] else "active"),
            ("Evidence", "Acquire & hash", "done" if evidence else ("active" if state["case"] else "pending")),
            ("Integrity", "Verify hashes",
             "blocked" if (evidence and not intact) or state["blocked"] else "done" if intact else "pending"),
            ("Triage", "ML + XAI", "done" if result else ("active" if intact else "pending")),
            ("Report", "Seal & export", "done" if state["pdf_ready"] else ("active" if result else "pending")),
        ]
        with stepper_slot.container():
            ui.stepper(steps)
        render_sidebar(state["case"], evidence, result, state["pdf_ready"])


# ── Authentication & sessions ─────────────────────────────────────────────────
def start_session(user: dict):
    """A successful sign-in starts a fresh, empty workspace."""
    st.session_state.clear()
    st.session_state["auth"] = {
        "username": user["username"], "session_id": uuid.uuid4().hex[:8].upper(),
        "login_ts": time.time(), "last_seen": time.time(), "login_local": ei.local_timestamp(),
    }
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
        if st.button("Sign out", icon=":material/logout:", width="stretch", key="sign_out"):
            end_session("LOGOUT", "You have been signed out.")
            st.rerun()


def main():
    st.set_page_config(page_title="MemTriage XAI · Memory Forensics", page_icon=":material/memory:", layout="wide")
    ui.inject_theme()

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

    pages = [st.Page(triage_page, title="Triage", icon=":material/biotech:", url_path="triage", default=True)]
    if user["role"] == "admin":
        pages += [st.Page(admin_pages.render_audit_page, title="Audit log", icon=":material/policy:", url_path="audit"),
                  st.Page(admin_pages.render_users_page, title="Users", icon=":material/group:", url_path="users")]
    pages.append(st.Page(admin_pages.render_account_page, title="My account", icon=":material/person:",
                         url_path="account"))
    page = st.navigation(pages, position="top")
    render_user_panel(user)
    page.run()


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
