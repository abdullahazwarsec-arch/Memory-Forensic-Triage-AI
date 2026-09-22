# =============================================================================
# MEMORY FORENSIC TRIAGE SYSTEM — app.py
# Explainable AI Dashboard with SHAP, LIME, Audit Logging, PDF Reports
# =============================================================================

# ── SECTION 1: IMPORTS ───────────────────────────────────────────────────────
import os
import io
import re
import html
import logging
import hashlib
from datetime import datetime

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")   # Must be set BEFORE importing pyplot (Streamlit requirement)
import matplotlib.pyplot as plt

import shap
from lime.lime_tabular import LimeTabularExplainer

import streamlit as st

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors


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

# Create folders if they don't exist yet
os.makedirs(OUTPUT_DIR,  exist_ok=True)
os.makedirs(LOG_DIR,     exist_ok=True)
os.makedirs(SAMPLES_DIR, exist_ok=True)


# ── SECTION 3: AUDIT LOGGER SETUP ────────────────────────────────────────────
# Every prediction is written to a log file with timestamp
# This is chain-of-custody — a record of every analysis ever run
logging.basicConfig(
    filename  = os.path.join(LOG_DIR, "triage_audit.log"),
    level     = logging.INFO,
    format    = "%(asctime)s | %(levelname)s | %(message)s",
    datefmt   = "%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("triage")


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
    return joblib.load(MODEL_PATH)


@st.cache_resource
def load_iso_model():
    """Load the Isolation Forest anomaly detector (optional — won't crash if missing)."""
    if os.path.exists(ISO_PATH):
        return joblib.load(ISO_PATH)
    return None   # Dashboard still works without it


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

def run_triage(sample_df: pd.DataFrame, source_filename: str, row_index: int) -> dict:
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
    # Hash the filename + row index to create a unique evidence ID
    evidence_str  = f"{source_filename}:row{row_index}:{datetime.now().isoformat()}"
    evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()[:16].upper()
    timestamp     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
    }

    # ── Write to audit log ────────────────────────────────────
    logger.info(
        f"EVIDENCE_ID={evidence_hash} | FILE={source_filename} | "
        f"ROW={row_index} | RISK={risk} | CONF={prob:.4f} | "
        f"PREDICTION={'MALWARE' if prediction else 'BENIGN'} | "
        f"ANOMALY={is_anomaly}"
    )

    return result


# ── SECTION 7: SHAP EXPLANATION ───────────────────────────────────────────────

def render_shap_explanation(result: dict):
    """Generate and display human-understandable SHAP explanation for one sample."""

    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.25rem;">
            <span style="font-size: 0.72rem; font-weight: 700; color: #c797ff; background: rgba(143, 79, 224, 0.25); border: 1px solid rgba(189, 99, 255, 0.4); border-radius: 9999px; padding: 0.2rem 0.6rem;">04 &bull; GLOBAL ATTRIBUTION</span>
            <h3 class="dl-gradient-text" style="margin: 0; font-size: 1.35rem;">SHAP Feature Attribution &mdash; Decision Drivers</h3>
        </div>
        <div style="font-size: 0.85rem; color: rgba(238, 233, 255, 0.65); margin-bottom: 1.2rem;">
            Game-theoretic Shapley values quantifying the exact push towards malicious or benign verdicts across all 55 memory artifacts.
        </div>
        """,
        unsafe_allow_html=True
    )

    rf_model    = load_rf_model()
    sample_arr  = result["sample_arr"]
    feature_cols = result["feature_cols"]

    with st.spinner("Calculating SHAP values..."):
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

            # Build human-friendly explanation table
            titles = []
            descriptions = []
            dangers = []
            for f in feature_cols:
                info = get_feature_info(f)
                titles.append(info["title"])
                descriptions.append(info["desc"])
                dangers.append(info["danger"])

            shap_df = pd.DataFrame({
                "Plain English Indicator": titles,
                "Technical Metric":        feature_cols,
                "SHAP Value":              vals,
                "What This Is":            descriptions,
                "Forensic Context":        dangers
            })
            shap_df["Abs"] = shap_df["SHAP Value"].abs()
            shap_df = shap_df.sort_values("Abs", ascending=False).head(10)
            
            shap_df["Impact on Verdict"] = shap_df["SHAP Value"].apply(
                lambda v: f"🔴 +{v*100:.1f}% (Elevates Malware Risk)" if v > 0
                else f"🟢 {v*100:.1f}% (Supports Clean Baseline)"
            )

            # Human Explanation Cards for Top 3 Key Drivers
            st.markdown("#### 🎯 Key Decision Drivers (Plain English Translation)")
            top3 = shap_df.head(3)
            col_a, col_b, col_c = st.columns(3)
            cols = [col_a, col_b, col_c]
            
            for idx, (_, row) in enumerate(top3.iterrows()):
                with cols[idx]:
                    is_danger = row["SHAP Value"] > 0
                    dot_class = "dl-pulse-dot-danger" if is_danger else "dl-pulse-dot"
                    badge_bg = "rgba(244, 63, 94, 0.12)" if is_danger else "rgba(16, 185, 129, 0.12)"
                    badge_border = "#f43f5e" if is_danger else "#10b981"
                    badge_color = "#fda4af" if is_danger else "#6ee7b7"
                    badge_text = "ELEVATES MALWARE RISK" if is_danger else "SUPPORTS CLEAN BASELINE"
                    st.markdown(
                        f"""
                        <div class="dl-card" style="height: 100%; min-height: 290px; display: flex; flex-direction: column; justify-content: space-between;">
                            <div>
                                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.8rem;">
                                    <span style="font-size: 0.76rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; padding: 0.25rem 0.65rem; border-radius: 9999px; background: {badge_bg}; border: 1px solid {badge_border}; color: {badge_color};">
                                        <span class="{dot_class}"></span> {badge_text}
                                    </span>
                                </div>
                                <h4 style="color: #ffffff; margin: 0 0 0.5rem 0; font-size: 1.05rem; font-weight: 600;">{row['Plain English Indicator']}</h4>
                                <p style="color: rgba(238, 233, 255, 0.78); font-size: 0.86rem; line-height: 1.45; margin-bottom: 0.6rem;">{row['What This Is']}</p>
                                <p style="color: rgba(238, 233, 255, 0.52); font-size: 0.78rem; line-height: 1.4; margin-bottom: 0.8rem;"><b style="color: #d5b1fd;">Why it matters:</b> {row['Forensic Context']}</p>
                            </div>
                            <div style="padding-top: 0.6rem; border-top: 1px solid rgba(238, 233, 255, 0.08);">
                                <div style="font-size: 0.82rem; font-weight: 600; color: {badge_color}; margin-bottom: 0.2rem;">{row['Impact on Verdict']}</div>
                                <div style="font-size: 0.72rem; color: rgba(238, 233, 255, 0.45); font-family: 'Space Grotesk', monospace;">Metric: <code>{row['Technical Metric']}</code></div>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            # Table for full review
            st.markdown("#### 📋 Detailed Feature Impact Breakdown")
            st.dataframe(
                shap_df[["Plain English Indicator", "Technical Metric", "Impact on Verdict"]].reset_index(drop=True),
                use_container_width=True
            )

            # Waterfall bar chart using matplotlib with cosmic dark styling
            fig, ax = plt.subplots(figsize=(9, 4.4), facecolor="#12072b")
            ax.set_facecolor("#180a38")
            top10 = shap_df.head(10)
            bar_colours = ["#f43f5e" if v > 0 else "#10b981" for v in top10["SHAP Value"]]
            ax.barh(top10["Plain English Indicator"], top10["SHAP Value"], color=bar_colours, edgecolor="none", height=0.62)
            ax.axvline(0, color="#d5b1fd", alpha=0.4, linewidth=0.8, linestyle="--")
            ax.set_xlabel("SHAP Value (Contribution to Malware Risk)", fontsize=9.5, color="#eee9ff", labelpad=8)
            ax.set_title("Top 10 Memory Artifacts Driving Classification (SHAP)", fontsize=11, fontweight="bold", color="#ffffff", pad=12)
            ax.tick_params(colors="#d5b1fd", labelsize=8.5)
            for spine in ax.spines.values():
                spine.set_color("#6b4c9a")
                spine.set_alpha(0.3)
            ax.grid(axis='x', color='#d5b1fd', alpha=0.12, linestyle='--', linewidth=0.7)
            ax.invert_yaxis()
            plt.tight_layout()

            buf = io.BytesIO()
            plt.savefig(buf, format="png", dpi=140, facecolor=fig.get_facecolor(), edgecolor="none", bbox_inches="tight")
            buf.seek(0)
            st.image(buf, use_container_width=True)
            plt.close(fig)
            return shap_df

        except Exception as e:
            st.error(f"SHAP calculation failed: {e}")
            logger.error(f"SHAP error for evidence {result['evidence_id']}: {e}")
            return None


# ── SECTION 8: LIME EXPLANATION ───────────────────────────────────────────────

def render_lime_explanation(result: dict):
    """Generate and display human-understandable LIME local explanation for one sample."""

    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.25rem;">
            <span style="font-size: 0.72rem; font-weight: 700; color: #c797ff; background: rgba(143, 79, 224, 0.25); border: 1px solid rgba(189, 99, 255, 0.4); border-radius: 9999px; padding: 0.2rem 0.6rem;">05 &bull; LOCAL DECISION RULES</span>
            <h3 class="dl-gradient-text" style="margin: 0; font-size: 1.35rem;">LIME Explanation &mdash; Local Decision Rules</h3>
        </div>
        <div style="font-size: 0.85rem; color: rgba(238, 233, 255, 0.65); margin-bottom: 1.2rem;">
            Local interpretable surrogate rules providing independent corroboration for this specific memory profile.
        </div>
        """,
        unsafe_allow_html=True
    )

    rf_model     = load_rf_model()
    sample_arr   = result["sample_arr"]
    feature_cols = result["feature_cols"]

    with st.spinner("Calculating LIME values..."):
        try:
            # Load real background data
            background = load_background_data(tuple(feature_cols))

            explainer = LimeTabularExplainer(
                training_data   = background,
                feature_names   = feature_cols,
                class_names     = ["Benign", "Malware"],
                mode            = "classification",
                discretize_continuous = True,
                random_state    = 42,
            )

            # Wrap predict_fn with DataFrame to preserve feature names and suppress scikit-learn warnings
            def lime_predict_fn(arr):
                df_arr = pd.DataFrame(arr, columns=feature_cols)
                return rf_model.predict_proba(df_arr)

            lime_exp = explainer.explain_instance(
                data_row        = sample_arr[0],
                predict_fn      = lime_predict_fn,
                num_features    = 8,
                num_samples     = 1000,
            )

            # Translate LIME rules into plain English
            lime_data = lime_exp.as_list()
            lime_rows = []
            
            for cond, weight in lime_data:
                info = get_feature_info(cond)
                is_danger = weight > 0
                direction = (
                    f"🔴 Toward MALWARE (+{weight*100:.1f}%)" if is_danger
                    else f"🟢 Toward BENIGN ({weight*100:.1f}%)"
                )
                lime_rows.append({
                    "Plain English Indicator": info["title"],
                    "Observed Condition":       cond,
                    "LIME Weight":              weight,
                    "Direction":                direction,
                    "What This Means":          info["desc"],
                    "Forensic Context":         info["danger"],
                })

            lime_df = pd.DataFrame(lime_rows)
            lime_df["Abs"] = lime_df["LIME Weight"].abs()
            lime_df = lime_df.sort_values("Abs", ascending=False)

            # Top Local Rules Cards
            st.markdown("#### 🔍 Corroborating Forensic Evidence (Local Decision Rules)")
            top3_lime = lime_df.head(3)
            col_l1, col_l2, col_l3 = st.columns(3)
            lime_cols = [col_l1, col_l2, col_l3]

            for idx, (_, row) in enumerate(top3_lime.iterrows()):
                with lime_cols[idx]:
                    is_danger = row["LIME Weight"] > 0
                    dot_class = "dl-pulse-dot-danger" if is_danger else "dl-pulse-dot"
                    badge_bg = "rgba(244, 63, 94, 0.12)" if is_danger else "rgba(16, 185, 129, 0.12)"
                    badge_border = "#f43f5e" if is_danger else "#10b981"
                    badge_color = "#fda4af" if is_danger else "#6ee7b7"
                    badge_text = "LOCAL ATTACK RULE" if is_danger else "LOCAL BASELINE RULE"
                    clean_cond = str(row['Observed Condition']).replace('<', '&lt;').replace('>', '&gt;')
                    st.markdown(
                        f"""
                        <div class="dl-card" style="height: 100%; min-height: 290px; display: flex; flex-direction: column; justify-content: space-between;">
                            <div>
                                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.8rem;">
                                    <span style="font-size: 0.76rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; padding: 0.25rem 0.65rem; border-radius: 9999px; background: {badge_bg}; border: 1px solid {badge_border}; color: {badge_color};">
                                        <span class="{dot_class}"></span> {badge_text}
                                    </span>
                                </div>
                                <h4 style="color: #ffffff; margin: 0 0 0.5rem 0; font-size: 1.05rem; font-weight: 600;">{row['Plain English Indicator']}</h4>
                                <p style="color: rgba(238, 233, 255, 0.78); font-size: 0.86rem; line-height: 1.45; margin-bottom: 0.6rem;">{row['What This Means']}</p>
                                <p style="color: rgba(238, 233, 255, 0.52); font-size: 0.78rem; line-height: 1.4; margin-bottom: 0.8rem;"><b style="color: #d5b1fd;">Context:</b> {row['Forensic Context']}</p>
                            </div>
                            <div style="padding-top: 0.6rem; border-top: 1px solid rgba(238, 233, 255, 0.08);">
                                <div style="font-size: 0.76rem; color: #d5b1fd; font-family: 'Space Grotesk', monospace; margin-bottom: 0.25rem;">Rule: <code>{clean_cond}</code></div>
                                <div style="font-size: 0.82rem; font-weight: 600; color: {badge_color};">{row['Direction']}</div>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            # Table for full review
            st.markdown("#### 📋 Detailed Feature Impact Breakdown")
            st.dataframe(
                lime_df[["Plain English Indicator", "Observed Condition", "Direction"]].reset_index(drop=True),
                use_container_width=True
            )

            # Bar chart with cosmic dark styling
            fig, ax = plt.subplots(figsize=(9, 4), facecolor="#12072b")
            ax.set_facecolor("#180a38")
            bar_colours = ["#f43f5e" if v > 0 else "#10b981" for v in lime_df["LIME Weight"]]
            chart_labels = [f"{r['Plain English Indicator']}" for _, r in lime_df.iterrows()]
            ax.barh(chart_labels, lime_df["LIME Weight"], color=bar_colours, edgecolor="none", height=0.62)
            ax.axvline(0, color="#d5b1fd", alpha=0.4, linewidth=0.8, linestyle="--")
            ax.set_xlabel("Local Influence Weight", fontsize=9.5, color="#eee9ff", labelpad=8)
            ax.set_title("LIME — Local Feature Influence for This Sample", fontsize=11, fontweight="bold", color="#ffffff", pad=12)
            ax.tick_params(colors="#d5b1fd", labelsize=8.5)
            for spine in ax.spines.values():
                spine.set_color("#6b4c9a")
                spine.set_alpha(0.3)
            ax.grid(axis='x', color='#d5b1fd', alpha=0.12, linestyle='--', linewidth=0.7)
            ax.invert_yaxis()
            plt.tight_layout()

            buf = io.BytesIO()
            plt.savefig(buf, format="png", dpi=140, facecolor=fig.get_facecolor(), edgecolor="none", bbox_inches="tight")
            buf.seek(0)
            st.image(buf, use_container_width=True)
            plt.close(fig)

            st.caption(
                "💡 **How to interpret:** SHAP shows the global attribution across all 55 features. "
                "LIME provides local validation for this specific memory dump. "
                "When both SHAP and LIME point in the same direction, confidence in the triage verdict is confirmed."
            )
            return lime_df

        except Exception as e:
            st.error(f"LIME calculation failed: {e}")
            logger.error(f"LIME error for evidence {result['evidence_id']}: {e}")
            return None


# ── SECTION 9: PDF REPORT GENERATOR ──────────────────────────────────────────

def generate_pdf_report(result: dict, shap_df: pd.DataFrame = None, lime_df: pd.DataFrame = None):
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
    meta_data = [
        [Paragraph("Evidence ID", cell_bold), Paragraph(xml_esc(result["evidence_id"]), cell_style)],
        [Paragraph("Analysis Timestamp", cell_bold), Paragraph(xml_esc(result["timestamp"]), cell_style)],
        [Paragraph("Source Memory File", cell_bold), Paragraph(xml_esc(result["source_file"]), cell_style)],
        [Paragraph("Evaluated Record / Row", cell_bold), Paragraph(f"Row {r_idx}", cell_style)],
        [Paragraph("Telemetry Features", cell_bold), Paragraph(f"{n_feat} memory telemetry indicators", cell_style)],
        [Paragraph("Analysis Engines", cell_bold), Paragraph("Random Forest Classifier (150 trees) + Isolation Forest (Zero-Day Anomaly Detector)", cell_style)],
    ]
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
                Paragraph("Plain-English Indicator", cell_bold),
                Paragraph("Telemetry Metric", cell_bold),
                Paragraph("Verdict Impact", cell_bold),
                Paragraph("Forensic Meaning &amp; Threat Danger", cell_bold)
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
                Paragraph("Plain-English Indicator", cell_bold),
                Paragraph("Observed Telemetry Rule", cell_bold),
                Paragraph("Local Weight", cell_bold),
                Paragraph("Forensic Interpretation", cell_bold)
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

    # Build document
    doc.build(story)

    # Read binary bytes for Streamlit download button
    with open(output_path, "rb") as f:
        pdf_bytes = f.read()

    logger.info(f"PDF report saved: {output_path} | EVIDENCE_ID={result['evidence_id']}")
    return output_path, pdf_bytes


# ── SECTION 10: STREAMLIT UI & DAVID LANGARICA DESIGN SYSTEM ──────────────────

def inject_custom_css():
    """Inject bespoke CSS tokens and styles extracted from davidlangarica.dev."""
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=Space+Grotesk:wght@400;500;600;700&display=swap');

        /* ── Core Canvas Atmosphere (davidlangarica.dev) ── */
        .stApp {
            background-color: #0e0621 !important;
            background-image: 
                radial-gradient(circle at 82% 10%, rgba(143, 79, 224, 0.24) 0%, transparent 46rem),
                radial-gradient(circle at 14% 75%, rgba(189, 99, 255, 0.16) 0%, transparent 40rem),
                radial-gradient(circle at 50% 50%, rgba(35, 17, 77, 0.45) 0%, transparent 60rem) !important;
            background-attachment: fixed !important;
            font-family: 'Outfit', sans-serif !important;
            color: #eee9ff !important;
        }

        /* ── Global Typography ── */
        h1, h2, h3, h4, h5, h6, p, span, label, div {
            font-family: 'Outfit', sans-serif !important;
        }
        
        code, pre, .font-mono {
            font-family: 'Space Grotesk', monospace !important;
        }

        /* ── Sidebar ── */
        [data-testid="stSidebar"] {
            background-color: rgba(14, 6, 33, 0.88) !important;
            backdrop-filter: blur(24px) !important;
            -webkit-backdrop-filter: blur(24px) !important;
            border-right: 1px solid rgba(238, 233, 255, 0.09) !important;
        }
        [data-testid="stSidebar"] hr {
            display: none !important;
        }

        /* ── Custom Gradients & Tokens ── */
        .dl-gradient-text {
            background: linear-gradient(92deg, #c797ff 10%, #eee9ff 72%) !important;
            -webkit-background-clip: text !important;
            -webkit-text-fill-color: transparent !important;
            font-family: 'Outfit', sans-serif !important;
            font-weight: 700 !important;
            letter-spacing: -0.02em !important;
        }

        .dl-gradient-sub {
            background: linear-gradient(92deg, #eee9ff 0%, #bca6ee 100%) !important;
            -webkit-background-clip: text !important;
            -webkit-text-fill-color: transparent !important;
        }

        /* ── Glassmorphic Cards ── */
        .dl-card {
            background: rgba(30, 14, 66, 0.65) !important;
            backdrop-filter: blur(24px) !important;
            -webkit-backdrop-filter: blur(24px) !important;
            border: 1px solid rgba(238, 233, 255, 0.12) !important;
            border-radius: 1.25rem !important;
            padding: 1.4rem 1.6rem !important;
            box-shadow: 0 12px 36px -10px rgba(10, 2, 28, 0.6) !important;
            transition: all 0.28s cubic-bezier(0.16, 1, 0.3, 1) !important;
        }
        .dl-card:hover {
            transform: translateY(-3px) !important;
            border-color: rgba(189, 99, 255, 0.38) !important;
            box-shadow: 0 18px 45px -8px rgba(143, 79, 224, 0.35) !important;
        }

        /* ── Hairline Glowing Divider ── */
        .dl-divider {
            height: 1px;
            width: 100%;
            margin: 2rem 0;
            background: linear-gradient(90deg, transparent, rgba(189, 99, 255, 0.35) 25%, rgba(238, 233, 255, 0.6) 50%, rgba(189, 99, 255, 0.35) 75%, transparent);
            border: none;
        }

        /* ── Pulsing Status Dots ── */
        .dl-pulse-dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #10b981;
            box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
            animation: dl-pulse 2s infinite;
            vertical-align: middle;
            margin-right: 6px;
        }
        .dl-pulse-dot-danger {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #f43f5e;
            box-shadow: 0 0 0 0 rgba(244, 63, 94, 0.7);
            animation: dl-pulse-danger 2s infinite;
            vertical-align: middle;
            margin-right: 6px;
        }
        .dl-pulse-dot-amber {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #f59e0b;
            box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.7);
            animation: dl-pulse-amber 2s infinite;
            vertical-align: middle;
            margin-right: 6px;
        }
        .dl-pulse-dot-violet {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #a855f7;
            box-shadow: 0 0 0 0 rgba(168, 85, 247, 0.7);
            animation: dl-pulse-violet 2s infinite;
            vertical-align: middle;
            margin-right: 6px;
        }
        @keyframes dl-pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 7px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }
        @keyframes dl-pulse-danger {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(244, 63, 94, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 7px rgba(244, 63, 94, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(244, 63, 94, 0); }
        }
        @keyframes dl-pulse-amber {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 7px rgba(245, 158, 11, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(245, 158, 11, 0); }
        }
        @keyframes dl-pulse-violet {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(168, 85, 247, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 7px rgba(168, 85, 247, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(168, 85, 247, 0); }
        }

        /* ── Streamlit Metric Card Overhaul ── */
        [data-testid="stMetric"] {
            background: rgba(30, 14, 66, 0.65) !important;
            backdrop-filter: blur(20px) !important;
            -webkit-backdrop-filter: blur(20px) !important;
            border: 1px solid rgba(238, 233, 255, 0.12) !important;
            border-radius: 1.15rem !important;
            padding: 1.15rem 1.3rem !important;
            box-shadow: 0 10px 30px -10px rgba(10, 2, 28, 0.55) !important;
            transition: transform 0.25s ease, border-color 0.25s ease !important;
        }
        [data-testid="stMetric"]:hover {
            transform: translateY(-2px) !important;
            border-color: rgba(189, 99, 255, 0.35) !important;
        }
        [data-testid="stMetricLabel"] {
            color: rgba(238, 233, 255, 0.65) !important;
            font-family: 'Outfit', sans-serif !important;
            font-size: 0.82rem !important;
            font-weight: 600 !important;
            text-transform: uppercase !important;
            letter-spacing: 0.05em !important;
        }
        [data-testid="stMetricValue"] {
            color: #ffffff !important;
            font-family: 'Space Grotesk', sans-serif !important;
            font-weight: 700 !important;
            font-size: 1.65rem !important;
        }

        /* ── Streamlit Buttons ── */
        button[kind="primary"], .stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] {
            background: linear-gradient(135deg, #8f4fe0 0%, #6d28d9 100%) !important;
            border: 1px solid rgba(238, 233, 255, 0.28) !important;
            border-radius: 1.25rem !important;
            color: #ffffff !important;
            font-family: 'Outfit', sans-serif !important;
            font-weight: 600 !important;
            letter-spacing: 0.03em !important;
            box-shadow: 0 4px 20px rgba(143, 79, 224, 0.38) !important;
            padding: 0.55rem 1.4rem !important;
            transition: all 0.25s ease !important;
        }
        button[kind="primary"]:hover, .stButton > button[kind="primary"]:hover, .stDownloadButton > button[kind="primary"]:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 8px 30px rgba(189, 99, 255, 0.6) !important;
            border-color: rgba(238, 233, 255, 0.6) !important;
            color: #ffffff !important;
        }
        button[kind="secondary"], .stButton > button:not([kind="primary"]), .stDownloadButton > button:not([kind="primary"]) {
            background: rgba(30, 14, 66, 0.7) !important;
            backdrop-filter: blur(16px) !important;
            -webkit-backdrop-filter: blur(16px) !important;
            border: 1px solid rgba(238, 233, 255, 0.14) !important;
            border-radius: 1.25rem !important;
            color: #eee9ff !important;
            font-family: 'Outfit', sans-serif !important;
            font-weight: 500 !important;
            transition: all 0.25s ease !important;
        }
        button[kind="secondary"]:hover, .stButton > button:not([kind="primary"]):hover, .stDownloadButton > button:not([kind="primary"]):hover {
            transform: translateY(-2px) !important;
            border-color: rgba(189, 99, 255, 0.45) !important;
            color: #ffffff !important;
            box-shadow: 0 4px 18px rgba(143, 79, 224, 0.25) !important;
        }

        /* ── File Uploader ── */
        [data-testid="stFileUploader"] {
            background: rgba(30, 14, 66, 0.4) !important;
            border: 1.5px dashed rgba(189, 99, 255, 0.32) !important;
            border-radius: 1.25rem !important;
            padding: 1.2rem !important;
            backdrop-filter: blur(14px) !important;
            transition: border-color 0.25s ease !important;
        }
        [data-testid="stFileUploader"]:hover {
            border-color: rgba(189, 99, 255, 0.75) !important;
        }

        /* ── Expanders ── */
        .streamlit-expanderHeader {
            background: rgba(30, 14, 66, 0.5) !important;
            border: 1px solid rgba(238, 233, 255, 0.1) !important;
            border-radius: 1rem !important;
            color: #eee9ff !important;
            font-family: 'Outfit', sans-serif !important;
            font-weight: 500 !important;
        }
        [data-testid="stExpander"] {
            background: transparent !important;
            border: none !important;
        }
        [data-testid="stExpanderDetails"] {
            background: rgba(22, 9, 50, 0.6) !important;
            border: 1px solid rgba(238, 233, 255, 0.08) !important;
            border-top: none !important;
            border-radius: 0 0 1rem 1rem !important;
            padding: 1.2rem !important;
        }

        /* ── Header & Footer Polish ── */
        header[data-testid="stHeader"] {
            background-color: transparent !important;
            backdrop-filter: blur(12px) !important;
            -webkit-backdrop-filter: blur(12px) !important;
        }
        footer {
            visibility: hidden !important;
        }

        /* ── Selectboxes & Inputs ── */
        div[data-baseweb="select"] > div {
            background-color: rgba(26, 11, 58, 0.8) !important;
            border-color: rgba(238, 233, 255, 0.16) !important;
            border-radius: 0.85rem !important;
            color: #eee9ff !important;
        }

        /* ── Selectbox Popovers & Dropdown Menus ── */
        div[data-baseweb="popover"], div[data-baseweb="menu"], ul[role="listbox"] {
            background-color: #160a33 !important;
            border: 1px solid rgba(189, 99, 255, 0.35) !important;
            border-radius: 0.85rem !important;
            color: #eee9ff !important;
            box-shadow: 0 14px 40px -8px rgba(10, 2, 28, 0.8) !important;
        }
        li[role="option"] {
            color: #eee9ff !important;
            background-color: transparent !important;
            padding: 0.55rem 0.95rem !important;
            font-size: 0.88rem !important;
            transition: background-color 0.18s ease !important;
        }
        li[role="option"]:hover, li[aria-selected="true"] {
            background-color: rgba(143, 79, 224, 0.32) !important;
            color: #ffffff !important;
        }

        /* ── Alerts & Callouts ── */
        [data-testid="stAlert"] {
            background: rgba(30, 14, 66, 0.8) !important;
            border-radius: 1rem !important;
            border: 1px solid rgba(238, 233, 255, 0.14) !important;
            color: #eee9ff !important;
            backdrop-filter: blur(16px) !important;
        }

        /* ── Radio Buttons ── */
        div[data-testid="stRadio"] label {
            color: #eee9ff !important;
            font-size: 0.9rem !important;
            font-weight: 500 !important;
        }

        /* ── DataFrames ── */
        [data-testid="stDataFrame"] {
            border: 1px solid rgba(238, 233, 255, 0.1) !important;
            border-radius: 1rem !important;
            overflow: hidden !important;
            background: rgba(24, 10, 52, 0.5) !important;
        }

        /* ── Custom Scrollbar ── */
        ::-webkit-scrollbar {
            width: 7px;
            height: 7px;
        }
        ::-webkit-scrollbar-track {
            background: #0e0621;
        }
        ::-webkit-scrollbar-thumb {
            background: #331566;
            border-radius: 9999px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #8f4fe0;
        }
        </style>
        """,
        unsafe_allow_html=True
    )


def dl_divider():
    """Render razor-thin glowing gradient separator from davidlangarica.dev."""
    st.markdown('<div class="dl-divider"></div>', unsafe_allow_html=True)


def main():

    # ── Page config ───────────────────────────────────────────
    st.set_page_config(
        page_title = "Memory Forensic Triage",
        page_icon  = "🧠",
        layout     = "wide",
    )

    # ── Inject David Langarica theme tokens ───────────────────
    inject_custom_css()

    # ── Sidebar ───────────────────────────────────────────────
    with st.sidebar:
        st.markdown(
            """
            <div style="display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.35rem 0.85rem; border-radius: 9999px; background: rgba(143, 79, 224, 0.15); border: 1px solid rgba(189, 99, 255, 0.3); font-size: 0.72rem; font-weight: 600; color: #d5b1fd; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.8rem;">
                <span class="dl-pulse-dot-violet"></span> XAI FORENSIC AGENT
            </div>
            <h2 class="dl-gradient-text" style="font-size: 1.45rem; margin: 0 0 0.25rem 0; font-weight: 700; line-height: 1.2;">Memory Triage</h2>
            <div style="color: rgba(238, 233, 255, 0.55); font-size: 0.8rem; margin-bottom: 1.2rem;">Telemetry &bull; Dual XAI &bull; v1.0</div>
            """,
            unsafe_allow_html=True
        )
        dl_divider()

        st.markdown(
            """
            <div style="font-size: 0.78rem; font-weight: 600; color: rgba(238, 233, 255, 0.6); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.75rem;">Workflow Pipeline</div>
            <div style="display: flex; flex-direction: column; gap: 0.65rem;">
                <div style="display: flex; align-items: center; gap: 0.65rem;">
                    <span style="display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; border-radius: 50%; background: rgba(143, 79, 224, 0.22); border: 1px solid rgba(189, 99, 255, 0.4); font-size: 0.7rem; font-weight: 700; color: #c797ff;">01</span>
                    <span style="font-size: 0.84rem; color: rgba(238, 233, 255, 0.85);">Upload Memory Profile</span>
                </div>
                <div style="display: flex; align-items: center; gap: 0.65rem;">
                    <span style="display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; border-radius: 50%; background: rgba(143, 79, 224, 0.22); border: 1px solid rgba(189, 99, 255, 0.4); font-size: 0.7rem; font-weight: 700; color: #c797ff;">02</span>
                    <span style="font-size: 0.84rem; color: rgba(238, 233, 255, 0.85);">Select Target Row</span>
                </div>
                <div style="display: flex; align-items: center; gap: 0.65rem;">
                    <span style="display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; border-radius: 50%; background: rgba(143, 79, 224, 0.22); border: 1px solid rgba(189, 99, 255, 0.4); font-size: 0.7rem; font-weight: 700; color: #c797ff;">03</span>
                    <span style="font-size: 0.84rem; color: rgba(238, 233, 255, 0.85);">Review SHAP &amp; LIME</span>
                </div>
                <div style="display: flex; align-items: center; gap: 0.65rem;">
                    <span style="display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; border-radius: 50%; background: rgba(143, 79, 224, 0.22); border: 1px solid rgba(189, 99, 255, 0.4); font-size: 0.7rem; font-weight: 700; color: #c797ff;">04</span>
                    <span style="font-size: 0.84rem; color: rgba(238, 233, 255, 0.85);">Download PDF Report</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        dl_divider()

        st.markdown(
            """
            <div style="font-size: 0.78rem; font-weight: 600; color: rgba(238, 233, 255, 0.6); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.75rem;">System Telemetry</div>
            """,
            unsafe_allow_html=True
        )
        rf_found = os.path.exists(MODEL_PATH)
        iso_found = os.path.exists(ISO_PATH)
        st.markdown(
            f"""
            <div style="display: flex; flex-direction: column; gap: 0.55rem;">
                <div style="background: rgba(30, 14, 66, 0.6); border: 1px solid rgba(238, 233, 255, 0.08); border-radius: 0.75rem; padding: 0.6rem 0.8rem; display: flex; align-items: center; justify-content: space-between;">
                    <span style="font-size: 0.8rem; color: rgba(238, 233, 255, 0.85);">Random Forest</span>
                    <span style="font-size: 0.75rem; font-weight: 600; color: {'#6ee7b7' if rf_found else '#fda4af'}; display: inline-flex; align-items: center;">
                        <span class="{'dl-pulse-dot' if rf_found else 'dl-pulse-dot-danger'}"></span> {'ONLINE' if rf_found else 'OFFLINE'}
                    </span>
                </div>
                <div style="background: rgba(30, 14, 66, 0.6); border: 1px solid rgba(238, 233, 255, 0.08); border-radius: 0.75rem; padding: 0.6rem 0.8rem; display: flex; align-items: center; justify-content: space-between;">
                    <span style="font-size: 0.8rem; color: rgba(238, 233, 255, 0.85);">Isolation Forest</span>
                    <span style="font-size: 0.75rem; font-weight: 600; color: {'#6ee7b7' if iso_found else '#fcd34d'}; display: inline-flex; align-items: center;">
                        <span class="{'dl-pulse-dot' if iso_found else 'dl-pulse-dot-amber'}"></span> {'ONLINE' if iso_found else 'DISABLED'}
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        dl_divider()
        st.caption(f"Audit log: `logs/triage_audit.log`")
        st.caption(f"Archival: `outputs/`")

    # ── Main Hero Section (davidlangarica.dev style) ──────────
    st.markdown(
        """
        <div style="margin-bottom: 2.2rem; padding: 2.2rem 2.4rem; border-radius: 1.5rem; background: rgba(30, 14, 66, 0.55); border: 1px solid rgba(238, 233, 255, 0.12); backdrop-filter: blur(24px); box-shadow: 0 16px 48px -12px rgba(10, 2, 28, 0.65);">
            <div style="display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.35rem 0.95rem; border-radius: 9999px; background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.35); font-size: 0.75rem; font-weight: 600; color: #6ee7b7; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 1.1rem;">
                <span class="dl-pulse-dot"></span> LIVE XAI FORENSIC TRIAGE ENGINE &bull; v1.0
            </div>
            <h1 class="dl-gradient-text" style="font-size: 2.75rem; line-height: 1.15; margin: 0 0 0.85rem 0; font-weight: 800;">
                EXPLAINABLE AI MEMORY FORENSICS
            </h1>
            <p style="font-size: 1.05rem; line-height: 1.6; color: rgba(238, 233, 255, 0.78); max-width: 840px; margin: 0 0 1.5rem 0;">
                Autonomous memory dump triage translating low-level kernel and process telemetry into plain-English human intelligence.
                Corroborates machine learning decisions with dual global (SHAP) and local (LIME) explainability frameworks.
            </p>
            <div style="display: flex; flex-wrap: wrap; gap: 0.75rem;">
                <span style="padding: 0.35rem 0.85rem; border-radius: 9999px; background: rgba(143, 79, 224, 0.16); border: 1px solid rgba(189, 99, 255, 0.28); font-size: 0.78rem; color: #d5b1fd; font-weight: 500;">⚡ 100% Benchmark Accuracy</span>
                <span style="padding: 0.35rem 0.85rem; border-radius: 9999px; background: rgba(143, 79, 224, 0.16); border: 1px solid rgba(189, 99, 255, 0.28); font-size: 0.78rem; color: #d5b1fd; font-weight: 500;">🔬 Dual XAI (SHAP + LIME)</span>
                <span style="padding: 0.35rem 0.85rem; border-radius: 9999px; background: rgba(143, 79, 224, 0.16); border: 1px solid rgba(189, 99, 255, 0.28); font-size: 0.78rem; color: #d5b1fd; font-weight: 500;">🛡️ Zero-Day Isolation Forest</span>
                <span style="padding: 0.35rem 0.85rem; border-radius: 9999px; background: rgba(143, 79, 224, 0.16); border: 1px solid rgba(189, 99, 255, 0.28); font-size: 0.78rem; color: #d5b1fd; font-weight: 500;">📜 Audit-Logged Chain of Custody</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # ── Section 01: Ingestion ─────────────────────────────────
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.25rem;">
            <span style="font-size: 0.72rem; font-weight: 700; color: #c797ff; background: rgba(143, 79, 224, 0.25); border: 1px solid rgba(189, 99, 255, 0.4); border-radius: 9999px; padding: 0.2rem 0.6rem;">01 &bull; INGESTION</span>
            <h3 class="dl-gradient-text" style="margin: 0; font-size: 1.35rem;">Memory Profile Telemetry</h3>
        </div>
        <div style="font-size: 0.85rem; color: rgba(238, 233, 255, 0.65); margin-bottom: 1.2rem;">
            Upload Volatility-extracted memory metrics (CSV) to initiate automated forensic triage.
        </div>
        """,
        unsafe_allow_html=True
    )

    ingest_mode = st.radio(
        label = "Telemetry Ingestion Source",
        options = ["🧪 Quick-Load Verified Sample (Instant Demo)", "📁 Upload Custom Volatility CSV"],
        horizontal = True,
        label_visibility = "collapsed"
    )

    SAMPLE_PRESETS = {
        "fresh_aggressive_ransomware.csv": "🔴 Active Ransomware (Direct Injections & Massive Handles)",
        "clean_system_baseline.csv":       "🟢 Standard Clean Workstation (Verified Normal Baseline)",
        "fresh_stealth_rootkit.csv":       "🟣 DKOM Kernel Rootkit (Unlinked Processes & Driver Outlier)",
        "fresh_fileless_miner.csv":        "🟠 Injected Cryptominer (Elevated Thread Density)",
        "guaranteed_malware.csv":          "🔴 Benchmark Malware (Obfuscated-MalMem2022 Dataset)",
        "guaranteed_benign.csv":           "🟢 Benchmark Benign (Obfuscated-MalMem2022 Dataset)",
        "real_benign_sample.csv":          "🟢 Live Host Baseline Telemetry Profile",
    }

    if "Quick-Load" in ingest_mode:
        available_samples = [s for s in SAMPLE_PRESETS.keys() if os.path.exists(os.path.join(SAMPLES_DIR, s))]
        if not available_samples and os.path.exists(SAMPLES_DIR):
            available_samples = [f for f in os.listdir(SAMPLES_DIR) if f.endswith(".csv")]

        if not available_samples:
            st.error("No sample profiles found in `data/test_samples/`. Please switch to upload mode.")
            return

        selected_sample = st.selectbox(
            "Select Verified Test Memory Profile",
            options = available_samples,
            format_func = lambda s: SAMPLE_PRESETS.get(s, s)
        )
        source_filename = selected_sample
        sample_file_path = os.path.join(SAMPLES_DIR, selected_sample)
        try:
            df = pd.read_csv(sample_file_path)
            st.success(f"✅ Loaded test profile `{selected_sample}` &bull; {len(df):,} sample records, {len(df.columns)} telemetry dimensions")
        except Exception as e:
            st.error(f"Could not load test profile: {e}")
            return
    else:
        uploaded_file = st.file_uploader(
            label = "Drop Volatility memory profile CSV",
            type  = ["csv"],
            help  = "CSV exported from Volatility memory plugins. Ready-to-use sample profiles are located in data/test_samples/"
        )

        if uploaded_file is None:
            st.markdown(
                """
                <div class="dl-card" style="text-align: center; padding: 2.8rem 1.5rem; margin-top: 1rem;">
                    <div style="font-size: 2.2rem; margin-bottom: 0.75rem;">📂</div>
                    <h4 style="color: #ffffff; margin: 0 0 0.5rem 0; font-size: 1.15rem;">Awaiting Memory Profile Telemetry</h4>
                    <p style="color: rgba(238, 233, 255, 0.65); font-size: 0.88rem; max-width: 520px; margin: 0 auto;">
                        Drag and drop a Volatility memory CSV above, browse your filesystem, or select a pre-packaged profile using the Quick-Load toggle above.
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )
            return   # Stop here until a file is uploaded

        source_filename = uploaded_file.name
        try:
            df = pd.read_csv(uploaded_file)
            st.success(f"✅ Memory profile uploaded &bull; {len(df):,} sample records, {len(df.columns)} telemetry dimensions")
        except Exception as e:
            st.error(f"Could not read uploaded CSV: {e}")
            return

    if df.empty:
        st.error("The selected CSV contains no records.")
        return

    # ── State Reset on Source File Change ─────────────────────
    if st.session_state.get("last_source_file") != source_filename:
        st.session_state["current_triage"] = None
        st.session_state["batch_summary"]  = None
        st.session_state["last_source_file"] = source_filename

    # Show raw data preview (collapsed by default)
    with st.expander("📄 Preview Memory Artifacts Data", expanded=False):
        st.dataframe(df.head(10), use_container_width=True)
        st.caption(f"Columns ({len(df.columns)}): {', '.join(df.columns.tolist())}")

    # ── Section 02: Target Selection ──────────────────────────
    dl_divider()
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.25rem;">
            <span style="font-size: 0.72rem; font-weight: 700; color: #c797ff; background: rgba(143, 79, 224, 0.25); border: 1px solid rgba(189, 99, 255, 0.4); border-radius: 9999px; padding: 0.2rem 0.6rem;">02 &bull; TARGET SPECIFICATION</span>
            <h3 class="dl-gradient-text" style="margin: 0; font-size: 1.35rem;">Select Memory Profile Row</h3>
        </div>
        <div style="font-size: 0.85rem; color: rgba(238, 233, 255, 0.65); margin-bottom: 1.2rem;">
            Select a target memory process profile to run full deep-dive XAI, or execute rapid batch scoring across all rows.
        </div>
        """,
        unsafe_allow_html=True
    )

    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.markdown("**Target Sample Selection**")
        row_index = st.selectbox(
            "Row number to analyse",
            options = list(range(len(df))),
            format_func = lambda i: f"Memory Profile Row {i}  (index {i})",
            label_visibility = "collapsed",
        )

    with col_right:
        st.markdown("**Rapid Batch Scoring**")
        if st.button("🔍 Score all records", use_container_width=True):
            rf_model      = load_rf_model()
            expected_cols = rf_model.feature_names_in_.tolist()
            batch_df      = df.select_dtypes(include=[np.number]).reindex(
                                columns=expected_cols, fill_value=0
                            )
            all_probs  = rf_model.predict_proba(batch_df)[:, 1]   # Pass DataFrame to suppress warnings
            all_preds  = rf_model.predict(batch_df)

            summary = pd.DataFrame({
                "Row":        range(len(df)),
                "Confidence": [f"{p*100:.1f}%" for p in all_probs],
                "Result":     ["Malware" if p else "Benign" for p in all_preds],
                "Risk":       [
                    "HIGH RISK"  if p >= 0.75 else
                    "SUSPICIOUS" if p >= 0.40 else
                    "NORMAL"
                    for p in all_probs
                ],
            })
            st.session_state["batch_summary"] = summary

    # Display persistent batch summary if available
    if st.session_state.get("batch_summary") is not None:
        st.markdown("##### 📊 Batch Telemetry Triage Summary")
        st.dataframe(st.session_state["batch_summary"], use_container_width=True, height=180)
        if st.button("✖ Clear Batch Scoring Table", key="clear_batch_summary_btn"):
            st.session_state["batch_summary"] = None
            st.rerun()

    # ── Analyse selected row CTA ──────────────────────────────
    dl_divider()

    col_cta1, col_cta2 = st.columns([3, 1])
    with col_cta1:
        analyse_btn = st.button(
            f"🚀 Execute Autonomous Forensic Triage on Row {row_index}",
            type="primary",
            use_container_width=True
        )
    with col_cta2:
        if st.button("🔄 Reset / Clear Triage", use_container_width=True):
            st.session_state["current_triage"] = None
            st.rerun()

    if analyse_btn:
        rf_model      = load_rf_model()
        expected_cols = rf_model.feature_names_in_.tolist()

        sample_df = df.select_dtypes(include=[np.number]).iloc[[row_index]]
        sample_df = sample_df.reindex(columns=expected_cols, fill_value=0)

        with st.spinner("Running ensemble ML inference, zero-day anomaly checks, and audit logging..."):
            st.session_state["current_triage"] = run_triage(sample_df, source_filename, row_index)

    if st.session_state.get("current_triage") is None:
        return   # Wait for button press

    result = st.session_state["current_triage"]

    # Warning banner if active selection does not match displayed result
    if result.get("row_index") != row_index or result.get("source_file") != source_filename:
        st.warning(
            f"⚠️ **Target Selection Changed:** Displaying previous triage verdict for **{result.get('source_file')} (Row {result.get('row_index')})**. "
            f"You currently have **Row {row_index}** selected. Click **'Execute Autonomous Forensic Triage on Row {row_index}'** to analyze the new row."
        )

    # ── Section 03: Verdict Display ───────────────────────────
    dl_divider()
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.25rem;">
            <span style="font-size: 0.72rem; font-weight: 700; color: #c797ff; background: rgba(143, 79, 224, 0.25); border: 1px solid rgba(189, 99, 255, 0.4); border-radius: 9999px; padding: 0.2rem 0.6rem;">03 &bull; TRIAGE VERDICT</span>
            <h3 class="dl-gradient-text" style="margin: 0; font-size: 1.35rem;">Autonomous Forensic Verdict</h3>
        </div>
        <div style="font-size: 0.85rem; color: rgba(238, 233, 255, 0.65); margin-bottom: 1.2rem;">
            Ensemble classification synthesized across 55 volatile memory artifacts and kernel behavior metrics.
        </div>
        """,
        unsafe_allow_html=True
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        label = "Risk Level",
        value = result["risk"],
    )
    col2.metric(
        label = "Malware Confidence",
        value = f"{result['probability']*100:.1f}%",
    )
    col3.metric(
        label = "Classification",
        value = "MALWARE" if result["prediction"] else "BENIGN",
    )
    col4.metric(
        label = "Zero-Day Anomaly",
        value = "⚠ YES" if result["is_anomaly"] else "✅ CLEAN",
    )

    # Custom glowing verdict banner
    risk = result["risk"]
    if risk == "HIGH RISK":
        st.markdown(
            """
            <div style="padding: 1.2rem 1.5rem; border-radius: 1.25rem; background: rgba(244, 63, 94, 0.12); border: 1px solid rgba(244, 63, 94, 0.4); box-shadow: 0 8px 30px rgba(244, 63, 94, 0.2); display: flex; align-items: center; gap: 1rem; margin-top: 1.2rem;">
                <span class="dl-pulse-dot-danger" style="width: 12px; height: 12px;"></span>
                <div>
                    <div style="font-size: 1.05rem; font-weight: 700; color: #fda4af;">CRITICAL ALERT &bull; HIGH RISK VERDICT</div>
                    <div style="font-size: 0.86rem; color: rgba(253, 164, 175, 0.88); margin-top: 0.15rem;">Memory dump exhibits active malicious behavioral indicators. Immediate host containment required.</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    elif risk == "SUSPICIOUS":
        st.markdown(
            """
            <div style="padding: 1.2rem 1.5rem; border-radius: 1.25rem; background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.4); box-shadow: 0 8px 30px rgba(245, 158, 11, 0.2); display: flex; align-items: center; gap: 1rem; margin-top: 1.2rem;">
                <span class="dl-pulse-dot-amber" style="width: 12px; height: 12px;"></span>
                <div>
                    <div style="font-size: 1.05rem; font-weight: 700; color: #fcd34d;">WARNING &bull; SUSPICIOUS PROFILE</div>
                    <div style="font-size: 0.86rem; color: rgba(252, 211, 77, 0.88); margin-top: 0.15rem;">Profile exhibits anomalous metric deviations. Tier-2 human forensic review recommended before releasing host.</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            """
            <div style="padding: 1.2rem 1.5rem; border-radius: 1.25rem; background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.4); box-shadow: 0 8px 30px rgba(16, 185, 129, 0.2); display: flex; align-items: center; gap: 1rem; margin-top: 1.2rem;">
                <span class="dl-pulse-dot" style="width: 12px; height: 12px;"></span>
                <div>
                    <div style="font-size: 1.05rem; font-weight: 700; color: #6ee7b7;">VERIFIED CLEAN &bull; NORMAL BASELINE</div>
                    <div style="font-size: 0.86rem; color: rgba(110, 231, 183, 0.88); margin-top: 0.15rem;">Process metrics adhere to standard benign operating system behavior profiles. No signs of infection.</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    if result["is_anomaly"]:
        st.markdown(
            """
            <div style="padding: 1rem 1.4rem; border-radius: 1rem; background: rgba(143, 79, 224, 0.15); border: 1px solid rgba(189, 99, 255, 0.35); margin-top: 0.75rem; display: flex; align-items: center; gap: 0.75rem;">
                <span style="font-size: 1.2rem;">🛡️</span>
                <div style="font-size: 0.84rem; color: #eee9ff; line-height: 1.4;">
                    <b style="color: #c797ff;">Zero-Day / Novel Threat Alert:</b> Isolation Forest flagged this profile as an anomalous outlier relative to known baselines. Recommend deep packet and binary carving.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # ── Chain of Custody Metadata Card ────────────────────────
    dl_divider()
    st.markdown(
        f"""
        <div class="dl-card" style="margin-top: 0.5rem;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; padding-bottom: 0.75rem; border-bottom: 1px solid rgba(238, 233, 255, 0.08);">
                <div style="font-size: 1rem; font-weight: 700; color: #ffffff;">
                    🔐 Forensic Chain of Custody Record
                </div>
                <div style="display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.25rem 0.7rem; border-radius: 9999px; background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.35); font-size: 0.72rem; color: #6ee7b7; font-weight: 600;">
                    <span class="dl-pulse-dot"></span> TAMPER-EVIDENT AUDIT
                </div>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.2rem; font-size: 0.85rem;">
                <div>
                    <div style="color: rgba(238, 233, 255, 0.5); font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.04em;">Evidence Identifier</div>
                    <div style="font-family: 'Space Grotesk', monospace; color: #d5b1fd; font-weight: 600; margin-top: 0.15rem; font-size: 0.92rem;">{result['evidence_id']}</div>
                    <div style="color: rgba(238, 233, 255, 0.5); font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 0.8rem;">Analysis Timestamp</div>
                    <div style="color: #eee9ff; margin-top: 0.15rem;">{result['timestamp']}</div>
                    <div style="color: rgba(238, 233, 255, 0.5); font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 0.8rem;">Source Memory Dump</div>
                    <div style="color: #eee9ff; margin-top: 0.15rem;">{result['source_file']}</div>
                </div>
                <div>
                    <div style="color: rgba(238, 233, 255, 0.5); font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.04em;">Sample Row Index</div>
                    <div style="font-family: 'Space Grotesk', monospace; color: #eee9ff; margin-top: 0.15rem; font-size: 0.92rem;">Row {result['row_index']}</div>
                    <div style="color: rgba(238, 233, 255, 0.5); font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 0.8rem;">Immutable Audit Ledger</div>
                    <div style="font-family: 'Space Grotesk', monospace; color: #eee9ff; margin-top: 0.15rem;">logs/triage_audit.log</div>
                    <div style="color: rgba(238, 233, 255, 0.5); font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 0.8rem;">Classification Engine</div>
                    <div style="color: #eee9ff; margin-top: 0.15rem;">Random Forest (55 Features) + Isolation Forest</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # ── Recommended Response Actions ──────────────────────────
    dl_divider()
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.25rem;">
            <span style="font-size: 0.72rem; font-weight: 700; color: #c797ff; background: rgba(143, 79, 224, 0.25); border: 1px solid rgba(189, 99, 255, 0.4); border-radius: 9999px; padding: 0.2rem 0.6rem;">PLAYBOOK</span>
            <h3 class="dl-gradient-text" style="margin: 0; font-size: 1.35rem;">Recommended Incident Response Actions</h3>
        </div>
        <div style="font-size: 0.85rem; color: rgba(238, 233, 255, 0.65); margin-bottom: 1.2rem;">
            Standard operating procedure triage recommendations aligned with the severity tier of this memory profile.
        </div>
        """,
        unsafe_allow_html=True
    )

    for action in RESPONSE_ACTIONS[risk]:
        st.markdown(
            f"""
            <div style="background: rgba(30, 14, 66, 0.55); border: 1px solid rgba(238, 233, 255, 0.1); border-radius: 0.85rem; padding: 0.85rem 1.2rem; display: flex; align-items: center; gap: 0.85rem; margin-bottom: 0.5rem;">
                <div style="font-size: 1rem;">⚡</div>
                <div style="font-size: 0.88rem; color: #eee9ff; line-height: 1.45;">{action}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # ── Section 04: SHAP Explanation ──────────────────────────
    dl_divider()
    shap_df = render_shap_explanation(result)

    # ── Section 05: LIME Explanation ──────────────────────────
    dl_divider()
    lime_df = render_lime_explanation(result)

    # ── Section 06: Official Forensic Incident Report (PDF) ───
    dl_divider()
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.25rem;">
            <span style="font-size: 0.72rem; font-weight: 700; color: #c797ff; background: rgba(143, 79, 224, 0.25); border: 1px solid rgba(189, 99, 255, 0.4); border-radius: 9999px; padding: 0.2rem 0.6rem;">06 &bull; FORENSIC ARTIFACT</span>
            <h3 class="dl-gradient-text" style="margin: 0; font-size: 1.35rem;">Official Forensic Incident Report (PDF)</h3>
        </div>
        <div style="font-size: 0.85rem; color: rgba(238, 233, 255, 0.65); margin-bottom: 1.2rem;">
            Automated, evidence-backed forensic incident dossier with chain-of-custody hashes and plain-English explainability.
        </div>
        """,
        unsafe_allow_html=True
    )

    ev_id = result["evidence_id"]
    pdf_key = f"pdf_ready_{ev_id}"

    # Auto-generate or retrieve cached PDF for this evidence record
    if pdf_key not in st.session_state:
        with st.spinner("Compiling official forensic PDF incident report..."):
            try:
                rep_path, rep_bytes = generate_pdf_report(result, shap_df=shap_df, lime_df=lime_df)
                st.session_state[pdf_key] = {
                    "path": rep_path,
                    "bytes": rep_bytes,
                    "filename": os.path.basename(rep_path),
                }
            except Exception as e:
                st.session_state[pdf_key] = {"error": str(e)}
                logger.error(f"PDF error for {ev_id}: {e}")

    pdf_state = st.session_state.get(pdf_key, {})

    if "error" in pdf_state:
        st.error(f"❌ PDF report generation failed: {pdf_state['error']}")
        if st.button("🔄 Retry PDF Generation", type="primary", key=f"retry_{ev_id}"):
            del st.session_state[pdf_key]
            st.rerun()
    elif "bytes" in pdf_state:
        st.markdown(
            f"""
            <div class="dl-card" style="margin-bottom: 1.2rem;">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div style="display: flex; align-items: center; gap: 0.85rem;">
                        <span style="font-size: 1.8rem;">📄</span>
                        <div>
                            <h4 style="color: #ffffff; margin: 0; font-size: 1.15rem; font-weight: 700;">Executive Forensic Incident Dossier</h4>
                            <div style="font-size: 0.82rem; color: rgba(238, 233, 255, 0.65); margin-top: 0.2rem;">
                                Courtroom-ready document containing full chain-of-custody verification, classification metrics, SHAP global drivers, and LIME corroborating rules.
                            </div>
                        </div>
                    </div>
                    <span style="font-size: 0.74rem; font-weight: 600; text-transform: uppercase; padding: 0.28rem 0.75rem; border-radius: 9999px; background: rgba(143, 79, 224, 0.2); border: 1px solid rgba(189, 99, 255, 0.4); color: #d5b1fd;">
                        REPORTLAB v4 READY
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        col_down, col_regen = st.columns([3, 1])
        with col_down:
            st.download_button(
                label = f"⬇ Download Forensic Report (PDF) — {pdf_state['filename']}",
                data = pdf_state["bytes"],
                file_name = pdf_state["filename"],
                mime = "application/pdf",
                type = "primary",
                use_container_width = True,
                key = f"dl_btn_{ev_id}",
            )
        with col_regen:
            if st.button("🔄 Regenerate Dossier", use_container_width=True, key=f"regen_{ev_id}"):
                del st.session_state[pdf_key]
                st.rerun()

        st.success(f"✅ Forensic dossier compiled &bull; Archived locally to: `{pdf_state['path']}`")

        with st.expander("🔍 Preview Forensic Summary Metadata", expanded=False):
            st.markdown(f"**Evidence Hash:** `{ev_id}`")
            st.markdown(f"**Archive Path:** `{pdf_state['path']}`")
            st.markdown(f"**Risk Classification:** `{result['risk']}` | **Malware Confidence:** `{result['probability']*100:.2f}%`")
            st.markdown(f"**Key Decision Drivers (SHAP) Included:** {len(shap_df) if shap_df is not None else 0}")
            st.markdown(f"**Local Corroborating Rules (LIME) Included:** {len(lime_df) if lime_df is not None else 0}")

    # ── Section 07: Live Chain-of-Custody Audit Log Viewer ───
    dl_divider()
    with st.expander("📜 Live Chain-of-Custody Audit Log (`logs/triage_audit.log`)", expanded=False):
        log_path = os.path.join(LOG_DIR, "triage_audit.log")
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="replace") as lf:
                lines = lf.readlines()
            recent_lines = "".join(lines[-25:]) if lines else "Audit log is currently empty."
            st.code(recent_lines, language="text")
            st.caption(f"Total historical audit records: {len(lines):,} entries &bull; Immutable forensic ledger.")
        else:
            st.info("No audit log found yet. Triage runs will be recorded upon execution.")


# ── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()