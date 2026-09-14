from pathlib import Path

import joblib
import pandas as pd
import shap
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
OUTPUTS_DIR = BASE_DIR / "outputs"

# Configure page layout
st.set_page_config(page_title="Memory Forensics AI Triage", page_icon="🛡️", layout="wide")

# Header section
st.title("🛡️ Explainable AI Memory Forensic Triage Dashboard")
st.markdown("**Project Outcome:** A prototype forensic triage system for memory-resident / fileless malware using Random Forest and SHAP.")
st.divider()

# Load model
@st.cache_resource
def load_assets():
    model = joblib.load(MODELS_DIR / "random_forest_model.pkl")
    return model

model = load_assets()
expected_features = list(model.feature_names_in_)

# Plain-English forensic translation dictionary
reason_mapping = {
    'pslist.nproc': "Suspicious process execution pattern (abnormal process count)",
    'psxview.not_in_eprocess': "Hidden execution (process unhooked from Windows task structures)",
    'malfind.ninjections': "Unusual memory access (unauthorized code injection detected in RAM)",
    'dlllist.ndlls': "Suspicious loaded modules (abnormal DLL count or injection)",
    'handles.nfile': "Unusual file handle activity (process accessing unauthorized files)",
    'callbacks.ncallbacks': "Kernel-level manipulation (suspicious system callback registration)",
    'ldrmodules.not_in_load': "Stealth DLL hiding (module unlinked from process loader list)"
}

# --- STEP 1: INPUT INGESTION ---
st.subheader("📁 Step 1: Memory Dump Ingestion")
st.write("Upload an extracted memory feature profile (CSV format) or test against built-in snapshots.")

uploaded_file = st.file_uploader("Upload Extracted Memory Feature File (CSV)", type=["csv"])

if uploaded_file is not None:
    df_raw = pd.read_csv(uploaded_file)
    st.success(f"Uploaded `{uploaded_file.name}` ({df_raw.shape[0]} rows, {df_raw.shape[1]} columns).")
    
    # If the file contains multiple records, allow selecting a row
    if len(df_raw) > 1:
        row_idx = st.number_input(
            f"Select memory profile index to scan (0 to {len(df_raw)-1}):", 
            min_value=0, 
            max_value=len(df_raw)-1, 
            value=0
        )
        df_to_analyze = df_raw.iloc[[row_idx]]
    else:
        df_to_analyze = df_raw.iloc[[0]]
else:
    st.info("No external file uploaded. Select a built-in test case for prototype demonstration:")
    test_df = pd.read_csv(DATA_DIR / "Obfuscated-MalMem2022.csv")
    sample_type = st.radio(
        "Select a baseline test scenario:", 
        ("Benign / Clean Baseline", "Obfuscated Malware Sample"),
        horizontal=True
    )
    
    if sample_type == "Benign / Clean Baseline":
        df_to_analyze = test_df[test_df['Class'] == 'Benign'].sample(1, random_state=42)
    else:
        df_to_analyze = test_df[test_df['Class'] != 'Benign'].sample(1, random_state=42)

# --- FEATURE ALIGNMENT & SANITIZATION ---
# 1. Map underscore naming (Kaggle variant) to dot notation (original training set)
rename_dict = {}
for feat in expected_features:
    underscore_version = feat.replace('.', '_')
    if underscore_version in df_to_analyze.columns and feat not in df_to_analyze.columns:
        rename_dict[underscore_version] = feat

df_aligned = df_to_analyze.rename(columns=rename_dict)

# 2. Reindex strictly to model features; drops extra columns (Label, Raw_Type, etc.) and fills missing with 0
X_eval = df_aligned.reindex(columns=expected_features, fill_value=0)

# Initialize default triage state so the app can render safely before a prediction is run
risk_level = "Normal"
risk_display = "🟢 NORMAL"
recommendation = "No immediate action required. Monitor as standard."

# --- STEP 2: TRIAGE EXECUTION ---
if st.button("Run Automated Forensic Triage", type="primary"):
    
    # Calculate Probabilities
    prediction_proba = model.predict_proba(X_eval)[0]
    malware_score = prediction_proba[1] * 100

    # Three-tier triage categorization
    if malware_score >= 75:
        risk_level = "High Risk"
        risk_display = "🔴 HIGH RISK"
        recommendation = "Isolate system immediately. Begin incident response."
    elif malware_score >= 40:
        risk_level = "Suspicious"
        risk_display = "🟡 SUSPICIOUS — Needs Analyst Review"
        recommendation = "Do not act automatically. Flag for human review."
    else:
        risk_level = "Normal"
        risk_display = "🟢 NORMAL"
        recommendation = "No immediate action required. Monitor as standard."

    st.divider()
    st.subheader("📊 Step 2: Triage Assessment & Metrics")
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Risk Classification", risk_display)
    col2.metric("Malware Probability", f"{malware_score:.2f}%")
    col3.metric("Evaluated Artifacts", f"{len(expected_features)} features")

    st.info(f"**Verdict & Recommendation:** {recommendation}")

    # --- STEP 3: EXPLAINABILITY (SHAP REASONING) ---
    st.divider()
    st.subheader("🔍 Step 3: Forensic Reasoning (Why it was Flagged)")
    
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_eval)
    
    if isinstance(shap_values, list):
        current_shap = shap_values[1][0]
    elif len(shap_values.shape) == 3:
        current_shap = shap_values[0, :, 1]
    else:
        current_shap = shap_values[0]

    feature_importance = pd.DataFrame({'Feature': expected_features, 'Importance': current_shap})
    top_suspicious = feature_importance.sort_values(by='Importance', ascending=False).head(3)

    st.markdown("**Top Forensic Indicators Identified:**")
    for _, row in top_suspicious.iterrows():
        feat_name = row['Feature']
        reason_text = reason_mapping.get(feat_name, f"Abnormal statistical deviation in memory metric `{feat_name}`")
        st.markdown(f"- 🔴 **{reason_text}**")

    # --- STEP 4: INCIDENT RESPONSE RECOMMENDATIONS ---
    st.divider()
    st.subheader("🛠️ Step 4: Recommended Next Actions")
    if risk_level in ["High Risk", "Suspicious"]:
        st.markdown("""
        1. **Endpoint Containment:** Isolate the host machine from the internal network immediately.
        2. **Artifact Extraction:** Carve out injected process memory spaces using `volatility -f <dump> windows.malfind.Malfind --dump`.
        3. **Network Corroboration:** Cross-reference active sockets against external Threat Intelligence logs.
        """)
    else:
        st.markdown("1. Log the memory profile baseline into the system integrity log and close the investigation ticket.")