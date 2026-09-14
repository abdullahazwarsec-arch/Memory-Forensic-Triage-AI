import os
import joblib
import pandas as pd
import streamlit as st

# Configure page layout
st.set_page_config(
    page_title="Memory Forensics AI Triage",
    page_icon="🛡️",
    layout="wide"
)

# Header section
st.title("🛡️ Explainable AI Memory Forensic Triage Dashboard")
st.markdown("Automated triage system for detecting memory-resident / fileless threats using Random Forest and SHAP.")

st.divider()

# Sidebar: Model and Dataset Status
st.sidebar.header("System Configuration")
model_path = "random_forest_model.pkl"
data_path = "Obfuscated-MalMem2022.csv"
shap_img_path = "shap_summary.png"

if os.path.exists(model_path):
    st.sidebar.success("✅ Model: Loaded (`random_forest_model.pkl`)")
else:
    st.sidebar.error("❌ Model file not found!")

if os.path.exists(data_path):
    st.sidebar.success("✅ Dataset: Available (`Obfuscated-MalMem2022.csv`)")
else:
    st.sidebar.error("❌ Dataset not found!")

# Main Analysis Section
st.subheader("Memory Evidence Analysis")
st.write("Simulate scanning an extracted memory profile to evaluate forensic artifacts:")

# Load model and sample dataset
@st.cache_resource
def load_assets():
    model = joblib.load(model_path)
    df = pd.read_csv(data_path)
    return model, df

try:
    model, df = load_assets()

    # Create sample options: Pick 1 benign sample or 1 malware sample for testing
    col1, col2 = st.columns([2, 1])

    with col1:
        sample_type = st.radio(
            "Select a memory sample to analyze:",
            ("Random Unknown Sample", "Forced Benign Baseline", "Forced Obfuscated Malware"),
            horizontal=True
        )

    # Filter row based on selection
    if sample_type == "Forced Benign Baseline":
        test_row = df[df['Class'] == 'Benign'].sample(1, random_state=10)
    elif sample_type == "Forced Obfuscated Malware":
        test_row = df[df['Class'] != 'Benign'].sample(1, random_state=10)
    else:
        test_row = df.sample(1)

    # Prepare features for the model
    features_to_drop = [col for col in ['Class', 'Category'] if col in test_row.columns]
    feature_row = test_row.drop(columns=features_to_drop)

    # Triage Execution Button
    if st.button("Run Forensic Triage Scan", type="primary"):
        prediction = model.predict(feature_row)[0]
        prediction_proba = model.predict_proba(feature_row)[0]

        st.subheader("Triage Results")
        res_col1, res_col2 = st.columns(2)

        if prediction == 1:
            res_col1.error("🚨 **MALICIOUS ACTIVITY DETECTED**")
            res_col1.metric("Malware Confidence Score", f"{prediction_proba[1] * 100:.2f}%")
        else:
            res_col1.success("✅ **BENIGN / NORMAL SYSTEM STATE**")
            res_col1.metric("Benign Confidence Score", f"{prediction_proba[0] * 100:.2f}%")

        with res_col2:
            st.write("**Extracted Memory Profile Snapshot:**")
            st.dataframe(feature_row.iloc[:, :6])  # Display first 6 key features

        st.divider()

        # Explainability (XAI) Section
        st.subheader("🔍 Explainable AI (SHAP) Forensic Reasoning")
        st.write(
            "The plot below highlights the top memory artifacts that influenced the AI model's triage decision:"
        )

        if os.path.exists(shap_img_path):
            st.image(shap_img_path, caption="SHAP Summary Plot - Feature Importance in RAM", use_container_width=True)
        else:
            st.warning("SHAP plot image not found. Run explain_model.py to generate shap_summary.png.")

except Exception as e:
    st.error(f"Error during triage execution: {e}")