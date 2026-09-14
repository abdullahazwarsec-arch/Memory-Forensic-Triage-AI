from pathlib import Path

import pandas as pd
import shap
import joblib
import matplotlib.pyplot as plt

BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_PATH = BASE_DIR / "models" / "random_forest_model.pkl"
DATA_PATH = BASE_DIR / "data" / "Obfuscated-MalMem2022.csv"
OUTPUTS_DIR = BASE_DIR / "outputs"

# 1. Load the saved AI Brain
print("Loading saved AI model...")
model = joblib.load(MODEL_PATH)

# 2. Load the dataset
print("Loading dataset for explanation...")
df = pd.read_csv(DATA_PATH)
df['Class'] = df['Class'].apply(lambda x: 0 if x == 'Benign' else 1)
if 'Category' in df.columns:
    df = df.drop(columns=['Category'])

X = df.drop(columns=['Class'])

# We only need a small sample of data to generate the plot (100 rows is fast and effective)
X_sample = X.sample(100, random_state=42)

# 3. Create the SHAP Explainer
print("Interrogating the AI with SHAP...")
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_sample)

# Random Forest binary classifiers output two sets of explanations (Safe vs Malware).
# We want to explain the 'Malware' class (Class 1)
if isinstance(shap_values, list):
    malware_explanations = shap_values[1]
elif len(shap_values.shape) == 3:
    malware_explanations = shap_values[:, :, 1]
else:
    malware_explanations = shap_values

# 4. Generate and save the Summary Plot
print("Creating visual explanation plot...")
plt.figure(figsize=(10, 6))
shap.summary_plot(malware_explanations, X_sample, show=False)

plt.savefig(OUTPUTS_DIR / "shap_summary.png", bbox_inches='tight', dpi=300)
print(f"✅ Explainable AI plot saved successfully as '{OUTPUTS_DIR / 'shap_summary.png'}'!")