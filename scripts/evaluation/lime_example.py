from pathlib import Path

import pandas as pd
import joblib
from lime.lime_tabular import LimeTabularExplainer

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_PATH = BASE_DIR / "models" / "random_forest_model.pkl"
DATA_PATH = BASE_DIR / "data" / "Obfuscated-MalMem2022.csv"

print("--- Step 4: Initializing LIME Explainer ---")

# Load model and data
model = joblib.load(MODEL_PATH)
df = pd.read_csv(DATA_PATH)
df['Class'] = df['Class'].apply(lambda x: 0 if x == 'Benign' else 1)
if 'Category' in df.columns:
    df = df.drop(columns=['Category'])

X = df.drop(columns=['Class'])
feature_names = list(X.columns)

# Initialize LIME Tabular Explainer
explainer = LimeTabularExplainer(
    training_data=X.values,
    feature_names=feature_names,
    class_names=['Benign', 'Malware'],
    mode='classification',
    random_state=42
)

# Pick an instance to explain (e.g., first malware row)
sample_idx = df[df['Class'] == 1].index[0]
sample_instance = X.loc[sample_idx].values

# Generate LIME local explanation
exp = explainer.explain_instance(
    data_row=sample_instance,
    predict_fn=model.predict_proba,
    num_features=5
)

print(f"\nLIME Local Explanation for Instance #{sample_idx}:")
for feature, weight in exp.as_list():
    print(f"  - {feature}: {weight:.4f}")

print("[+] LIME explainer successfully executed!")