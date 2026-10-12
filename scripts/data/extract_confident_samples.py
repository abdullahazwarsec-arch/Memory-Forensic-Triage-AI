from pathlib import Path
import pandas as pd
import joblib

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_PATH = BASE_DIR / "models" / "random_forest_model.pkl"
DATA_PATH = BASE_DIR / "data" / "Obfuscated-MalMem2022.csv"
OUTPUT_DIR = BASE_DIR / "data" / "test_samples"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("--- Extracting Confident Test Samples ---")
# 1. Load Model
model = joblib.load(MODEL_PATH)

# 2. Load Dataset
df = pd.read_csv(DATA_PATH)

# 3. Format data and calculate probabilities for the entire dataset
expected_cols = list(model.feature_names_in_)
X = df[expected_cols]
probs = model.predict_proba(X)
df['Malware_Prob'] = probs[:, 1] # Index 1 is the Malware probability

# 4. Extract a guaranteed Benign sample (Less than 5% malware probability)
benign_sample = df[(df['Class'] == 'Benign') & (df['Malware_Prob'] < 0.05)].head(1)
benign_out = OUTPUT_DIR / "guaranteed_benign.csv"
benign_sample[expected_cols].to_csv(benign_out, index=False)
print(f"[+] Saved: {benign_out} (Model Confidence: ~0% Risk)")

# 5. Extract a guaranteed Malware sample (Greater than 95% malware probability)
malware_sample = df[(df['Class'] == 'Malware') & (df['Malware_Prob'] > 0.95)].head(1)
malware_out = OUTPUT_DIR / "guaranteed_malware.csv"
malware_sample[expected_cols].to_csv(malware_out, index=False)
print(f"[+] Saved: {malware_out} (Model Confidence: ~100% Risk)")