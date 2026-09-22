from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "Obfuscated-MalMem2022.csv"
OUTPUT_DIR = BASE_DIR / "data" / "test_samples"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("--- Extracting a Real Benign System Profile ---")
if not DATA_PATH.exists():
    print(f"[-] Dataset not found at: {DATA_PATH}")
    exit(1)

df = pd.read_csv(DATA_PATH)

# 1. Filter for a genuinely benign memory dump
benign_df = df[df['Class'] == 'Benign'].head(1)

# 2. Drop ground-truth labels
clean_sample = benign_df.drop(columns=['Class', 'Category'], errors='ignore')

# 3. Save to data/test_samples/
out_path = OUTPUT_DIR / "real_benign_sample.csv"
clean_sample.to_csv(out_path, index=False)
print(f"[+] Saved: {out_path} (Authentic normal baseline)")