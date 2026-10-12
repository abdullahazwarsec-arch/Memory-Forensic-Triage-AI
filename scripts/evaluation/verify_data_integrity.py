from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_PATH = BASE_DIR / "data" / "Obfuscated-MalMem2022.csv"

if not DATA_PATH.exists():
    print(f"❌ Dataset not found at: {DATA_PATH}")
    exit(1)

df = pd.read_csv(DATA_PATH)

print("--- DATASET INTEGRITY AUDIT ---")
print(f"Dataset Path: {DATA_PATH}")
print(f"Total Rows: {len(df):,}")
print(f"Duplicate Rows: {df.duplicated().sum()}")

# Check for label leakage
leakage_cols = [c for c in df.columns if 'class' in c.lower() or 'category' in c.lower()]
print(f"Ground Truth Label Columns Detected: {leakage_cols}")

# Feature count check
feature_cols = [c for c in df.columns if c not in leakage_cols]
print(f"Clean Independent Features Count: {len(feature_cols)}")