from pathlib import Path
import pandas as pd
import numpy as np
import joblib

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_PATH = BASE_DIR / "models" / "random_forest_model.pkl"
OUTPUT_DIR = BASE_DIR / "data" / "test_samples"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("--- Generating Fresh Synthetic Threat Profiles ---")

# 1. Load the model to get the exact expected feature columns
model = joblib.load(MODEL_PATH)
expected_features = list(model.feature_names_in_)

# 2. Helper function to create a clean baseline system profile
def create_baseline():
    df = pd.DataFrame(0, index=[0], columns=expected_features)
    if 'pslist.nproc' in df.columns: df['pslist.nproc'] = 45
    if 'svcscan.nservices' in df.columns: df['svcscan.nservices'] = 120
    if 'handles.avg_handles_per_proc' in df.columns: df['handles.avg_handles_per_proc'] = 150
    return df

# --- THREAT PROFILE 1: Stealth Rootkit (DKOM) ---
rootkit = create_baseline()
if 'psxview.not_in_eprocess' in rootkit.columns: rootkit['psxview.not_in_eprocess'] = 3
if 'svcscan.shared_process_services' in rootkit.columns: rootkit['svcscan.shared_process_services'] = 250
out_rootkit = OUTPUT_DIR / "fresh_stealth_rootkit.csv"
rootkit.to_csv(out_rootkit, index=False)
print(f"[+] Created: {out_rootkit} (Expected XAI Focus: Hidden Processes / DKOM)")

# --- THREAT PROFILE 2: Aggressive Ransomware ---
ransomware = create_baseline()
if 'handles.avg_handles_per_proc' in ransomware.columns: ransomware['handles.avg_handles_per_proc'] = 9850
if 'pslist.avg_threads' in ransomware.columns: ransomware['pslist.avg_threads'] = 85
out_ransomware = OUTPUT_DIR / "fresh_aggressive_ransomware.csv"
ransomware.to_csv(out_ransomware, index=False)
print(f"[+] Created: {out_ransomware} (Expected XAI Focus: Resource Handle Spike)")

# --- THREAT PROFILE 3: Fileless Cryptominer ---
cryptominer = create_baseline()
if 'malfind.ninjections' in cryptominer.columns: cryptominer['malfind.ninjections'] = 5
if 'pslist.avg_threads' in cryptominer.columns: cryptominer['pslist.avg_threads'] = 450
if 'ldrmodules.not_in_load' in cryptominer.columns: cryptominer['ldrmodules.not_in_load'] = 2
out_miner = OUTPUT_DIR / "fresh_fileless_miner.csv"
cryptominer.to_csv(out_miner, index=False)
print(f"[+] Created: {out_miner} (Expected XAI Focus: Code Injection & Threads)")

print(f"\n[+] Fresh threat profiles generated into {OUTPUT_DIR}! Ready for dashboard testing.")