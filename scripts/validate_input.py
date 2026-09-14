from pathlib import Path

import pandas as pd
import numpy as np
import joblib

BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_PATH = BASE_DIR / "models" / "random_forest_model.pkl"
DATA_DIR = BASE_DIR / "data"

print("--- Step 2: Setting up Evidence-Gating & Sanity Checks ---")

# Load model to get expected features
model = joblib.load(MODEL_PATH)
expected_features = list(model.feature_names_in_)

def validate_forensic_csv(file_path):
    """
    Validates an input memory feature CSV file for structural integrity,
    missing values, and feature alignment prior to triage execution.
    """
    report = {"status": "PASS", "warnings": [], "errors": []}
    
    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        report["status"] = "FAIL"
        report["errors"].append(f"File parsing error: {str(e)}")
        return report

    # Check 1: Empty file check
    if df.empty:
        report["status"] = "FAIL"
        report["errors"].append("Uploaded CSV file is completely empty.")
        return report

    # Check 2: Check for missing required features
    # Handle both dot and underscore notations via mapping
    cleaned_columns = [col.replace('_', '.') for col in df.columns]
    missing_features = [feat for feat in expected_features if feat not in cleaned_columns and feat not in df.columns]
    
    if len(missing_features) > 0:
        report["warnings"].append(f"Missing {len(missing_features)} expected features. They will be auto-filled with 0s.")

    # Check 3: Check for NaN / Null values
    if df.isnull().sum().sum() > 0:
        report["warnings"].append("Null/NaN values detected in features. Imputing missing slots with 0.")

    print(f"Validation Report for '{file_path}':")
    print(f"  Status: {report['status']}")
    if report["warnings"]:
        for w in report["warnings"]:
            print(f"  ⚠️ Warning: {w}")
    if report["errors"]:
        for e in report["errors"]:
            print(f"  ❌ Error: {e}")
            
    return report

# Test validation using one of our existing files
if __name__ == "__main__":
    validate_forensic_csv(DATA_DIR / "simulated_cobalt_strike.csv")    