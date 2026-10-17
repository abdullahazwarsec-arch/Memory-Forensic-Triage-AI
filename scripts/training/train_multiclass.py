"""
SUPERSEDED - kept for reference only. Use scripts/training/train_models.py, which removes duplicate
rows, evaluates with folds grouped by malware sample and writes models/model_card.json.
This old script used a random split (optimistic accuracy) and would overwrite the deployed model.
"""
import sys
sys.exit("Superseded: run scripts/training/train_models.py instead.")

from pathlib import Path

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_PATH = BASE_DIR / "data" / "Obfuscated-MalMem2022.csv"
MODEL_PATH = BASE_DIR / "models" / "multiclass_random_forest.pkl"

print("--- Step 1 (Corrected): Multi-Class Malware Family Training ---")

# 1. Load dataset
df = pd.read_csv(DATA_PATH)

# 2. Extract base malware family using string matching prefixes
def extract_family(cat_val):
    cat_str = str(cat_val)
    if 'Benign' in cat_str:
        return 'Benign'
    elif 'Ransomware' in cat_str:
        return 'Ransomware'
    elif 'Spyware' in cat_str:
        return 'Spyware'
    elif 'Trojan' in cat_str:
        return 'Trojan'
    else:
        return 'Unknown'

df['Base_Family'] = df['Category'].apply(extract_family)
df = df[df['Base_Family'] != 'Unknown']

print("Parsed Malware Family Distribution:")
print(df['Base_Family'].value_counts())

# Map families to integers
family_mapping = {'Benign': 0, 'Spyware': 1, 'Ransomware': 2, 'Trojan': 3}
df['Multi_Class'] = df['Base_Family'].map(family_mapping)

X = df.drop(columns=['Class', 'Category', 'Base_Family', 'Multi_Class'], errors='ignore')
y = df['Multi_Class'].astype(int)

# 3. Stratified Train/Test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

# 4. Initialize and train Multi-Class Random Forest
multiclass_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    min_samples_split=10,
    min_samples_leaf=4,
    random_state=42,
    n_jobs=-1
)

print("Training Multi-Class Random Forest across malware families...")
multiclass_model.fit(X_train, y_train)

# 5. Evaluate
y_pred = multiclass_model.predict(X_test)
print("\nMulti-Class Classification Report on Unseen Test Data:")
print(classification_report(y_test, y_pred, target_names=['Benign', 'Spyware', 'Ransomware', 'Trojan'], digits=4))

# Save multiclass model
joblib.dump(multiclass_model, MODEL_PATH)
print(f"✅ Saved model as '{MODEL_PATH.name}'.")