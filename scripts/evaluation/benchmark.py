from pathlib import Path

import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_PATH = BASE_DIR / "data" / "Obfuscated-MalMem2022.csv"

print("--- Step 3: Comparative Model Benchmarking ---")

# 1. Load Dataset
df = pd.read_csv(DATA_PATH)
df['Class'] = df['Class'].apply(lambda x: 0 if x == 'Benign' else 1)
if 'Category' in df.columns:
    df = df.drop(columns=['Category'])

y = df['Class']
X = df.drop(columns=['Class'])

# 2. Define Models to Benchmark
models = {
    "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1),
    "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, max_depth=6, random_state=42),
    "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42)
}

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
results = {}

# 3. Cross-validate each model
for name, model in models.items():
    print(f"Evaluating {name} across 5 folds...")
    scores = cross_val_score(model, X, y, cv=cv, scoring='f1', n_jobs=-1)
    results[name] = scores.mean()
    print(f"  -> Mean F1-Score: {scores.mean() * 100:.2f}% (+/- {scores.std() * 100:.2f}%)")

print("\n--- Benchmark Summary ---")
for name, f1 in results.items():
    print(f"{name}: {f1 * 100:.2f}% F1")