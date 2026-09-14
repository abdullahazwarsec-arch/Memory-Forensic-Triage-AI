from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    ConfusionMatrixDisplay,
    roc_curve,
    auc,
)

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_PATH = BASE_DIR / "data" / "Obfuscated-MalMem2022.csv"
MODELS_DIR = BASE_DIR / "models"
OUTPUTS_DIR = BASE_DIR / "outputs"

print("=" * 70)
print("ACADEMIC MODEL EVALUATION & MODEL COMPARISON PIPELINE")
print("=" * 70)

print("\n[1/5] Loading and preparing dataset...")
df = pd.read_csv(DATA_PATH)
df['Class'] = df['Class'].apply(lambda x: 1 if x != 'Benign' else 0)
if 'Category' in df.columns:
    df = df.drop(columns=['Category'])

y = df['Class']
X = df.drop(columns=['Class'])

print("[2/5] Performing stratified 80/20 train-test split...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

CV_FOLDS = 3
cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=42)

models = {
    "Logistic Regression": make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=2000, random_state=42)
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_split=10,
        min_samples_leaf=4,
        max_features='sqrt',
        random_state=42,
        n_jobs=-1,
    ),
}

results = []
trained_models = {}

print("\n[3/5] Training and evaluating multiple models...")
for name, model in models.items():
    print(f"\n--- Evaluating {name} ---")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        "model": name,
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "f1_score": f1_score(y_test, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_test, y_proba),
    }

    cv_f1_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring='f1', n_jobs=-1)
    cv_roc_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring='roc_auc', n_jobs=-1)

    metrics["cv_f1_mean"] = cv_f1_scores.mean()
    metrics["cv_f1_std"] = cv_f1_scores.std()
    metrics["cv_roc_mean"] = cv_roc_scores.mean()
    metrics["cv_roc_std"] = cv_roc_scores.std()

    results.append(metrics)
    trained_models[name] = model

    print(f"Accuracy:      {metrics['accuracy'] * 100:.2f}%")
    print(f"Precision:     {metrics['precision'] * 100:.2f}%")
    print(f"Recall:        {metrics['recall'] * 100:.2f}%")
    print(f"F1-Score:      {metrics['f1_score'] * 100:.2f}%")
    print(f"ROC-AUC:       {metrics['roc_auc'] * 100:.2f}%")
    print(f"Mean CV F1:    {metrics['cv_f1_mean'] * 100:.2f}%")
    print(f"Mean CV ROC-AUC: {metrics['cv_roc_mean'] * 100:.2f}%")

comparison_df = pd.DataFrame(results).sort_values(by='roc_auc', ascending=False)
comparison_df.to_csv(OUTPUTS_DIR / "model_comparison.csv", index=False)
print(f"\n✅ [Saved] {OUTPUTS_DIR / 'model_comparison.csv'}")

best_model_name = comparison_df.iloc[0]['model']
best_model = trained_models[best_model_name]

print(f"\n[4/5] Best performing model on unseen data: {best_model_name}")
print(comparison_df[['model', 'accuracy', 'precision', 'recall', 'f1_score', 'roc_auc']].round(4).to_string(index=False))

print("\n[5/5] Generating best-model visual outputs...")

# Save the best-performing model to the app-compatible filename for dashboard usage
joblib.dump(best_model, MODELS_DIR / "random_forest_model.pkl")
print(f"✅ [Saved] {MODELS_DIR / 'random_forest_model.pkl'}")

# Best-model confusion matrix
fig, ax = plt.subplots(figsize=(6, 5))
ConfusionMatrixDisplay.from_predictions(
    y_test,
    best_model.predict(X_test),
    display_labels=["Benign", "Malware"],
    cmap="Blues",
    ax=ax,
)
plt.title(f"Confusion Matrix — {best_model_name}")
plt.tight_layout()
plt.savefig(OUTPUTS_DIR / "confusion_matrix.png", dpi=150)
print(f"✅ [Saved] {OUTPUTS_DIR / 'confusion_matrix.png'}")

# Best-model ROC curve
best_y_proba = best_model.predict_proba(X_test)[:, 1]
fpr, tpr, _ = roc_curve(y_test, best_y_proba)
roc_auc = auc(fpr, tpr)

fig2, ax2 = plt.subplots(figsize=(6, 5))
ax2.plot(fpr, tpr, color="blue", lw=2, label=f"ROC curve (AUC = {roc_auc:.4f})")
ax2.plot([0, 1], [0, 1], color="gray", linestyle="--")
ax2.set_xlabel("False Positive Rate")
ax2.set_ylabel("True Positive Rate")
ax2.set_title(f"ROC Curve — {best_model_name}")
ax2.legend(loc="lower right")
plt.tight_layout()
plt.savefig(OUTPUTS_DIR / "roc_curve.png", dpi=150)
print(f"✅ [Saved] {OUTPUTS_DIR / 'roc_curve.png'}")

print("\n" + "=" * 70)
print("EVALUATION COMPLETE")
print("=" * 70)