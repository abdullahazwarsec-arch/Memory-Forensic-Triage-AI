"""
Train and honestly evaluate every HazMem model from Obfuscated-MalMem2022.

Why this script exists
----------------------
The earlier scripts used a random 80/20 split. The dataset holds ~10 snapshots of every malware
sample plus 569 duplicate rows, so near-copies landed in both train and test and the reported
99.99 % said little. This script:

  1. removes duplicate rows;
  2. evaluates with folds grouped by malware sample (snapshots of one sample never sit on both
     sides), leave-one-family-out (a family the model has never seen) and a one-rule baseline that
     exposes the benign-machine shortcut;
  3. trains the deployed models on the de-duplicated data:
       random_forest_model.pkl       benign vs malware      (dashboard verdict)
       isolation_forest.pkl          benign-only anomaly    (zero-day check)
       multiclass_random_forest.pkl  ransomware/spyware/trojan, malware rows only (type hint)
  4. writes models/model_card.json (read by the dashboard), docs/results/honest_evaluation.csv/.md
     and pins the new model hashes.

Benign rows carry no sample id in the dataset, so they cannot be grouped - see the limitations
written to the report. Run:  python scripts/training/train_models.py   (about 5-10 minutes)
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold, cross_val_predict, cross_val_score
from sklearn.tree import DecisionTreeClassifier

BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR))
from hazmem import evidence_integrity as ei  # noqa: E402

DATA_PATH = BASE_DIR / "data" / "Obfuscated-MalMem2022.csv"
MODELS_DIR = BASE_DIR / "models"
RESULTS_DIR = BASE_DIR / "docs" / "results"
SEED, FOLDS = 42, 5
FAMILIES = ["Ransomware", "Spyware", "Trojan"]


def binary_rf():
    return RandomForestClassifier(n_estimators=150, max_depth=12, min_samples_split=10, min_samples_leaf=4,
                                  max_features="sqrt", random_state=SEED, n_jobs=-1)


def family_rf():
    return RandomForestClassifier(n_estimators=150, max_depth=15, min_samples_leaf=4,
                                  max_features="sqrt", random_state=SEED, n_jobs=-1)


def load():
    raw = pd.read_csv(DATA_PATH)
    df = raw.drop_duplicates(subset=[c for c in raw.columns if c != "Category"]).reset_index(drop=True)
    y = (df["Class"] != "Benign").astype(int).values
    X = df.drop(columns=["Class", "Category"])
    parts = df["Category"].str.split("-")
    # "Trojan-Zeus-<sha256>-4.raw": the sample is everything before the snapshot number
    sample = np.where(y == 1, df["Category"].str.rsplit("-", n=1).str[0], "benign-" + df.index.astype(str))
    family = np.where(y == 1, parts.str[0] + "-" + parts.str[1], "Benign")
    category = np.where(y == 1, parts.str[0], "Benign")
    return raw, df, X, y, sample, family, category


def scores(y_true, prob):
    pred = prob >= 0.5
    return {"accuracy": accuracy_score(y_true, pred), "precision": precision_score(y_true, pred, zero_division=0),
            "recall": recall_score(y_true, pred, zero_division=0), "f1": f1_score(y_true, pred, zero_division=0),
            "roc_auc": roc_auc_score(y_true, prob)}


def cross_validate(X, y, splitter, groups=None):
    prob = cross_val_predict(binary_rf(), X, y, cv=splitter, groups=groups, method="predict_proba")[:, 1]
    return scores(y, prob)


def main():
    raw, df, X, y, sample, family, category = load()
    rows = []
    print(f"{len(raw)} rows, {len(raw) - len(df)} duplicates removed -> {len(df)} "
          f"({int(y.sum())} malware snapshots of {len(set(sample[y == 1]))} samples, {int((y == 0).sum())} benign)")

    print("[1/5] Random vs grouped cross-validation ...")
    random_cv = cross_validate(X, y, StratifiedKFold(FOLDS, shuffle=True, random_state=SEED))
    grouped_cv = cross_validate(X, y, StratifiedGroupKFold(FOLDS, shuffle=True, random_state=SEED), sample)
    rows += [{"test": "Random 5-fold (old method)", **random_cv}, {"test": "Grouped by malware sample, 5-fold", **grouped_cv}]

    print("[2/5] Leave-one-family-out ...")
    rng = np.random.default_rng(SEED)
    benign_idx = np.where(y == 0)[0]
    lofo = {}
    for name in sorted(set(family) - {"Benign"}) + FAMILIES:
        held = family == name if "-" in name else category == name
        test_benign = rng.choice(benign_idx, 2000, replace=False)
        train = np.where(~held & ~np.isin(np.arange(len(y)), test_benign))[0]
        test = np.concatenate([np.where(held)[0], test_benign])
        prob = binary_rf().fit(X.iloc[train], y[train]).predict_proba(X.iloc[test])[:, 1]
        lofo[name] = {"recall": float(recall_score(y[test], prob >= 0.5)),
                      "false_alarm_rate": float(np.mean(prob[y[test] == 0] >= 0.5))}
        print(f"   {name:22s} recall {lofo[name]['recall']:.3f}")
    worst = min((n for n in lofo if "-" in n), key=lambda n: lofo[n]["recall"])

    print("[3/5] Shortcut check: best one-rule classifier ...")
    cv = StratifiedKFold(FOLDS, shuffle=True, random_state=SEED)
    stumps = sorted(((cross_val_score(DecisionTreeClassifier(max_depth=1), X[[c]], y, cv=cv).mean(), c)
                     for c in X.columns), reverse=True)
    stump_acc, stump_feature = stumps[0]
    stump = DecisionTreeClassifier(max_depth=1).fit(X[[stump_feature]], y)
    benign_range = [int(X[stump_feature][y == 0].min()), int(X[stump_feature][y == 0].max())]
    rows.append({"test": f"One rule only: {stump_feature} <= {stump.tree_.threshold[0]:.1f}", "accuracy": stump_acc})
    no_svc = [c for c in X.columns if not c.startswith("svcscan.")]
    ablation = cross_validate(X[no_svc], y, StratifiedGroupKFold(FOLDS, shuffle=True, random_state=SEED), sample)
    rows.append({"test": "Grouped 5-fold without the svcscan features", **ablation})

    print("[4/5] Malware type model (malware rows only) ...")
    m = y == 1
    fam_y = category[m]
    fam_random = accuracy_score(fam_y, cross_val_predict(family_rf(), X[m], fam_y,
                                                         cv=StratifiedKFold(FOLDS, shuffle=True, random_state=SEED)))
    fam_pred = cross_val_predict(family_rf(), X[m], fam_y, groups=sample[m],
                                 cv=StratifiedGroupKFold(FOLDS, shuffle=True, random_state=SEED))
    fam_grouped = accuracy_score(fam_y, fam_pred)
    fam_recall = {f: float(recall_score(fam_y, fam_pred, labels=[f], average="macro")) for f in FAMILIES}
    rows += [{"test": "Malware type, random 5-fold", "accuracy": fam_random},
             {"test": "Malware type, grouped by sample 5-fold", "accuracy": fam_grouped}]

    print("[5/5] Training the deployed models on all de-duplicated rows ...")
    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(binary_rf().fit(X, y), MODELS_DIR / "random_forest_model.pkl", compress=3)
    joblib.dump(IsolationForest(n_estimators=100, contamination=0.01, random_state=SEED, n_jobs=-1).fit(X[y == 0]),
                MODELS_DIR / "isolation_forest.pkl", compress=3)
    joblib.dump(family_rf().fit(X[m], fam_y), MODELS_DIR / "multiclass_random_forest.pkl", compress=3)

    card = {
        "trained_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "dataset": {"file": DATA_PATH.name, "sha256": ei.hash_file(str(DATA_PATH))["sha256"],
                    "rows": len(raw), "duplicates_removed": len(raw) - len(df),
                    "malware_samples": int(len(set(sample[y == 1]))), "malware_snapshots": int(y.sum()),
                    "benign_snapshots": int((y == 0).sum())},
        "binary": {"random_cv": random_cv, "grouped_cv": grouped_cv, "without_svcscan_grouped_cv": ablation,
                   "leave_one_family_out": lofo, "hardest_unseen_family": worst},
        "shortcut": {"feature": stump_feature, "threshold": float(stump.tree_.threshold[0]),
                     "one_rule_accuracy": float(stump_acc), "benign_range": benign_range},
        "family": {"classes": FAMILIES, "random_cv_accuracy": float(fam_random),
                   "grouped_cv_accuracy": float(fam_grouped), "grouped_recall": fam_recall},
        "versions": {"scikit-learn": sklearn.__version__, "pandas": pd.__version__, "numpy": np.__version__},
    }
    (MODELS_DIR / "model_card.json").write_text(json.dumps(card, indent=2, default=float), encoding="utf-8")
    pins = ei.pin_model_hashes()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    table = pd.DataFrame(rows)
    table.round(4).to_csv(RESULTS_DIR / "honest_evaluation.csv", index=False)
    pct = lambda v: f"{v * 100:.2f} %"  # noqa: E731
    lines = [
        "# Honest model evaluation", "",
        f"Generated by `scripts/training/train_models.py` on {card['trained_utc']} "
        f"(scikit-learn {sklearn.__version__}).", "",
        f"Dataset: {len(raw):,} rows -> {len(df):,} after removing {len(raw) - len(df)} duplicates; "
        f"{int(y.sum()):,} malware snapshots from {card['dataset']['malware_samples']:,} samples "
        f"(15 families), {int((y == 0).sum()):,} benign snapshots.", "",
        "## Benign vs malware", "",
        "| Test | Accuracy | Recall | Precision | ROC-AUC |", "|---|---|---|---|---|",
        *(f"| {r['test']} | {pct(r['accuracy'])} | "
          + (f"{pct(r['recall'])} | {pct(r['precision'])} | {r['roc_auc']:.4f} |" if "recall" in r else "- | - | - |")
          for r in rows if "Malware type" not in r["test"]), "",
        "### Malware families the model never saw", "",
        "| Held-out family | Detected (recall) | Benign false-alarm rate |", "|---|---|---|",
        *(f"| {n if '-' in n else f'All {n} families'} | {pct(v['recall'])} | {pct(v['false_alarm_rate'])} |"
          for n, v in lofo.items()), "",
        "## Malware type (ransomware / spyware / trojan)", "",
        f"- Random 5-fold: **{pct(fam_random)}**", f"- Grouped by sample: **{pct(fam_grouped)}** (chance = 33 %)",
        *(f"  - {f}: {pct(r)} recall" for f, r in fam_recall.items()), "",
        "## What these numbers mean", "",
        f"- Grouping by sample changes the binary score very little, and even unseen families are detected. "
        f"That is **not** proof of a general malware detector: one rule, `{stump_feature} <= "
        f"{stump.tree_.threshold[0]:.1f}`, already scores {pct(stump_acc)}. Every benign snapshot has "
        f"{benign_range[0]}-{benign_range[1]} services because all benign data comes from one machine, so the "
        "model largely learns \"different from that machine\".",
        f"- Without the svcscan features the grouped score is {pct(ablation['accuracy'])} - other counts "
        "(handles, DLLs, mutants) carry the same machine fingerprint.",
        "- Expect false alarms on clean dumps from other Windows versions or machines. The benign rows carry no "
        "sample id, so they could not be grouped; a fair benign estimate needs dumps from many machines.",
        f"- The malware-type model is a hint, not a verdict: about {pct(fam_grouped)} correct on unseen samples.", "",
        "## Model hashes (pinned)", "", *(f"- `{n}`: `{h}`" for n, h in pins.items()), "",
    ]
    (RESULTS_DIR / "honest_evaluation.md").write_text("\n".join(lines), encoding="utf-8")
    print(table.round(4).to_string(index=False))
    print(f"\nSaved models, models/model_card.json and {RESULTS_DIR / 'honest_evaluation.md'}")


if __name__ == "__main__":
    main()
