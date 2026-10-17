"""
Draw the evaluation figures used in the dissertation's results chapter.

Reads models/model_card.json (written by scripts/training/train_models.py) and saves
three PNG figures to docs/images/results/:

  family_holdout_recall.png  - recall on each malware family when it is held out of training
  baseline_comparison.png    - one-rule baseline vs Random Forest (random and grouped folds)
  malware_type_recall.png    - recall of the malware-type model per class, grouped folds

Run from the project root:  python scripts/evaluation/plot_results.py
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE_DIR = Path(__file__).resolve().parents[2]
CARD = BASE_DIR / "models" / "model_card.json"
OUT = BASE_DIR / "docs" / "images" / "results"

INK, MUTED, GRID, SERIES = "#0b0b0b", "#52514e", "#e4e3df", "#2a78d6"
plt.rcParams.update({"font.size": 10, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
                     "xtick.color": MUTED, "ytick.color": MUTED, "font.family": "DejaVu Sans"})


def style(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def family_recall(card):
    lofo = card["binary"]["leave_one_family_out"]
    fams = sorted((k for k in lofo if "-" in k), key=lambda k: lofo[k]["recall"])
    vals = [lofo[k]["recall"] * 100 for k in fams]
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.scatter(vals, range(len(fams)), s=55, color=SERIES, zorder=3)
    ax.axvline(95, color=MUTED, linestyle="--", linewidth=1)
    ax.text(95.1, len(fams) - 0.6, "95% target", color=MUTED, fontsize=9)
    for i, v in enumerate(vals):
        if v < 100:
            ax.text(v - 0.15, i, f"{v:.2f}%", va="center", ha="right", color=INK, fontsize=9)
    ax.set_yticks(range(len(fams)), fams)
    ax.set_xlim(94.5, 100.5)
    ax.set_xlabel("Recall on the held-out family (%)")
    style(ax)
    fig.tight_layout()
    fig.savefig(OUT / "family_holdout_recall.png", dpi=200)
    plt.close(fig)


def baseline(card):
    rows = [("One-rule baseline\n(svcscan.nservices <= 390.5)", card["shortcut"]["one_rule_accuracy"]),
            ("Random Forest,\ngrouped 5-fold", card["binary"]["grouped_cv"]["accuracy"]),
            ("Random Forest,\nrandom 5-fold", card["binary"]["random_cv"]["accuracy"])]
    fig, ax = plt.subplots(figsize=(7, 2.8))
    for i, (name, acc) in enumerate(rows):
        ax.scatter(acc * 100, i, s=70, color=SERIES, zorder=3)
        ax.text(acc * 100 - 0.02, i + 0.22, f"{acc * 100:.2f}%", ha="right", color=INK, fontsize=9)
    ax.set_yticks(range(len(rows)), [r[0] for r in rows])
    ax.set_ylim(-0.6, len(rows) - 0.4)
    ax.set_xlim(99.5, 100.02)
    ax.set_xlabel("Accuracy (%) - axis starts at 99.5%")
    style(ax)
    fig.tight_layout()
    fig.savefig(OUT / "baseline_comparison.png", dpi=200)
    plt.close(fig)


def type_recall(card):
    rec = card["family"]["grouped_recall"]
    names = list(rec)
    vals = [rec[k] * 100 for k in names]
    fig, ax = plt.subplots(figsize=(7, 2.6))
    ax.barh(range(len(names)), vals, height=0.5, color=SERIES, zorder=3)
    ax.axvline(100 / 3, color=MUTED, linestyle="--", linewidth=1)
    ax.text(100 / 3 + 1, len(names) - 0.45, "chance (33%)", color=MUTED, fontsize=9)
    for i, v in enumerate(vals):
        ax.text(v + 1, i, f"{v:.1f}%", va="center", color=INK, fontsize=9)
    ax.set_yticks(range(len(names)), names)
    ax.set_xlim(0, 100)
    ax.set_xlabel("Recall on unseen malware samples (%), grouped 5-fold")
    style(ax)
    fig.tight_layout()
    fig.savefig(OUT / "malware_type_recall.png", dpi=200)
    plt.close(fig)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    card = json.loads(CARD.read_text(encoding="utf-8"))
    family_recall(card)
    baseline(card)
    type_recall(card)
    print(f"Figures written to {OUT}")


if __name__ == "__main__":
    main()
