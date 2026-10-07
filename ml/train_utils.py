"""Shared helpers for the CyberShield training notebooks."""
import json
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "ml" / "data" / "processed"
MODELS = ROOT / "ml" / "models"
REPORTS = ROOT / "ml" / "reports"
SERVICE_MODELS = ROOT / "ml-service" / "models"

for _d in (MODELS, REPORTS, SERVICE_MODELS):
    _d.mkdir(parents=True, exist_ok=True)


def evaluate(y_true, y_pred, labels, *, key, name, task, dataset,
             is_baseline=False, train_seconds=None, pos_label=None, extra=None):
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    labels = [str(l) for l in labels]

    p, r, f, s = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    mp, mr, mf, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="macro", zero_division=0
    )
    wp, wr, wf, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="weighted", zero_division=0
    )
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    result = {
        "key": key,
        "name": name,
        "task": task,
        "dataset": dataset,
        "is_baseline": bool(is_baseline),
        "served": False,
        "n_test": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(mp),
        "recall_macro": float(mr),
        "f1_macro": float(mf),
        "precision_weighted": float(wp),
        "recall_weighted": float(wr),
        "f1_weighted": float(wf),
        "labels": labels,
        "confusion_matrix": cm.tolist(),
        "per_class": {
            labels[i]: {
                "precision": float(p[i]),
                "recall": float(r[i]),
                "f1": float(f[i]),
                "support": int(s[i]),
            }
            for i in range(len(labels))
        },
        "train_seconds": None if train_seconds is None else round(float(train_seconds), 2),
        "extra": extra or {},
    }

    if pos_label is not None:
        i = labels.index(pos_label)
        result["positive_class"] = {
            "label": pos_label,
            "precision": float(p[i]),
            "recall": float(r[i]),
            "f1": float(f[i]),
        }

    return result


def plot_confusion(result, title=None):
    labels = result["labels"]
    cm = np.array(result["confusion_matrix"])
    norm = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
    size = max(5, 0.9 * len(labels) + 3)

    fig, ax = plt.subplots(figsize=(size, size * 0.85))
    sns.heatmap(
        norm,
        annot=cm,
        fmt="d",
        cmap="Blues",
        cbar=False,
        xticklabels=labels,
        yticklabels=labels,
        ax=ax,
        vmin=0,
        vmax=1,
    )
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title or result["name"])
    plt.xticks(rotation=35, ha="right")
    plt.tight_layout()

    path = REPORTS / f"cm_{result['key']}.png"
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def summary_table(results):
    rows = []
    for r in results:
        rows.append({
            "model": r["name"],
            "dataset": r["dataset"],
            "acc": round(r["accuracy"], 4),
            "prec(macro)": round(r["precision_macro"], 4),
            "rec(macro)": round(r["recall_macro"], 4),
            "f1(macro)": round(r["f1_macro"], 4),
            "baseline": r["is_baseline"],
            "served": r["served"],
        })
    return pd.DataFrame(rows)


def save_partial(task, results):
    for r in results:
        plot_confusion(r)

    payload = {
        "task": task,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "models": results,
    }

    path = MODELS / f"metrics_{task}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
