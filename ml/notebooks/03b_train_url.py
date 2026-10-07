import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier


def find_root() -> Path:
    here = Path.cwd().resolve()
    for cand in [here, *here.parents]:
        if (cand / "ml" / "data" / "processed").exists():
            return cand
    raise FileNotFoundError("Run from inside the cyber-shield folder.")


ROOT = find_root()
sys.path.insert(0, str(ROOT / "ml"))
import train_utils as tu


SEED = 42
DATASET = "malicious_phish (lexical features)"


features = json.loads(
    (tu.PROCESSED / "url_feature_names.json").read_text()
)
classes = json.loads(
    (tu.PROCESSED / "url_classes.json").read_text()
)

train = pd.read_csv(tu.PROCESSED / "url_train.csv.gz")
test = pd.read_csv(tu.PROCESSED / "url_test.csv.gz")

print(
    "train", train.shape,
    "test", test.shape,
    "classes", classes
)

# The processed dataset contains:
# type  -> original 4-class label
# label -> binary malicious/safe label
if "type" not in train.columns:
    raise KeyError(
        "Expected 'type' column for the planned 4-class URL model."
    )

le = LabelEncoder().fit(classes)

X_train = train[features].astype("float32")
y_train = le.transform(train["type"].astype(str))

X_test = test[features].astype("float32")
y_test = le.transform(test["type"].astype(str))

X_fit, X_val, y_fit, y_val = train_test_split(
    X_train,
    y_train,
    test_size=0.1,
    stratify=y_train,
    random_state=SEED,
)


# 4-class XGBoost
t0 = time.time()

xgb = XGBClassifier(
    n_estimators=400,
    max_depth=7,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    tree_method="hist",
    early_stopping_rounds=25,
    n_jobs=-1,
    random_state=SEED,
)

xgb.fit(
    X_fit,
    y_fit,
    sample_weight=compute_sample_weight("balanced", y_fit),
    eval_set=[(X_val, y_val)],
    verbose=False,
)

secs = time.time() - t0

val_f1 = f1_score(
    y_val,
    xgb.predict(X_val),
    average="macro",
)

print(
    f"Trained in {secs:.0f}s; "
    f"validation macro-F1 {val_f1:.4f}"
)


# Predictions
proba = xgb.predict_proba(X_test)

pred_multi = le.inverse_transform(
    proba.argmax(axis=1)
)

true_multi = le.inverse_transform(y_test)

benign_idx = list(le.classes_).index("benign")

p_malicious = 1.0 - proba[:, benign_idx]

pred_bin = np.where(
    p_malicious >= 0.5,
    "malicious",
    "safe",
)

true_bin = np.where(
    test["label"].values == 1,
    "malicious",
    "safe",
)


# Feature importance
imp = (
    pd.Series(
        xgb.feature_importances_,
        index=features,
    )
    .sort_values(ascending=False)
    .head(15)
)

importance = [
    {
        "feature": k,
        "importance": float(v),
    }
    for k, v in imp.items()
]


# Rule baseline
def rules_url(df):
    masks = [
        df["has_ip_host"] == 1,
        df["num_at"] > 0,
        df["url_length"] > 75,
        df["host_hyphens"] >= 3,
        df["suspicious_word_count"] >= 2,
        df["has_punycode"] == 1,
        df["risky_extension"] == 1,
        df["num_subdomains"] >= 4,
        df["double_slash_in_path"] == 1,
    ]

    triggered = sum(
        m.astype(int)
        for m in masks
    )

    return np.where(
        triggered >= 1,
        "malicious",
        "safe",
    )


results = [
    tu.evaluate(
        true_bin,
        pred_bin,
        ["safe", "malicious"],
        key="url_xgb_binary",
        name="XGBoost (safe vs malicious)",
        task="url",
        dataset=DATASET,
        train_seconds=secs,
        pos_label="malicious",
        extra={
            "feature_importance": importance,
        },
    ),

    tu.evaluate(
        true_bin,
        rules_url(test),
        ["safe", "malicious"],
        key="url_rules",
        name="Rule-based baseline",
        task="url",
        dataset=DATASET,
        is_baseline=True,
        pos_label="malicious",
    ),

    tu.evaluate(
        true_multi,
        pred_multi,
        classes,
        key="url_xgb_multiclass",
        name="XGBoost (4-class)",
        task="url",
        dataset=DATASET,
        train_seconds=secs,
    ),
]

results[0]["served"] = True
results[2]["served"] = True

print(
    tu.summary_table(results).to_string(index=False)
)


# Save model
bundle = {
    "kind": "xgboost",
    "model": xgb,
    "features": features,
    "classes": [str(c) for c in le.classes_],
    "benign_index": int(benign_idx),
    "threshold": 0.5,
    "version": "1.0",
}

joblib.dump(
    bundle,
    tu.MODELS / "url_model.joblib",
    compress=3,
)

print(
    "Model size: %.1f MB"
    % (
        (tu.MODELS / "url_model.joblib").stat().st_size
        / 1e6
    )
)

print(
    "Saved",
    tu.save_partial("url", results)
)

print("\n4-class per-class results:")

for cls, m in results[2]["per_class"].items():
    print(
        f"  {cls:<12} "
        f"P={m['precision']:.3f} "
        f"R={m['recall']:.3f} "
        f"F1={m['f1']:.3f} "
        f"(n={m['support']})"
    )
