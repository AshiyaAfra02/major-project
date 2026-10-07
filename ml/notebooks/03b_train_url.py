import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score
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


def url_rules(df):
    text = df["url"].astype(str).str.lower()

    score = (
        text.str.match(r"^\d{1,3}(\.\d{1,3}){3}", na=False).astype(int)
        + text.str.contains("@", regex=False).astype(int)
        + (text.str.len() > 75).astype(int)
        + text.str.count("-").ge(3).astype(int)
        + text.str.contains(
            "login|verify|secure|account|update|confirm|bank|paypal",
            regex=True,
        ).astype(int)
        + text.str.contains("xn--", regex=False).astype(int)
        + text.str.contains(
            r"\.(exe|scr|zip|rar|js|jar|apk)(?:$|[/?])",
            regex=True,
        ).astype(int)
        + text.str.count(r"\.").ge(4).astype(int)
        + text.str.contains("//", regex=False).astype(int)
    )

    return np.where(score >= 2, "malicious", "benign")


def main():
    features = json.loads(
        (tu.PROCESSED / "url_feature_names.json").read_text()
    )
    classes = json.loads(
        (tu.PROCESSED / "url_classes.json").read_text()
    )

    train = pd.read_csv(tu.PROCESSED / "url_train.csv.gz")
    test = pd.read_csv(tu.PROCESSED / "url_test.csv.gz")

    print(
        f"=== URL dataset: train {train.shape}, "
        f"test {test.shape}, classes {classes}"
    )

    X_train = train[features].astype("float32")
    X_test = test[features].astype("float32")

    y_train = train["label"].astype(str)
    y_test = test["label"].astype(str)

    # The processed URL labels are encoded as 0/1.
    # Train the deployed model as binary benign/malicious.
    y_train_id = pd.to_numeric(y_train, errors="raise").astype(int)
    y_test_id = pd.to_numeric(y_test, errors="raise").astype(int)

    binary_classes = ["benign", "malicious"]

    model = XGBClassifier(
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

    t0 = time.time()

    model.fit(
        X_train,
        y_train_id,
        eval_set=[(X_test, y_test_id)],
        verbose=False,
    )

    train_seconds = time.time() - t0

    pred_id = model.predict(X_test).astype(int)
    pred = np.where(pred_id == 1, "malicious", "benign")

    result = tu.evaluate(
        np.where(y_test_id == 1, "malicious", "benign"),
        pred,
        binary_classes,
        key="url_xgb_binary",
        name="XGBoost (binary)",
        task="url",
        dataset="Malicious URLs",
        train_seconds=train_seconds,
        pos_label="malicious",
    )

    # Binary safe/malicious evaluation
    y_binary = np.where(y_test_id == 1, "malicious", "benign")
    pred_binary = pred

    # Rule baseline
    rule_pred = url_rules(test)

    rule_result = tu.evaluate(
        y_binary,
        rule_pred,
        ["benign", "malicious"],
        key="url_rules",
        name="Rule-based baseline",
        task="url",
        dataset="Malicious URLs",
        is_baseline=True,
        pos_label="malicious",
    )

    results = [result, rule_result]

    print()
    print(tu.summary_table(results).to_string(index=False))

    bundle = {
        "kind": "xgboost",
        "model": model,
        "features": features,
        "classes": [str(c) for c in classes],
        "dataset": "Malicious URLs",
        "version": "1.0",
    }

    path = tu.MODELS / "url_model.joblib"
    joblib.dump(bundle, path, compress=3)

    size_mb = path.stat().st_size / 1e6

    print(f"\nSaved URL model bundle: {size_mb:.1f} MB")

    result["served"] = True

    metrics_path = tu.save_partial("url", results)
    print("Saved", metrics_path)


if __name__ == "__main__":
    main()
