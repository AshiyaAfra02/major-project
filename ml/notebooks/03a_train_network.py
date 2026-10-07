# %% [markdown]
# CyberShield, Step 3a: Network attack models

# %% Setup
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
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
MAX_BUNDLE_MB = 80


def rules_cicids(df):
    port = df["Destination Port"]
    fwd = df["Total Fwd Packets"]
    bwd = df["Total Backward Packets"]
    dur = df["Flow Duration"]
    pps = df["Flow Packets/s"]

    common = port.isin([53, 67, 68, 123, 137, 138, 5353])

    ordered_rules = [
        ("BruteForce", port.isin([21, 22])),
        ("PortScan", (fwd <= 2) & (bwd <= 1) & (dur < 2000) & ~common),
        ("DDoS", (pps > 20000) & (fwd >= 3)),
        ("DoS", (dur > 5e7) & (fwd <= 10)),
    ]

    pred = pd.Series("Normal", index=df.index, dtype=object)
    unset = pd.Series(True, index=df.index)

    for label, mask in ordered_rules:
        hit = mask & unset
        pred[hit] = label
        unset &= ~hit

    return pred.values


def rules_nsl(df):
    def c(name):
        return df[name] if name in df.columns else pd.Series(0, index=df.index)

    attack = (
        (c("serror_rate") > 0.8)
        | (c("srv_serror_rate") > 0.8)
        | (c("rerror_rate") > 0.8)
        | (c("num_failed_logins") >= 3)
        | (c("root_shell") > 0)
        | (c("su_attempted") > 0)
        | (c("num_shells") > 0)
        | (c("num_access_files") > 2)
        | ((c("count") > 300) & (c("srv_count") > 300))
    )

    return np.where(attack, "Attack", "Normal")


def run_experiment(*, tag, dataset_name, key_prefix, rules_fn,
                   bundle_name=None, medians=None):

    features = json.loads(
        (tu.PROCESSED / f"{tag}_feature_names.json").read_text()
    )
    classes = json.loads(
        (tu.PROCESSED / f"{tag}_classes.json").read_text()
    )

    train = pd.read_csv(tu.PROCESSED / f"{tag}_train.csv.gz")
    test = pd.read_csv(tu.PROCESSED / f"{tag}_test.csv.gz")

    print(
        f"\n=== {dataset_name}: "
        f"train {train.shape}, test {test.shape}, classes {classes}"
    )

    le = LabelEncoder().fit(classes)

    X_train = train[features].astype("float32")
    y_train = le.transform(train["label"])

    X_test = test[features].astype("float32")
    y_test = test["label"].values

    pos_label = "Attack" if "Attack" in classes else None

    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train,
        y_train,
        test_size=0.1,
        stratify=y_train,
        random_state=SEED,
    )

    # Random Forest
    t0 = time.time()

    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_leaf=3,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=SEED,
    ).fit(X_fit, y_fit)

    rf_sec = time.time() - t0
    rf_val = f1_score(
        y_val,
        rf.predict(X_val),
        average="macro",
    )

    print(
        f"RandomForest trained in {rf_sec:.0f}s, "
        f"validation macro-F1 {rf_val:.4f}"
    )

    # XGBoost
    t0 = time.time()

    xgb = XGBClassifier(
        n_estimators=300,
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

    xgb_sec = time.time() - t0
    xgb_val = f1_score(
        y_val,
        xgb.predict(X_val),
        average="macro",
    )

    print(
        f"XGBoost trained in {xgb_sec:.0f}s, "
        f"validation macro-F1 {xgb_val:.4f}"
    )

    def importance(model):
        s = (
            pd.Series(
                model.feature_importances_,
                index=features,
            )
            .sort_values(ascending=False)
            .head(15)
        )

        return [
            {"feature": k, "importance": float(v)}
            for k, v in s.items()
        ]

    results = []

    for label, model, sec, key in [
        ("Random Forest", rf, rf_sec, f"{key_prefix}_rf"),
        ("XGBoost", xgb, xgb_sec, f"{key_prefix}_xgb"),
    ]:
        pred = le.inverse_transform(model.predict(X_test))

        results.append(
            tu.evaluate(
                y_test,
                pred,
                classes,
                key=key,
                name=label,
                task="network",
                dataset=dataset_name,
                train_seconds=sec,
                pos_label=pos_label,
                extra={"feature_importance": importance(model)},
            )
        )

    results.append(
        tu.evaluate(
            y_test,
            rules_fn(test),
            classes,
            key=f"{key_prefix}_rules",
            name="Rule-based baseline",
            task="network",
            dataset=dataset_name,
            is_baseline=True,
            pos_label=pos_label,
        )
    )

    if bundle_name:
        candidates = sorted(
            [
                ("random_forest", rf, rf_val, results[0]),
                ("xgboost", xgb, xgb_val, results[1]),
            ],
            key=lambda c: c[2],
            reverse=True,
        )

        for kind, model, vf1, res in candidates:
            bundle = {
                "kind": kind,
                "model": model,
                "features": features,
                "classes": [str(c) for c in le.classes_],
                "medians": medians or {},
                "dataset": dataset_name,
                "version": "1.0",
            }

            path = tu.MODELS / bundle_name
            joblib.dump(bundle, path, compress=3)

            size_mb = path.stat().st_size / 1e6
            print(f"Saved {kind} bundle: {size_mb:.1f} MB")

            if size_mb <= MAX_BUNDLE_MB or kind == "xgboost":
                res["served"] = True
                print(
                    f"-> deployed model: {kind} "
                    f"(validation macro-F1 {vf1:.4f})"
                )
                break

    return results


# CICIDS2017
medians = json.loads(
    (tu.PROCESSED / "cicids_medians.json").read_text()
)

all_results = run_experiment(
    tag="cicids",
    dataset_name="CICIDS2017",
    key_prefix="network",
    rules_fn=rules_cicids,
    bundle_name="network_model.joblib",
    medians=medians,
)

print(tu.summary_table(all_results).to_string(index=False))


# NSL-KDD secondary comparison
nsl_classes_file = tu.PROCESSED / "nsl_classes.json"

if nsl_classes_file.exists():
    nsl_classes = json.loads(nsl_classes_file.read_text())

    if sorted(nsl_classes) == ["Attack", "Normal"]:
        nsl_results = run_experiment(
            tag="nsl",
            dataset_name="NSL-KDD (binary)",
            key_prefix="nsl",
            rules_fn=rules_nsl,
            bundle_name=None,
        )

        all_results += nsl_results
        print(tu.summary_table(nsl_results).to_string(index=False))
    else:
        print("NSL-KDD is not binary here; skipping the secondary experiment.")
else:
    print("No NSL-KDD files found; skipping.")


# Save metrics
path = tu.save_partial("network", all_results)
print("Saved", path)

main = next(r for r in all_results if r["served"])

print(f"\nDeployed model: {main['name']}")

for cls, m in main["per_class"].items():
    print(
        f"  {cls:<12} "
        f"P={m['precision']:.3f} "
        f"R={m['recall']:.3f} "
        f"F1={m['f1']:.3f} "
        f"(n={m['support']})"
    )
