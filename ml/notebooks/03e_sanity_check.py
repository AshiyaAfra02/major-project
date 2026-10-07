# %% Sanity check of exported models and metrics (read-only; changes nothing)
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


def find_root() -> Path:
    here = Path.cwd().resolve()
    for cand in [here, *here.parents]:
        if (cand / "ml" / "data" / "processed").exists():
            return cand
    raise FileNotFoundError("Run from inside the cyber-shield folder.")


ROOT = find_root()
sys.path.insert(0, str(ROOT / "ml"))
import train_utils as tu
from url_features import extract_features

print("=== 1. Bundle structure ===")
bundles = {}

for name in ("network_model.joblib", "url_model.joblib", "text_model.joblib"):
    obj = joblib.load(tu.SERVICE_MODELS / name)
    bundles[name] = obj

    if isinstance(obj, dict):
        print(f"{name}: dict with keys {sorted(obj.keys())}")
    else:
        print(f"{name}: {type(obj).__name__} (NOT a dict bundle)")

txt = bundles["text_model.joblib"]
pipe = txt["pipeline"] if isinstance(txt, dict) and "pipeline" in txt else txt
print("text classes_:", list(getattr(pipe, "classes_", [])))

print("\n=== 2. URL model on sample URLs ===")
url = bundles["url_model.joblib"]

if isinstance(url, dict) and "model" in url:
    samples = [
        "https://www.wikipedia.org/wiki/Python",
        "https://github.com/pallets/flask",
        "https://www.bbc.com/news",
        "http://paypal-secure-login.verify-account.example.ru/signin.php?id=1",
        "http://192.168.10.5/update/setup.exe",
        "http://free-bonus-claim.example.xyz/win?id=998877",
    ]

    X = pd.DataFrame(
        [extract_features(u) for u in samples],
        columns=url["features"],
    ).astype("float32")

    P = url["model"].predict_proba(X)

    for u, p in zip(samples, P):
        probs = {
            c: round(float(v), 2)
            for c, v in zip(url["classes"], p)
        }
        print(f"{u[:62]:<64} {probs}")

    test = pd.read_csv(
        tu.PROCESSED / "url_test.csv.gz"
    ).sample(4000, random_state=1)

    Xt = test[url["features"]].astype("float32")
    pm = 1.0 - url["model"].predict_proba(Xt)[:, url["benign_index"]]
    pred = pm >= 0.5
    true = test["label"].values == 1

    print(
        f"\nHeld-out URLs: benign flagged malicious = "
        f"{pred[~true].mean():.1%}, "
        f"malicious caught = {pred[true].mean():.1%}"
    )

print("\n=== 3. Metrics file ===")
m = json.loads(
    (tu.SERVICE_MODELS / "metrics.json").read_text()
)

for r in m["models"]:
    if r["key"] in ("text_rules", "text_lr", "url_rules"):
        print(
            f"{r['key']}: "
            f"acc={r['accuracy']:.4f} "
            f"f1_macro={r['f1_macro']:.4f} "
            f"labels={r['labels']} "
            f"confusion={r['confusion_matrix']}"
        )
