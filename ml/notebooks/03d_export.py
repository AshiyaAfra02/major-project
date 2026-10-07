import json
import shutil
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
ML = ROOT / "ml"
MODELS = ML / "models"
SERVICE = ROOT / "ml-service" / "models"
PROCESSED = ML / "data" / "processed"

SERVICE.mkdir(parents=True, exist_ok=True)


def load_metrics(name):
    path = MODELS / f"metrics_{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    print("=== CyberShield Step 3d: Export models ===")

    network = load_metrics("network")
    url = load_metrics("url")
    text = load_metrics("text")

    all_models = (
        network["models"]
        + url["models"]
        + text["models"]
    )

    # Mark the actual deployed models.
    for item in all_models:
        if item["key"] == "network_xgb":
            item["served"] = True
        elif item["key"] == "url_xgb_binary":
            item["served"] = True
        elif item["key"] == "text_logreg":
            item["served"] = True

    payload = {
        "project": "CyberShield",
        "version": "1.0",
        "models": all_models,
    }

    metrics_path = SERVICE / "metrics.json"
    metrics_path.write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )

    print("Saved:", metrics_path)

    # Copy trained model bundles.
    model_files = [
        "network_model.joblib",
        "url_model.joblib",
        "text_model.joblib",
    ]

    for filename in model_files:
        source = MODELS / filename
        destination = SERVICE / filename

        if not source.exists():
            raise FileNotFoundError(
                f"Missing trained model: {source}"
            )

        shutil.copy2(source, destination)

        size_mb = destination.stat().st_size / 1e6
        print(f"Copied {filename}: {size_mb:.1f} MB")

    # Smoke test 1: network
    network_bundle = joblib.load(
        SERVICE / "network_model.joblib"
    )

    network_sample = pd.read_csv(
        PROCESSED / "demo_network_sample.csv"
    )

    network_features = network_bundle["features"]
    X_network = network_sample[network_features].astype("float32")

    network_pred = network_bundle["model"].predict(
        X_network
    )

    network_labels = network_bundle["classes"]

    print("\nNetwork smoke test:")
    print(
        [
            network_labels[int(x)]
            for x in network_pred[:5]
        ]
    )

    # Smoke test 2: URL
    url_bundle = joblib.load(
        SERVICE / "url_model.joblib"
    )

    # The URL model was trained on precomputed lexical features.
    # Use the processed test data for a reliable smoke test.
    url_test = pd.read_csv(
        PROCESSED / "url_test.csv.gz"
    )

    url_features = url_bundle["features"]
    X_url = url_test[url_features].astype("float32")

    url_pred = url_bundle["model"].predict(
        X_url.head(2)
    )

    print("\nURL smoke test:")
    print(url_pred.tolist())

    # Smoke test 3: text
    text_bundle = joblib.load(
        SERVICE / "text_model.joblib"
    )

    text_samples = [
        "Hello, hope you are doing well. See you tomorrow.",
        "URGENT! Verify your account immediately by clicking this link.",
    ]

    X_text = text_bundle["vectorizer"].transform(
        text_samples
    )

    text_pred = text_bundle["model"].predict(
        X_text
    )

    print("\nText smoke test:")
    print(text_pred.tolist())

    print("\n=== Export complete ===")


if __name__ == "__main__":
    main()
