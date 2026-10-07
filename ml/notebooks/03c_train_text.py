import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ROOT = Path.cwd().resolve()
sys.path.insert(0, str(ROOT / "ml"))
import train_utils as tu


def main():
    train = pd.read_csv(tu.PROCESSED / "text_train.csv.gz")
    test = pd.read_csv(tu.PROCESSED / "text_test.csv.gz")

    print(
        f"=== Text dataset: train {train.shape}, "
        f"test {test.shape}"
    )

    text_col = "text"

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=2,
        max_features=60000,
        sublinear_tf=True,
        strip_accents="unicode",
        lowercase=True,
    )

    X_train = vectorizer.fit_transform(
        train[text_col].fillna("").astype(str)
    )
    X_test = vectorizer.transform(
        test[text_col].fillna("").astype(str)
    )

    y_train = train["label"].astype(str)
    y_test = test["label"].astype(str)

    classes = sorted(y_train.unique().tolist())

    print(f"Classes: {classes}")
    print(f"TF-IDF features: {X_train.shape[1]}")

    t0 = time.time()

    model = LogisticRegression(
        C=5,
        class_weight="balanced",
        max_iter=1000,
        random_state=42,
    )

    model.fit(X_train, y_train)

    train_seconds = time.time() - t0

    pred = model.predict(X_test)

    result = tu.evaluate(
        y_test,
        pred,
        classes,
        key="text_logreg",
        name="TF-IDF + Logistic Regression",
        task="text",
        dataset="Phishing Email + SMS",
        train_seconds=train_seconds,
        pos_label="phishing" if "phishing" in classes else None,
    )

    # Rule baseline
    def rule_predict(texts):
        outputs = []

        for text in texts:
            t = str(text).lower()
            score = 0

            if any(x in t for x in [
                "http://",
                "https://",
                "www.",
                ".com/",
            ]):
                score += 1

            if any(x in t for x in [
                "urgent",
                "immediately",
                "act now",
                "limited time",
                "verify now",
            ]):
                score += 1

            if any(x in t for x in [
                "winner",
                "prize",
                "congratulations",
                "reward",
                "free",
            ]):
                score += 1

            if any(x in t for x in [
                "password",
                "login",
                "credential",
                "account",
                "bank",
                "verify your",
            ]):
                score += 1

            if any(x in t for x in [
                "click here",
                "open the link",
                "download",
                "confirm",
                "update your",
            ]):
                score += 1

            threshold = 3 if len(t) > 200 else 2
            outputs.append(
                "phishing" if score >= threshold else "legitimate"
            )

        return np.array(outputs)

    rule_pred = rule_predict(test[text_col].fillna("").astype(str))

    rule_labels = ["legitimate", "phishing"]

    y_rule = np.where(
        y_test.str.lower().isin(["phishing", "spam"]),
        "phishing",
        "legitimate",
    )

    rule_result = tu.evaluate(
        y_rule,
        rule_pred,
        rule_labels,
        key="text_rules",
        name="Rule-based baseline",
        task="text",
        dataset="Phishing Email + SMS",
        is_baseline=True,
        pos_label="phishing",
    )

    results = [result, rule_result]

    print()
    print(tu.summary_table(results).to_string(index=False))

    bundle = {
        "kind": "tfidf_logreg",
        "vectorizer": vectorizer,
        "model": model,
        "classes": [str(c) for c in model.classes_],
        "text_column": text_col,
        "dataset": "Phishing Email + SMS",
        "version": "1.0",
    }

    path = tu.MODELS / "text_model.joblib"
    joblib.dump(bundle, path, compress=3)

    size_mb = path.stat().st_size / 1e6

    print(f"\nSaved text model bundle: {size_mb:.1f} MB")

    result["served"] = True

    metrics_path = tu.save_partial("text", results)
    print("Saved", metrics_path)


if __name__ == "__main__":
    main()
