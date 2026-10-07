import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

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

    # Planned reporting: performance by source (email vs SMS)
    by_source = {}

    for src in sorted(test["source"].astype(str).unique()):
        mask = test["source"].astype(str).values == src

        by_source[src] = {
            "n": int(mask.sum()),
            "accuracy": float(
                (pred[mask] == y_test.values[mask]).mean()
            ),
        }

        from sklearn.metrics import f1_score

        by_source[src]["f1"] = float(
            f1_score(
                y_test.values[mask],
                pred[mask],
                average="binary",
                pos_label="1",
                zero_division=0,
            )
        )

    # Planned reporting: top phishing terms
    coef = model.coef_[0]
    terms = np.array(vectorizer.get_feature_names_out())
    order = np.argsort(coef)

    top_phishing_terms = terms[order[-15:]][::-1].tolist()
    top_safe_terms = terms[order[:15]].tolist()

    print("\nAccuracy by source:")
    for src, values in by_source.items():
        print(
            f"  {src}: "
            f"n={values['n']} "
            f"accuracy={values['accuracy']:.4f} "
            f"F1={values['f1']:.4f}"
        )

    print("\nTop phishing terms:")
    print(top_phishing_terms)

    print("\nTop safe terms:")
    print(top_safe_terms)

    result = tu.evaluate(
        y_test,
        pred,
        classes,
        key="text_logreg",
        name="TF-IDF + Logistic Regression",
        task="text",
        dataset="Phishing Email + SMS",
        train_seconds=train_seconds,
        pos_label="1" if "1" in classes else None,
        extra={
            "by_source": by_source,
            "top_phishing_terms": top_phishing_terms,
            "top_safe_terms": top_safe_terms,
        },
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

    pipeline = Pipeline([
        ("tfidf", vectorizer),
        ("clf", model),
    ])

    bundle = {
        "kind": "tfidf_logreg",
        "pipeline": pipeline,
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
