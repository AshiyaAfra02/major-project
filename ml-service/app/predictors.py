"""Model loading, prediction and MOCK fallback for the CyberShield ML service."""
import hashlib
import json
import logging
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from url_features import extract_features, features_dict

log = logging.getLogger("cybershield.ml")

MODEL_FILES = {
    "network": "network_model.joblib",
    "url": "url_model.joblib",
    "text": "text_model.joblib",
}

SAFE_ACTION = "No action required."

NETWORK_ACTIONS = {
    "DoS": "Enable rate limiting on the targeted service, block the source IPs at the firewall, and check server resource usage.",
    "DDoS": "Activate DDoS protection / CDN scrubbing, rate-limit upstream, and notify the hosting provider or ISP.",
    "PortScan": "Block the scanning source IP, close unused ports, and review firewall rules for exposed services.",
    "BruteForce": "Lock the targeted accounts, block the source IP, enforce MFA, and review authentication logs.",
    "WebAttack": "Enable WAF rules for SQLi/XSS, sanitize inputs on the affected endpoints, and review web server logs.",
    "Bot": "Isolate the infected host from the network, block its command-and-control traffic, and run malware cleanup.",
    "default": "Investigate the flow, isolate the source if confirmed malicious, and review firewall logs.",
}

URL_ACTIONS = {
    "phishing": "Block the domain at DNS/web-filter level, warn users not to enter credentials, and report it to the brand owner.",
    "malware": "Block the URL immediately, do not download anything from it, and scan any machine that visited it.",
    "defacement": "Treat the site as compromised: avoid it and notify its owner or administrator.",
    "default": "Block the URL and review who accessed it.",
}

TEXT_ACTION = "Do not click links or reply. Report it as phishing, delete it, and warn the recipients."

MOCK_NETWORK_CLASSES = ["Normal", "DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Bot"]


def model_dir() -> Path:
    d = Path(os.getenv("MODEL_DIR", "models"))
    return d if d.is_absolute() else ROOT / d


def severity_for(score: float, is_threat: bool) -> str:
    if not is_threat:
        return "none"
    if score >= 0.95:
        return "critical"
    if score >= 0.85:
        return "high"
    if score >= 0.70:
        return "medium"
    return "low"


def _mock_score(text: str) -> float:
    digest = hashlib.sha256(text.encode("utf-8", "ignore")).digest()
    return int.from_bytes(digest[:4], "big") / 0xFFFFFFFF


def _pack(*, label, is_threat, confidence, threat_score, probabilities,
          reasons, mock, version, action):
    return {
        "label": label,
        "is_threat": bool(is_threat),
        "confidence": round(float(confidence), 4),
        "threat_score": round(float(threat_score), 4),
        "severity": severity_for(float(threat_score), bool(is_threat)),
        "recommended_action": action if is_threat else SAFE_ACTION,
        "probabilities": {k: round(float(v), 4) for k, v in probabilities.items()},
        "reasons": reasons,
        "mock": mock,
        "model_version": version,
    }


class ModelStore:
    def __init__(self):
        self.bundles: dict[str, Any] = {}
        self.errors: dict[str, str] = {}
        self.text_terms = None

    def load(self):
        folder = model_dir()
        log.info("Loading models from %s", folder)

        for name, filename in MODEL_FILES.items():
            path = folder / filename

            if not path.exists():
                self.errors[name] = f"{filename} not found in {folder}"
                log.warning("%s model missing -> MOCK mode", name)
                continue

            try:
                self.bundles[name] = joblib.load(path)
                log.info("Loaded %s model (%s)", name, filename)
            except Exception as exc:
                self.errors[name] = f"{type(exc).__name__}: {exc}"
                log.exception("Could not load %s model -> MOCK mode", name)

        text = self.bundles.get("text")
        if text is not None:
            try:
                self.text_terms = text["pipeline"].named_steps["tfidf"].get_feature_names_out()
            except Exception:
                self.text_terms = None

    def status(self):
        return {
            name: {
                "loaded": name in self.bundles,
                "mock": name not in self.bundles,
                "error": self.errors.get(name),
            }
            for name in MODEL_FILES
        }

    def mode(self):
        loaded = len(self.bundles)
        if loaded == len(MODEL_FILES):
            return "live"
        return "mock" if loaded == 0 else "partial"


store = ModelStore()


def url_signals(url: str) -> list[str]:
    f = features_dict(url)
    out = []

    if f["has_ip_host"]:
        out.append("Host is a raw IP address")
    if f["is_shortener"]:
        out.append("Uses a link-shortening service")
    if f["num_at"]:
        out.append("Contains '@', which can hide the real destination")
    if f["suspicious_word_count"] >= 2:
        out.append(f"Contains {int(f['suspicious_word_count'])} suspicious keywords")
    if f["url_length"] > 75:
        out.append("Unusually long URL")
    if f["host_hyphens"] >= 3:
        out.append("Many hyphens in the domain name")
    if f["num_subdomains"] >= 3:
        out.append("Many nested subdomains")
    if f["has_punycode"]:
        out.append("Punycode domain")
    if f["risky_extension"]:
        out.append("Points to a risky file type")
    if f["has_port"]:
        out.append("Uses a non-standard port")
    if f["url_entropy"] > 4.5:
        out.append("High character randomness")

    return out


def predict_url(url: str) -> dict:
    signals = url_signals(url)
    bundle = store.bundles.get("url")

    if bundle is None:
        score = min(0.98, 0.10 + 0.18 * len(signals) + 0.25 * _mock_score(url))
        is_threat = score >= 0.5

        return _pack(
            label="phishing" if is_threat else "benign",
            is_threat=is_threat,
            confidence=score if is_threat else 1 - score,
            threat_score=score,
            probabilities={"benign": 1 - score, "phishing": score},
            reasons=["MOCK prediction: the URL model file is not loaded."] + signals,
            mock=True,
            version="mock",
            action=URL_ACTIONS["phishing"],
        )

    features = bundle["features"]
    values = extract_features(url)

    if len(values) != len(features):
        raise RuntimeError(
            "url_features.py does not match the trained model (feature count differs)."
        )

    x = pd.DataFrame([values], columns=features).astype("float32")
    proba = bundle["model"].predict_proba(x)[0]
    classes = bundle["classes"]
    benign_idx = bundle["benign_index"]
    p_mal = float(1.0 - proba[benign_idx])
    is_threat = p_mal >= bundle.get("threshold", 0.5)

    if is_threat:
        best = max(
            (i for i in range(len(classes)) if i != benign_idx),
            key=lambda i: proba[i],
        )
        label, confidence = classes[best], p_mal
    else:
        label, confidence = "benign", 1.0 - p_mal

    return _pack(
        label=label,
        is_threat=is_threat,
        confidence=confidence,
        threat_score=p_mal,
        probabilities={classes[i]: proba[i] for i in range(len(classes))},
        reasons=signals,
        mock=False,
        version=f"{bundle['kind']}-{bundle.get('version', '1.0')}",
        action=URL_ACTIONS.get(label, URL_ACTIONS["default"]),
    )


LINK_RE = re.compile(r"https?://|www\.", re.IGNORECASE)
MOCK_WORDS = [
    "urgent", "verify", "password", "account", "suspended",
    "click", "winner", "prize", "free", "bank"
]


def _text_reasons(text: str, k: int = 5) -> list[str]:
    reasons = []

    if LINK_RE.search(text):
        reasons.append("Message contains a link")

    bundle = store.bundles.get("text")

    if bundle is not None and store.text_terms is not None:
        try:
            pipe = bundle["pipeline"]
            coef = pipe.named_steps["clf"].coef_[0]
            X = pipe.named_steps["tfidf"].transform([text]).tocoo()

            contrib = sorted(
                (
                    (float(v * coef[j]), str(store.text_terms[j]))
                    for j, v in zip(X.col, X.data)
                ),
                reverse=True,
            )

            top = [term for c, term in contrib[:k] if c > 0]

            if top:
                reasons.append(
                    "Wording that raised the phishing score: " + ", ".join(top)
                )
        except Exception:
            pass

    return reasons


def predict_text(text: str) -> dict:
    bundle = store.bundles.get("text")

    if bundle is None:
        low = text.lower()
        hits = sum(w in low for w in MOCK_WORDS)
        if LINK_RE.search(text):
            hits += 2

        score = min(0.98, 0.08 + 0.15 * hits + 0.2 * _mock_score(text))
        is_threat = score >= 0.5

        return _pack(
            label="phishing" if is_threat else "safe",
            is_threat=is_threat,
            confidence=score if is_threat else 1 - score,
            threat_score=score,
            probabilities={"safe": 1 - score, "phishing": score},
            reasons=["MOCK prediction: the text model file is not loaded."]
                     + _text_reasons(text),
            mock=True,
            version="mock",
            action=TEXT_ACTION,
        )

    p = float(bundle["pipeline"].predict_proba([text])[0][1])
    is_threat = p >= bundle.get("threshold", 0.5)

    return _pack(
        label="phishing" if is_threat else "safe",
        is_threat=is_threat,
        confidence=p if is_threat else 1 - p,
        threat_score=p,
        probabilities={"safe": 1 - p, "phishing": p},
        reasons=_text_reasons(text),
        mock=False,
        version=f"tfidf-lr-{bundle.get('version', '1.0')}",
        action=TEXT_ACTION,
    )


def _network_response(
    labels,
    confidences,
    threat_scores,
    *,
    mock,
    version,
    warnings,
):
    results = []

    for i, (label, conf, ts) in enumerate(
        zip(labels, confidences, threat_scores)
    ):
        is_threat = label != "Normal"

        results.append({
            "index": i,
            "label": label,
            "confidence": round(float(conf), 4),
            "threat_score": round(float(ts), 4),
            "is_threat": is_threat,
            "severity": severity_for(float(ts), is_threat),
        })

    label_counts = Counter(r["label"] for r in results)
    severity_counts = Counter(r["severity"] for r in results)

    actions = {
        lbl: NETWORK_ACTIONS.get(lbl, NETWORK_ACTIONS["default"])
        for lbl in label_counts
        if lbl != "Normal"
    }

    return {
        "total_rows": len(results),
        "threats": sum(1 for r in results if r["is_threat"]),
        "label_counts": dict(label_counts),
        "severity_counts": dict(severity_counts),
        "recommended_actions": actions,
        "results": results,
        "warnings": warnings,
        "mock": mock,
        "model_version": version,
    }


def _mock_network(rows: list[dict]) -> dict:
    labels, confs, scores = [], [], []

    for i, row in enumerate(rows):
        s = _mock_score(
            json.dumps(row, sort_keys=True, default=str) + str(i)
        )

        if s < 0.6:
            threat = 0.05 + s * 0.2
            labels.append("Normal")
            confs.append(1 - threat)
        else:
            frac = (s - 0.6) / 0.4
            threat = 0.70 + 0.29 * frac
            labels.append(
                MOCK_NETWORK_CLASSES[1 + int(frac * 6) % 6]
            )
            confs.append(threat)

        scores.append(threat)

    return _network_response(
        labels,
        confs,
        scores,
        mock=True,
        version="mock",
        warnings=["MOCK prediction: the network model file is not loaded."],
    )


def predict_network(rows: list[dict]) -> dict:
    bundle = store.bundles.get("network")

    if bundle is None:
        return _mock_network(rows)

    features = bundle["features"]
    classes = bundle["classes"]
    medians = bundle.get("medians", {})

    df = pd.DataFrame(rows)
    df.columns = [str(c).strip() for c in df.columns]
    df = df.loc[:, ~df.columns.duplicated()]

    missing = [c for c in features if c not in df.columns]

    if len(missing) > len(features) * 0.5:
        raise ValueError(
            f"Input does not look like CICIDS2017 flow data: "
            f"{len(missing)} of {len(features)} expected columns are missing "
            f"(for example: {missing[:5]})."
        )

    X = df.reindex(columns=features)
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(pd.Series(medians)).fillna(0.0).astype("float32")

    proba = bundle["model"].predict_proba(X)
    idx = proba.argmax(axis=1)

    labels = [classes[i] for i in idx]
    confidences = proba.max(axis=1)

    normal_idx = classes.index("Normal")
    threat_scores = 1.0 - proba[:, normal_idx]

    warnings = []

    if missing:
        warnings.append(
            f"{len(missing)} expected columns were missing and filled "
            f"with training medians."
        )

    return _network_response(
        labels,
        confidences,
        threat_scores,
        mock=False,
        version=f"{bundle['kind']}-{bundle.get('version', '1.0')}",
        warnings=warnings,
    )


def load_metrics() -> dict | None:
    path = model_dir() / "metrics.json"

    if not path.exists():
        return None

    return json.loads(path.read_text(encoding="utf-8"))
