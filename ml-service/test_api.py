"""End-to-end local test of the ML service."""
import json
import urllib.error
import urllib.request
from pathlib import Path

import pandas as pd

BASE = "http://127.0.0.1:7860"
ROOT = Path(__file__).resolve().parent
DEMO = ROOT.parent / "ml" / "data" / "processed" / "demo_network_sample_labeled.csv"


def read_key() -> str:
    env = ROOT / ".env"

    if not env.exists():
        raise SystemExit(
            "ml-service/.env not found."
        )

    for line in env.read_text(encoding="utf-8").splitlines():
        if line.startswith("ML_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")

    raise SystemExit("ML_API_KEY not found in ml-service/.env")


KEY = read_key()


def call(method, path, body=None, key=KEY):
    data = None if body is None else json.dumps(body).encode()

    headers = {"Content-Type": "application/json"}

    if key:
        headers["X-API-Key"] = key

    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers=headers,
        method=method
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())

    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read())
        except Exception:
            payload = {}

        return e.code, payload

    except urllib.error.URLError as e:
        raise SystemExit(
            f"Cannot reach {BASE} ({e.reason}). Is uvicorn running?"
        )


passed = failed = 0


def check(name, ok, detail=""):
    global passed, failed

    if ok:
        passed += 1
    else:
        failed += 1

    print(
        f"  [{'PASS' if ok else 'FAIL'}] {name} {detail}"
    )


print("\n== Health ==")

code, h = call("GET", "/health", key=None)

check(
    "GET /health returns 200",
    code == 200
)

print(
    "  mode:",
    h.get("mode"),
    "| versions:",
    h.get("versions")
)

for name, st in h.get("models", {}).items():
    print(
        f"  {name:<8} loaded={st['loaded']} "
        f"{st['error'] or ''}"
    )


print("\n== Security and validation ==")

code, _ = call(
    "POST",
    "/predict/url",
    {"url": "example.com"},
    key=None
)

check(
    "missing API key -> 401",
    code == 401
)

code, _ = call(
    "POST",
    "/predict/url",
    {"url": "example.com"},
    key="wrong-key"
)

check(
    "wrong API key -> 401",
    code == 401
)

code, _ = call(
    "POST",
    "/predict/url",
    {"url": "has spaces in it"}
)

check(
    "invalid URL -> 422",
    code == 422
)

code, _ = call(
    "POST",
    "/predict/text",
    {"text": "   "}
)

check(
    "blank text -> 422",
    code == 422
)


print("\n== URL scanner ==")

for url, expect_threat in [
    ("https://www.wikipedia.org/wiki/Python", False),
    ("https://www.google.com/search?q=cats", False),
    ("https://github.com/anthropics", False),
    ("http://paypal-secure-login.verify-account.example.ru/signin.php?id=1", True),
    ("http://192.168.1.1:8080/admin.exe", True),
    ("http://bit.ly/3xFreeGiftClaim", True),
]:
    code, r = call(
        "POST",
        "/predict/url",
        {"url": url}
    )

    ok = (
        code == 200
        and (
            r["is_threat"] == expect_threat
            or r["mock"]
        )
    )

    check(
        url[:62],
        ok,
        f"-> {r.get('label')} "
        f"threat_score={r.get('threat_score')} "
        f"{r.get('severity')}"
        + (" [MOCK]" if r.get("mock") else "")
    )


print("\n== Message scanner ==")

for text, expect_threat in [
    ("Hey, are we still meeting for lunch tomorrow?", False),
    (
        "URGENT: your account is suspended. "
        "Verify your password now at "
        "http://secure-login.example.com",
        True
    ),
    (
        "Congratulations! You have won a free gift card. "
        "Click here to claim your prize now.",
        True
    ),
]:
    code, r = call(
        "POST",
        "/predict/text",
        {"text": text}
    )

    ok = (
        code == 200
        and (
            r["is_threat"] == expect_threat
            or r["mock"]
        )
    )

    check(
        text[:62],
        ok,
        f"-> {r.get('label')} "
        f"threat_score={r.get('threat_score')}"
        + (" [MOCK]" if r.get("mock") else "")
    )

    if r.get("reasons"):
        print("       reasons:", r["reasons"])


print("\n== Network analyzer (demo sample) ==")

if not DEMO.exists():
    print("  demo file not found, skipping:", DEMO)

else:
    df = pd.read_csv(DEMO)

    truth = df["label"].tolist()
    rows = df.drop(columns="label").to_dict(
        orient="records"
    )

    code, r = call(
        "POST",
        "/predict/network",
        {"rows": rows}
    )

    check(
        "POST /predict/network returns 200",
        code == 200,
        f"({len(rows)} rows)"
    )

    if code == 200:
        pred = [
            x["label"]
            for x in r["results"]
        ]

        acc = sum(
            p == t
            for p, t in zip(pred, truth)
        ) / len(truth)

        print(
            "  label_counts :",
            r["label_counts"]
        )

        print(
            "  severity     :",
            r["severity_counts"]
        )

        print(
            "  warnings     :",
            r["warnings"]
        )

        print(
            f"  accuracy on demo sample: {acc:.1%}"
            + (" [MOCK]" if r["mock"] else "")
        )

        check(
            "demo accuracy >= 90% (live model)",
            acc >= 0.90 or r["mock"]
        )


print(
    f"\nResult: {passed} passed, {failed} failed"
)

raise SystemExit(
    1 if failed else 0
)
