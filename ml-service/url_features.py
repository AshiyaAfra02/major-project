"""CyberShield URL feature extraction."""
import math
import re
from collections import Counter

SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
URL_SPLIT_RE = re.compile(r"^([^/?#]*)(/[^?#]*)?(?:\?([^#]*))?(?:#(.*))?$")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "lnkd.in", "t.ly",
}

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "update", "secure", "account", "bank",
    "paypal", "confirm", "password", "webscr", "billing", "wallet", "free",
    "bonus", "lucky", "prize", "support", "suspend", "unlock", "invoice",
    "crypto", "claim", "ebay", "amazon", "apple", "microsoft",
]

RISKY_EXTENSIONS = (
    ".exe", ".zip", ".rar", ".apk", ".scr", ".bin", ".msi", ".dmg",
    ".jar", ".bat", ".cmd", ".vbs", ".iso",
)

def normalize_url(url) -> str:
    s = str(url).strip()
    s = SCHEME_RE.sub("", s)
    if s.lower().startswith("www."):
        s = s[4:]
    return s

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def features_dict(url) -> dict:
    norm = normalize_url(url)
    m = URL_SPLIT_RE.match(norm)
    authority = (m.group(1) or "") if m else ""
    path = (m.group(2) or "") if m else ""
    query = (m.group(3) or "") if m else ""

    host = authority.split("@")[-1].lower()
    has_port = 0
    if ":" in host:
        maybe_host, _, maybe_port = host.rpartition(":")
        if maybe_port.isdigit():
            has_port = 1
            host = maybe_host

    labels = [p for p in host.split(".") if p]
    tld = labels[-1] if len(labels) > 1 else ""
    lower = norm.lower()
    n = max(len(norm), 1)

    digits = sum(ch.isdigit() for ch in norm)
    letters = sum(ch.isalpha() for ch in norm)
    special = sum((not ch.isalnum()) and ch not in ".-_/" for ch in norm)
    digit_runs = re.findall(r"\d+", norm)

    return {
        "url_length": len(norm),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": norm.count("."),
        "num_hyphens": norm.count("-"),
        "num_underscores": norm.count("_"),
        "num_slashes": norm.count("/"),
        "num_digits": digits,
        "num_letters": letters,
        "digit_ratio": digits / n,
        "letter_ratio": letters / n,
        "num_at": norm.count("@"),
        "num_question": norm.count("?"),
        "num_equals": norm.count("="),
        "num_ampersand": norm.count("&"),
        "num_percent": norm.count("%"),
        "num_special": special,
        "host_dots": host.count("."),
        "host_hyphens": host.count("-"),
        "host_digits": sum(ch.isdigit() for ch in host),
        "num_subdomains": max(0, len(labels) - 2),
        "tld_length": len(tld),
        "longest_host_label": max((len(p) for p in labels), default=0),
        "has_ip_host": int(bool(IPV4_RE.match(host))),
        "has_port": has_port,
        "is_shortener": int(host in SHORTENERS),
        "suspicious_word_count": sum(lower.count(w) for w in SUSPICIOUS_WORDS),
        "url_entropy": _entropy(norm),
        "host_entropy": _entropy(host),
        "path_depth": path.count("/"),
        "longest_digit_run": max((len(d) for d in digit_runs), default=0),
        "has_punycode": int("xn--" in host),
        "risky_extension": int(path.lower().endswith(RISKY_EXTENSIONS)),
        "double_slash_in_path": int("//" in path),
        "num_query_params": (query.count("&") + 1) if query else 0,
    }

FEATURE_NAMES = list(features_dict("example.com").keys())

def extract_features(url) -> list:
    d = features_dict(url)
    return [float(d[name]) for name in FEATURE_NAMES]

if __name__ == "__main__":
    for test in [
        "http://paypal-secure-login.example.com/verify?id=123",
        "https://www.google.com/search?q=cats",
        "192.168.1.1:8080/admin.exe",
    ]:
        print(test)
        print(dict(zip(FEATURE_NAMES, extract_features(test))))
        print()
