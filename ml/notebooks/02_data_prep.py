# %% [markdown]
# # CyberShield, Step 2: Data preparation
# Loads the raw datasets from ml/data/raw, cleans/encodes/splits them and saves
# the processed files into ml/data/processed.
#
# Outputs
# - CICIDS2017 (primary network dataset): cicids_train/test.csv.gz, cicids_*.json, cicids_scaler.joblib
# - NSL-KDD (secondary):                  nsl_train/test.csv.gz, nsl_*.json, nsl_scaler.joblib
# - URLs (lexical features):              url_train/test.csv.gz, url_*.json
# - Text (phishing emails + SMS spam):    text_train/test.csv.gz, text_classes.json
# - prep_report.json, demo_network_sample*.csv

# %% Setup
import json
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tqdm.auto import tqdm

warnings.filterwarnings("ignore")
SEED = 42
np.random.seed(SEED)


def find_root() -> Path:
    here = Path.cwd().resolve()
    for cand in [here, *here.parents]:
        if (cand / "ml" / "data" / "raw").exists():
            return cand
    raise FileNotFoundError(
        "Could not find ml/data/raw. Open the cyber-shield folder in VS Code "
        "or run this script from inside it."
    )


ROOT = find_root()
RAW = ROOT / "ml" / "data" / "raw"
OUT = ROOT / "ml" / "data" / "processed"
OUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "ml"))

from url_features import FEATURE_NAMES as URL_FEATURES  # noqa: E402
from url_features import extract_features, normalize_url  # noqa: E402

REPORT = {}


def save_json(obj, name):
    (OUT / name).write_text(json.dumps(obj, indent=2), encoding="utf-8")


def save_split(df, name):
    df.to_csv(OUT / name, index=False, compression="gzip")


print("Project root:", ROOT)
print("Raw folders :", sorted(p.name for p in RAW.iterdir()))

# %% [markdown]
# ## 1. CICIDS2017 (primary network dataset)

# %% CICIDS2017: load, label-group, sample per class
CIC_DIR = RAW / "cicids2017" / "MachineLearningCVE"
CIC_CAP = {
    "Normal": 60000, "DoS": 25000, "DDoS": 25000, "PortScan": 25000,
    "BruteForce": 25000, "WebAttack": 25000, "Bot": 25000,
}


def map_cic_label(raw):
    s = str(raw).strip()
    if s == "BENIGN":
        return "Normal"
    if s in {"DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"}:
        return "DoS"
    if s == "DDoS":
        return "DDoS"
    if s == "PortScan":
        return "PortScan"
    if s == "Bot":
        return "Bot"
    if s in {"FTP-Patator", "SSH-Patator"}:
        return "BruteForce"
    if s.startswith("Web Attack"):  # the file has a broken dash character here
        return "WebAttack"
    return None  # Infiltration, Heartbleed (too few rows) -> dropped


csv_files = sorted(CIC_DIR.glob("*.csv"))
print(f"Found {len(csv_files)} CICIDS2017 files")
parts = []
for f in tqdm(csv_files, desc="CICIDS files"):
    df = pd.read_csv(f, encoding="latin1", low_memory=False)
    df.columns = df.columns.str.strip()
    df = df.loc[:, ~df.columns.str.endswith(".1")]  # duplicated 'Fwd Header Length'
    df["label"] = df["Label"].map(map_cic_label)
    df = df.drop(columns="Label").dropna(subset=["label"])
    feats = [c for c in df.columns if c != "label"]
    df[feats] = df[feats].apply(pd.to_numeric, errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan)
    for lbl, g in df.groupby("label"):
        parts.append(g.sample(n=min(len(g), CIC_CAP[lbl]), random_state=SEED))
    del df

cic = pd.concat(parts, ignore_index=True)
del parts
before = len(cic)
cic = cic.drop_duplicates()
print(f"Dropped {before - len(cic):,} duplicate rows")
cic = pd.concat(
    [g.sample(n=min(len(g), CIC_CAP[l]), random_state=SEED) for l, g in cic.groupby("label")]
).reset_index(drop=True)
CIC_FEATURES = [c for c in cic.columns if c != "label"]
cic[CIC_FEATURES] = cic[CIC_FEATURES].astype("float32")
print("Rows:", len(cic), "| features:", len(CIC_FEATURES))
print(cic["label"].value_counts())

# %% CICIDS2017: split, impute (train medians only), scale, save
X_tr, X_te, y_tr, y_te = train_test_split(
    cic[CIC_FEATURES], cic["label"], test_size=0.2, stratify=cic["label"], random_state=SEED
)
medians = X_tr.median()
X_tr = X_tr.fillna(medians)
X_te = X_te.fillna(medians)

scaler = StandardScaler().fit(X_tr)  # only needed for the optional CNN-BiLSTM
joblib.dump(scaler, OUT / "cicids_scaler.joblib")

train = X_tr.copy()
train["label"] = y_tr.values
test = X_te.copy()
test["label"] = y_te.values
save_split(train, "cicids_train.csv.gz")
save_split(test, "cicids_test.csv.gz")

CIC_CLASSES = sorted(cic["label"].unique().tolist())
save_json(CIC_FEATURES, "cicids_feature_names.json")
save_json(CIC_CLASSES, "cicids_classes.json")
save_json({k: float(v) for k, v in medians.items()}, "cicids_medians.json")
REPORT["cicids"] = {
    "train_rows": len(train), "test_rows": len(test), "n_features": len(CIC_FEATURES),
    "classes": CIC_CLASSES,
    "train_class_counts": y_tr.value_counts().to_dict(),
    "test_class_counts": y_te.value_counts().to_dict(),
}
print("Saved CICIDS2017 files. Classes:", CIC_CLASSES)

# Demo upload files for the Network page (Step 9): 15 rows per class
demo = test.groupby("label", group_keys=False).head(15).sample(frac=1, random_state=SEED)
demo.to_csv(OUT / "demo_network_sample_labeled.csv", index=False)
demo.drop(columns="label").to_csv(OUT / "demo_network_sample.csv", index=False)
del cic, train, test, X_tr, X_te

# %% [markdown]
# ## 2. NSL-KDD (secondary; only KDDTest+.arff available)

# %% NSL-KDD
NSL_FILE = RAW / "nsl_kdd" / "KDDTest+.arff"

DOS = {"back", "land", "neptune", "pod", "smurf", "teardrop", "mailbomb", "apache2",
       "processtable", "udpstorm", "worm"}
PROBE = {"ipsweep", "nmap", "portsweep", "satan", "mscan", "saint"}
R2L = {"ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy", "warezclient",
       "warezmaster", "sendmail", "named", "snmpgetattack", "snmpguess", "xlock", "xsnoop"}
U2R = {"buffer_overflow", "loadmodule", "perl", "rootkit", "httptunnel", "ps", "sqlattack", "xterm"}


def nsl_group(name):
    if name == "normal":
        return "Normal"
    if name in DOS:
        return "DoS"
    if name in PROBE:
        return "Probe"
    if name in R2L:
        return "R2L"
    if name in U2R:
        return "U2R"
    return None


if NSL_FILE.exists():
    from scipy.io import arff

    data, meta = arff.loadarff(NSL_FILE)
    nsl = pd.DataFrame(data)
    for c in nsl.columns:
        if nsl[c].dtype == object:
            nsl[c] = nsl[c].apply(lambda v: v.decode("utf-8") if isinstance(v, bytes) else v)
    nsl.columns = [str(c).strip() for c in nsl.columns]

    label_col = "class" if "class" in nsl.columns else nsl.columns[-1]
    nsl = nsl.drop(columns=[c for c in ["difficulty", "difficulty_level"] if c in nsl.columns])
    raw_labels = nsl[label_col].astype(str).str.strip().str.lower()
    print("Raw class values:", raw_labels.value_counts().head(10).to_dict())

    if set(raw_labels.unique()) <= {"normal", "anomaly"}:
        NSL_MODE = "binary (this ARFF has only normal/anomaly labels)"
        nsl["label"] = raw_labels.map({"normal": "Normal", "anomaly": "Attack"})
    else:
        NSL_MODE = "5-class (Normal, DoS, Probe, R2L, U2R)"
        nsl["label"] = raw_labels.map(nsl_group)
        unknown = sorted(set(raw_labels[nsl["label"].isna()]))
        if unknown:
            print("Dropping unmapped attack names:", unknown)
    nsl = nsl.drop(columns=[label_col]).dropna(subset=["label"])
    print("NSL-KDD mode:", NSL_MODE)

    cat_cols = [c for c in ["protocol_type", "service", "flag"] if c in nsl.columns]
    num_cols = [c for c in nsl.columns if c not in cat_cols + ["label"]]
    nsl[num_cols] = nsl[num_cols].apply(pd.to_numeric, errors="coerce").fillna(0)
    nsl = pd.get_dummies(nsl, columns=cat_cols, dtype=int)
    nsl = nsl.drop_duplicates().reset_index(drop=True)

    NSL_FEATURES = [c for c in nsl.columns if c != "label"]
    nX_tr, nX_te, ny_tr, ny_te = train_test_split(
        nsl[NSL_FEATURES], nsl["label"], test_size=0.3, stratify=nsl["label"], random_state=SEED
    )
    nsl_scaler = StandardScaler().fit(nX_tr)
    joblib.dump(nsl_scaler, OUT / "nsl_scaler.joblib")

    n_train = nX_tr.copy()
    n_train["label"] = ny_tr.values
    n_test = nX_te.copy()
    n_test["label"] = ny_te.values
    save_split(n_train, "nsl_train.csv.gz")
    save_split(n_test, "nsl_test.csv.gz")
    NSL_CLASSES = sorted(nsl["label"].unique().tolist())
    save_json(NSL_FEATURES, "nsl_feature_names.json")
    save_json(NSL_CLASSES, "nsl_classes.json")
    REPORT["nsl_kdd"] = {
        "mode": NSL_MODE, "train_rows": len(n_train), "test_rows": len(n_test),
        "n_features": len(NSL_FEATURES), "classes": NSL_CLASSES,
        "train_class_counts": ny_tr.value_counts().to_dict(),
    }
    print(nsl["label"].value_counts())
    print("Saved NSL-KDD files.")
else:
    print("NSL-KDD file not found, skipping:", NSL_FILE)

# %% [markdown]
# ## 3. Malicious URLs (lexical features for XGBoost)

# %% URLs
URL_CAP = 30000
urls = pd.read_csv(RAW / "malicious_urls" / "malicious_phish.csv")
urls = urls.dropna(subset=["url", "type"])
urls["type"] = urls["type"].astype(str).str.strip().str.lower()
urls["url"] = urls["url"].astype(str).str.strip()
urls["norm"] = urls["url"].map(normalize_url)
urls = urls.drop_duplicates(subset="norm")
print("Types before sampling:", urls["type"].value_counts().to_dict())

urls = pd.concat(
    [g.sample(n=min(len(g), URL_CAP), random_state=SEED) for _, g in urls.groupby("type")]
).reset_index(drop=True)
print("Types after sampling :", urls["type"].value_counts().to_dict())

rows = [extract_features(u) for u in tqdm(urls["url"], desc="URL features")]
url_df = pd.DataFrame(rows, columns=URL_FEATURES, dtype="float32")
url_df.insert(0, "url", urls["url"].values)
url_df["type"] = urls["type"].values
url_df["label"] = (urls["type"] != "benign").astype(int).values  # 0 safe, 1 malicious

u_tr, u_te = train_test_split(url_df, test_size=0.2, stratify=url_df["type"], random_state=SEED)
save_split(u_tr, "url_train.csv.gz")
save_split(u_te, "url_test.csv.gz")
URL_CLASSES = sorted(url_df["type"].unique().tolist())
save_json(URL_FEATURES, "url_feature_names.json")
save_json(URL_CLASSES, "url_classes.json")
REPORT["urls"] = {
    "train_rows": len(u_tr), "test_rows": len(u_te), "n_features": len(URL_FEATURES),
    "classes": URL_CLASSES, "train_class_counts": u_tr["type"].value_counts().to_dict(),
}
print("Saved URL files. Classes:", URL_CLASSES)

# %% [markdown]
# ## 4. Text: phishing emails + SMS spam (label 1 = phishing/spam)

# %% Text
MAX_CHARS = 3000


def clean_text(s):
    s = " ".join(str(s).split())
    return s[:MAX_CHARS]


emails = pd.read_csv(RAW / "phishing_emails" / "Phishing_Email.csv")
print("Email columns:", list(emails.columns))
emails = emails.rename(columns={"Email Text": "text", "Email Type": "type"})
emails = emails.dropna(subset=["text", "type"])
print("Email types:", emails["type"].value_counts().to_dict())
emails["label"] = emails["type"].astype(str).str.contains("phish", case=False).astype(int)
emails["text"] = emails["text"].map(clean_text)
emails = emails[(emails["text"].str.len() > 5) & (emails["text"].str.lower() != "empty")]
emails["source"] = "email"
emails = emails[["text", "label", "source"]]

sms = pd.read_csv(
    RAW / "sms_spam" / "SMSSpamCollection",
    sep="\t", header=None, names=["type", "text"], quoting=3, encoding="latin-1",
)
sms = sms.dropna()
sms["label"] = (sms["type"].str.strip().str.lower() == "spam").astype(int)
sms["text"] = sms["text"].map(clean_text)
sms["source"] = "sms"
sms = sms[["text", "label", "source"]]

text_df = pd.concat([emails, sms], ignore_index=True).drop_duplicates(subset="text")
text_df = text_df.reset_index(drop=True)
print(text_df.groupby(["source", "label"]).size())

strat = text_df["source"] + "_" + text_df["label"].astype(str)
t_tr, t_te = train_test_split(text_df, test_size=0.2, stratify=strat, random_state=SEED)
save_split(t_tr, "text_train.csv.gz")
save_split(t_te, "text_test.csv.gz")
save_json(["safe", "phishing"], "text_classes.json")
REPORT["text"] = {
    "train_rows": len(t_tr), "test_rows": len(t_te),
    "train_label_counts": {int(k): int(v) for k, v in t_tr["label"].value_counts().items()},
    "sources": text_df["source"].value_counts().to_dict(),
}
print("Saved text files.")

# %% [markdown]
# ## 5. Report and file check

# %% Report
save_json(REPORT, "prep_report.json")
print(json.dumps(REPORT, indent=2, default=str))
print("\nFiles in", OUT)
for p in sorted(OUT.glob("*")):
    if p.name != ".gitkeep":
        print(f"  {p.name:<38} {p.stat().st_size / 1e6:8.2f} MB")