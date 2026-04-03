import pandas as pd
import numpy as np
import joblib
import math
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

import os

DATASET_PATH  = "ml_model/dataset.csv"
DATASET2_PATH = "ml_model/dataset2.csv"   # second Kaggle dataset (optional)
MODEL_PATH    = "ml_model/phishing_model.pkl"
MODEL2_PATH   = "ml_model/phishing_model_2.pkl"

_KNOWN_BRANDS = [
    "paypal", "ebay", "amazon", "google", "microsoft", "apple",
    "facebook", "instagram", "twitter", "netflix", "bank", "chase",
    "wellsfargo", "citibank", "hsbc", "barclays",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _min_brand_distance(url: str) -> int:
    try:
        parts = (urlparse(url).hostname or "").split(".")
        sld = parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")
        return min(_levenshtein(sld, b) for b in _KNOWN_BRANDS)
    except Exception:
        return 10


def _consonant_ratio(url: str) -> float:
    try:
        parts = (urlparse(url).hostname or "").split(".")
        sld = parts[0] if parts else ""
        letters = [c for c in sld.lower() if c.isalpha()]
        if not letters:
            return 0.0
        return len([c for c in letters if c not in "aeiou"]) / len(letters)
    except Exception:
        return 0.0


# Label normalization maps for different dataset conventions
_LABEL_MAP = {
    "bad":  "phishing",
    "good": "legitimate",
    "1":    "phishing",
    "0":    "legitimate",
}


def _normalize_labels(series: pd.Series) -> pd.Series:
    return series.astype(str).str.strip().str.lower().map(
        lambda v: _LABEL_MAP.get(v, v)
    )


def _extract_url_features_batch(urls: pd.Series) -> pd.DataFrame:
    """Extract URL-only features for datasets that have no pre-computed columns."""
    import re, math, itertools
    SHORTENING = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly|shorte\.st"
    PHISH_HINTS = r"login|verify|secure|account|update|banking|confirm|password|signin"
    BRANDS = r"paypal|ebay|amazon|google|microsoft|apple|facebook|instagram|twitter|netflix|bank"
    SUSP_TLDS = r"\.(tk|ml|ga|cf|gq|xyz|top|club|online|site|info|biz)$"

    rows = []
    for url in urls:
        url = str(url)
        try:
            parsed   = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            path     = parsed.path or ""
            full     = url.lower()
            parts    = hostname.split(".")
            tld      = parts[-1] if parts else ""
            words_raw  = [w for w in re.split(r"[\W_]+", full) if w]
            words_host = [w for w in re.split(r"[\W_]+", hostname) if w]
            words_path = [w for w in re.split(r"[\W_]+", path.lower()) if w]
            digits_url  = sum(c.isdigit() for c in url)
            digits_host = sum(c.isdigit() for c in hostname)
            nb_sub = max(len(parts) - 2, 0)
            char_repeat = max((len(list(g)) for _, g in itertools.groupby(full)), default=0)
            rows.append({
                "length_url":           len(url),
                "length_hostname":      len(hostname),
                "ip":                   int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))),
                "nb_dots":              url.count("."),
                "nb_hyphens":           url.count("-"),
                "nb_at":                url.count("@"),
                "nb_qm":                url.count("?"),
                "nb_and":               url.count("&"),
                "nb_or":                url.count("|"),
                "nb_eq":                url.count("="),
                "nb_underscore":        url.count("_"),
                "nb_tilde":             url.count("~"),
                "nb_percent":           url.count("%"),
                "nb_slash":             url.count("/"),
                "nb_star":              url.count("*"),
                "nb_colon":             url.count(":"),
                "nb_comma":             url.count(","),
                "nb_semicolumn":        url.count(";"),
                "nb_dollar":            url.count("$"),
                "nb_space":             url.count(" "),
                "nb_www":               full.count("www"),
                "nb_com":               full.count(".com"),
                "nb_dslash":            url.count("//"),
                "http_in_path":         int("http" in path.lower()),
                "https_token":          int("https" in hostname),
                "ratio_digits_url":     digits_url / len(url) if url else 0,
                "ratio_digits_host":    digits_host / len(hostname) if hostname else 0,
                "punycode":             int("xn--" in hostname),
                "port":                 int(parsed.port is not None),
                "tld_in_path":          int(tld in path.lower()),
                "tld_in_subdomain":     int(tld in ".".join(parts[:-2]) if len(parts) > 2 else False),
                "abnormal_subdomain":   int(bool(re.search(r"^(w[0-9]+|ww[^w])", hostname))),
                "nb_subdomains":        nb_sub,
                "prefix_suffix":        int("-" in hostname),
                "random_domain":        int(bool(re.search(r"[0-9]{4,}", hostname))),
                "shortening_service":   int(bool(re.search(SHORTENING, full))),
                "path_extension":       int(bool(re.search(r"\.(php|html|htm|asp|aspx|jsp)$", path.lower()))),
                "nb_redirection":       0,
                "nb_external_redirection": 0,
                "length_words_raw":     len(words_raw),
                "char_repeat":          char_repeat,
                "shortest_words_raw":   min((len(w) for w in words_raw), default=0),
                "shortest_word_host":   min((len(w) for w in words_host), default=0),
                "shortest_word_path":   min((len(w) for w in words_path), default=0),
                "longest_words_raw":    max((len(w) for w in words_raw), default=0),
                "longest_word_host":    max((len(w) for w in words_host), default=0),
                "longest_word_path":    max((len(w) for w in words_path), default=0),
                "avg_words_raw":        sum(len(w) for w in words_raw) / len(words_raw) if words_raw else 0,
                "avg_word_host":        sum(len(w) for w in words_host) / len(words_host) if words_host else 0,
                "avg_word_path":        sum(len(w) for w in words_path) / len(words_path) if words_path else 0,
                "phish_hints":          int(bool(re.search(PHISH_HINTS, full))),
                "domain_in_brand":      int(bool(re.search(BRANDS, hostname))),
                "brand_in_subdomain":   int(bool(re.search(BRANDS, ".".join(parts[:-2]))) if len(parts) > 2 else False),
                "brand_in_path":        int(bool(re.search(BRANDS, path.lower()))),
                "suspecious_tld":       int(bool(re.search(SUSP_TLDS, hostname))),
                "url_entropy":          _entropy(url),
                "hostname_entropy":     _entropy(hostname),
                "min_brand_distance":   _min_brand_distance(url),
                "consonant_ratio":      _consonant_ratio(url),
            })
        except Exception:
            rows.append({})
    return pd.DataFrame(rows).fillna(0)



    """Compute entropy, brand distance, consonant ratio from the URL column."""
    if "url" not in df.columns:
        return df
    df = df.copy()
    df["url_entropy"]        = df["url"].apply(_entropy)
    df["hostname_entropy"]   = df["url"].apply(
        lambda u: _entropy(urlparse(u).hostname or "")
    )
    df["min_brand_distance"] = df["url"].apply(_min_brand_distance)
    df["consonant_ratio"]    = df["url"].apply(_consonant_ratio)
    return df


def _add_url_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute entropy, brand distance, consonant ratio from the URL column."""
    if "url" not in df.columns:
        return df
    df = df.copy()
    df["url_entropy"]        = df["url"].apply(_entropy)
    df["hostname_entropy"]   = df["url"].apply(lambda u: _entropy(urlparse(u).hostname or ""))
    df["min_brand_distance"] = df["url"].apply(_min_brand_distance)
    df["consonant_ratio"]    = df["url"].apply(_consonant_ratio)
    return df


def _add_engineered_features(X: pd.DataFrame) -> pd.DataFrame:
    """Add interaction and ratio features on top of raw dataset columns."""
    X = X.copy()
    special = X.get("nb_at", 0) + X.get("nb_percent", 0) + X.get("nb_tilde", 0) + X.get("nb_dollar", 0)
    X["ratio_special_chars"] = special / (X["length_url"].replace(0, 1))
    X["subdomain_hyphen"]    = X.get("nb_subdomains", 0) * X.get("nb_hyphens", 0)
    X["ext_link_dominance"]  = X.get("ratio_extHyperlinks", 0) - X.get("ratio_intHyperlinks", 0)
    X["null_login_combo"]    = X.get("ratio_nullHyperlinks", 0) * X.get("login_form", 0)
    X["obfuscation_score"]   = (
        X.get("punycode", 0) * 3
        + X.get("shortening_service", 0) * 2
        + X.get("http_in_path", 0)
        + X.get("https_token", 0)
    )
    return X


def train(dataset_path: str = DATASET_PATH, model_path: str = MODEL_PATH):
    if not os.path.exists(dataset_path):
        print(f"Dataset not found: {dataset_path} — skipping.")
        return
    print(f"\nTraining on: {dataset_path}")
    df = pd.read_csv(dataset_path)

    # ── Detect dataset format ─────────────────────────────────────────────────
    # Format A: pre-extracted features (dataset1) — many numeric columns + url + status
    # Format B: URL-only (dataset2) — just URL/Label columns
    url_col    = next((c for c in df.columns if c.lower() == "url"), None)
    target_col = next((c for c in df.columns if c.lower() in ("status", "label", "class", "result")), df.columns[-1])

    # Normalize labels to legitimate/phishing regardless of source convention
    df[target_col] = _normalize_labels(df[target_col])
    df = df[df[target_col].isin(["legitimate", "phishing"])].reset_index(drop=True)

    is_url_only = url_col and df.select_dtypes(include=["number"]).shape[1] < 5

    if is_url_only:
        print(f"URL-only dataset detected ({len(df)} rows) — extracting features from URLs...")
        X = _extract_url_features_batch(df[url_col])
        X = _add_engineered_features(X)
    else:
        df = _add_url_features(df)
        X = df.drop(columns=[target_col, url_col or "url"], errors="ignore").select_dtypes(include=["number"])
        X = _add_engineered_features(X)

    le = LabelEncoder()
    le.fit(["legitimate", "phishing"])  # fixed order so both models share same encoding
    y = le.transform(df[target_col])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # ── Base learners ─────────────────────────────────────────────────────────
    xgb = XGBClassifier(
        n_estimators=500, max_depth=7, learning_rate=0.04,
        subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
        gamma=0.1, reg_alpha=0.1, reg_lambda=1.0,
        eval_metric="logloss", random_state=42, n_jobs=-1,
    )
    lgbm = LGBMClassifier(
        n_estimators=500, max_depth=7, learning_rate=0.04,
        subsample=0.8, colsample_bytree=0.8, min_child_weight=3,
        reg_alpha=0.1, reg_lambda=1.0,
        random_state=42, n_jobs=-1, verbose=-1,
    )
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=12, min_samples_leaf=2,
        random_state=42, n_jobs=-1,
    )

    # ── Stacking ensemble with LR meta-learner ────────────────────────────────
    stack = StackingClassifier(
        estimators=[("xgb", xgb), ("lgbm", lgbm), ("rf", rf)],
        final_estimator=LogisticRegression(C=1.0, max_iter=1000),
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
        passthrough=False,
        n_jobs=-1,
    )

    # ── Probability calibration (Platt scaling) ───────────────────────────────
    calibrated = CalibratedClassifierCV(stack, method="sigmoid", cv=3)

    print("Training stacking ensemble (XGBoost + LightGBM + RandomForest)...")
    calibrated.fit(X_train, y_train)

    y_pred  = calibrated.predict(X_test)
    y_proba = calibrated.predict_proba(X_test)[:, 1]

    print(classification_report(y_test, y_pred, target_names=le.classes_))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")

    # ── Feature importance from XGB base learner ──────────────────────────────
    try:
        inner_xgb = calibrated.calibrated_classifiers_[0].estimator.named_estimators_["xgb"]
        importances = pd.Series(inner_xgb.feature_importances_, index=X.columns)
        print("\nTop 15 features (XGB):")
        print(importances.nlargest(15).to_string())
    except Exception:
        pass

    joblib.dump({
        "model":         calibrated,
        "features":      list(X.columns),
        "label_encoder": le,
        "engineered":    True,
    }, model_path)
    print(f"Model saved to {model_path}")


if __name__ == "__main__":
    train(DATASET_PATH, MODEL_PATH)
    train(DATASET2_PATH, MODEL2_PATH)
