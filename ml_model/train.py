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

DATASET_PATH = "ml_model/dataset.csv"
MODEL_PATH   = "ml_model/phishing_model.pkl"

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


def _add_url_features(df: pd.DataFrame) -> pd.DataFrame:
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


def train():
    df = pd.read_csv(DATASET_PATH)

    target_col = "status" if "status" in df.columns else df.columns[-1]
    le = LabelEncoder()
    df[target_col] = le.fit_transform(df[target_col])

    df = _add_url_features(df)

    y = df[target_col]
    X = df.drop(columns=[target_col, "url"], errors="ignore").select_dtypes(include=["number"])
    X = _add_engineered_features(X)

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
    }, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")


if __name__ == "__main__":
    train()
