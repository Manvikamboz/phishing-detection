import pandas as pd
import numpy as np
import joblib
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from xgboost import XGBClassifier

DATASET_PATH = "ml_model/dataset.csv"
MODEL_PATH   = "ml_model/phishing_model.pkl"


def train():
    df = pd.read_csv(DATASET_PATH)

    target_col = "status" if "status" in df.columns else df.columns[-1]
    le = LabelEncoder()
    df[target_col] = le.fit_transform(df[target_col])

    y = df[target_col]
    X = df.drop(columns=[target_col]).select_dtypes(include=["number"])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = XGBClassifier(
        n_estimators=400,
        max_depth=7,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1_weighted", n_jobs=-1)
    print(f"CV F1 scores: {cv_scores.round(4)} | Mean: {cv_scores.mean():.4f}")

    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # Top 10 important features
    importances = pd.Series(model.feature_importances_, index=X.columns)
    print("\nTop 10 features:")
    print(importances.nlargest(10).to_string())

    joblib.dump({"model": model, "features": list(X.columns), "label_encoder": le}, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")


if __name__ == "__main__":
    train()
