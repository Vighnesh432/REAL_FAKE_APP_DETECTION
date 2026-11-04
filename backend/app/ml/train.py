import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from xgboost import XGBClassifier

from .features import (
    STRUCTURED_FEATURES, build_category_matrix, build_structured_matrix, build_text_corpus,
)

RANDOM_STATE = 42
ARTIFACT_DIR = Path(__file__).resolve().parents[2] / "models_store"
ARTIFACT_PATH = ARTIFACT_DIR / "model.joblib"
REPORT_PATH = ARTIFACT_DIR / "training_report.json"


def fit_transformers(train_df: pd.DataFrame):
    desc_corpus, review_corpus = build_text_corpus(train_df)
    desc_vec = TfidfVectorizer(max_features=3000, ngram_range=(1, 2), min_df=3, max_df=0.9, sublinear_tf=True)
    review_vec = TfidfVectorizer(max_features=1500, ngram_range=(1, 2), min_df=3, max_df=0.9, sublinear_tf=True)
    desc_vec.fit(desc_corpus)
    review_vec.fit(review_corpus)
    scaler = StandardScaler()
    scaler.fit(build_structured_matrix(train_df).values)
    return {"desc_vec": desc_vec, "review_vec": review_vec, "scaler": scaler}


def transform(df: pd.DataFrame, tf: dict) -> csr_matrix:
    desc_corpus, review_corpus = build_text_corpus(df)
    X_desc = tf["desc_vec"].transform(desc_corpus)
    X_rev = tf["review_vec"].transform(review_corpus)
    X_struct = csr_matrix(tf["scaler"].transform(build_structured_matrix(df).values))
    X_cat = csr_matrix(build_category_matrix(df).values)
    return hstack([X_desc, X_rev, X_struct, X_cat], format="csr")


def feature_names(tf: dict) -> list[str]:
    from .features import CATEGORIES
    return (
        [f"desc::{t}" for t in tf["desc_vec"].get_feature_names_out()]
        + [f"review::{t}" for t in tf["review_vec"].get_feature_names_out()]
        + [f"meta::{t}" for t in STRUCTURED_FEATURES]
        + [f"cat::{c}" for c in CATEGORIES]
    )


def build_models() -> dict:
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=300, max_depth=None, min_samples_leaf=2,
            class_weight="balanced", n_jobs=-1, random_state=RANDOM_STATE),
        "svm": CalibratedClassifierCV(
            LinearSVC(C=0.5, class_weight="balanced", random_state=RANDOM_STATE, max_iter=5000),
            cv=3, method="sigmoid"),
        "logistic_regression": LogisticRegression(
            C=1.0, max_iter=2000, class_weight="balanced", solver="liblinear",
            random_state=RANDOM_STATE),
        "xgboost": XGBClassifier(
            n_estimators=400, max_depth=6, learning_rate=0.08, subsample=0.9,
            colsample_bytree=0.8, reg_lambda=1.5, eval_metric="logloss",
            tree_method="hist", n_jobs=-1, random_state=RANDOM_STATE),
    }


def evaluate(model, X_test, y_test) -> dict:
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    return {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, y_proba)), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "false_positive_rate": round(float(fp / max(fp + tn, 1)), 4),
    }


def top_feature_importances(model, names: list[str], k: int = 25) -> list[dict]:
    if hasattr(model, "feature_importances_"):
        imp = np.asarray(model.feature_importances_, dtype=float)
    elif hasattr(model, "coef_"):
        imp = np.abs(np.asarray(model.coef_, dtype=float)).ravel()
    else:
        return []
    idx = np.argsort(imp)[::-1][:k]
    total = imp.sum() or 1.0
    return [{"feature": names[i], "importance": round(float(imp[i] / total), 5)} for i in idx]


def run(data_path: str, test_size: float = 0.2, cv_folds: int = 5, quick: bool = False) -> dict:
    df = pd.read_csv(data_path)
    required = {"description", "reviews", "permissions", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing)}")

    y = df["label"].astype(int).values
    train_df, test_df, y_train, y_test = train_test_split(
        df, y, test_size=test_size, stratify=y, random_state=RANDOM_STATE)

    print(f"[1/4] Fitting transformers on {len(train_df)} training rows...")
    tf = fit_transformers(train_df)
    names = feature_names(tf)

    print("[2/4] Building feature matrices...")
    X_train, X_test = transform(train_df, tf), transform(test_df, tf)
    print(f"      feature space: {X_train.shape[1]} dimensions")

    print("[3/4] Training and comparing models...")
    results, fitted = {}, {}
    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=RANDOM_STATE)

    for name, model in build_models().items():
        t0 = time.time()
        model.fit(X_train, y_train)
        metrics = evaluate(model, X_test, y_test)
        if not quick:
            cv = cross_val_score(model, X_train, y_train, cv=skf, scoring="f1", n_jobs=1)
            metrics["cv_f1_mean"] = round(float(cv.mean()), 4)
            metrics["cv_f1_std"] = round(float(cv.std()), 4)
        metrics["train_seconds"] = round(time.time() - t0, 2)
        results[name], fitted[name] = metrics, model
        print(f"      {name:<20} f1={metrics['f1']:.4f}  auc={metrics['roc_auc']:.4f}  "
              f"fpr={metrics['false_positive_rate']:.4f}  ({metrics['train_seconds']}s)")

    best_name = max(results, key=lambda n: (results[n]["f1"], -results[n]["false_positive_rate"]))
    best_model = fitted[best_name]
    print(f"[4/4] Best model: {best_name} (f1={results[best_name]['f1']})")

    report = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": str(data_path),
        "n_samples": len(df),
        "n_train": len(train_df),
        "n_test": len(test_df),
        "class_balance": {"genuine": int((y == 0).sum()), "fake": int((y == 1).sum())},
        "n_features": int(X_train.shape[1]),
        "best_model": best_name,
        "models": results,
        "top_features": top_feature_importances(best_model, names),
        "classification_report": classification_report(
            y_test, best_model.predict(X_test), target_names=["Genuine", "Fake"],
            output_dict=True, zero_division=0),
    }

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"model": best_model, "model_name": best_name, "all_models": fitted,
         "transformers": tf, "feature_names": names, "structured_features": STRUCTURED_FEATURES,
         "report": report, "version": report["trained_at"]},
        ARTIFACT_PATH, compress=3,
    )
    REPORT_PATH.write_text(json.dumps(report, indent=2))
    print(f"      artifact -> {ARTIFACT_PATH}")
    print(f"      report   -> {REPORT_PATH}")
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/apps_dataset.csv")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--cv-folds", type=int, default=5)
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    run(a.data, a.test_size, a.cv_folds, a.quick)
