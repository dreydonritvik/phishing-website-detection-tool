"""
Evaluate the phishing detection model on a held-out test split.

Reproduces the exact setup of train_model.py (same 16 features, stratified
80/20 split, random_state=42, 100-tree Random Forest) and reports metrics on
the 20% test set the model never sees during training.

It also trains a second model on URL features only (no page content) to show
how much the DOM features contribute.

Usage (from the server/ directory):
    python evaluate.py

Note on labels: in the PhiUSIIL dataset, label 0 = phishing and
label 1 = legitimate, so phishing is treated as the positive class here.
"""

import json

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

DATASET_PATH = "./datasets/dataset_full.csv"
PHISHING_LABEL = 0  # PhiUSIIL convention: 0 = phishing, 1 = legitimate
RANDOM_STATE = 42

# Same 16 features as train_model.py
FEATURE_NAMES = [
    'URLLength', 'DomainLength', 'IsDomainIP', 'TLDLength', 'NoOfSubDomain',
    'LetterRatioInURL', 'DegitRatioInURL', 'NoOfOtherSpecialCharsInURL', 'IsHTTPS',
    'LineOfCode', 'HasPasswordField', 'HasHiddenFields', 'NoOfImage', 'NoOfCSS',
    'NoOfJS', 'NoOfExternalRef'
]

# Subset that can be computed from the URL alone (no page content)
URL_FEATURES = FEATURE_NAMES[:9]


def evaluate(X_train, X_test, y_train, y_test):
    model = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    phishing_col = list(model.classes_).index(PHISHING_LABEL)
    y_score = model.predict_proba(X_test)[:, phishing_col]

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, pos_label=PHISHING_LABEL),
        "recall": recall_score(y_test, y_pred, pos_label=PHISHING_LABEL),
        "f1": f1_score(y_test, y_pred, pos_label=PHISHING_LABEL),
        "roc_auc": roc_auc_score(y_test == PHISHING_LABEL, y_score),
    }
    return model, y_pred, metrics


def main():
    df = pd.read_csv(DATASET_PATH)
    df.columns = df.columns.str.strip()
    y = df['label']

    print(f"Dataset: {len(df):,} URLs")
    print(f"Class counts: phishing (0) = {(y == 0).sum():,}, legitimate (1) = {(y == 1).sum():,}\n")

    X_train, X_test, y_train, y_test = train_test_split(
        df[FEATURE_NAMES], y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    print(f"Train: {len(X_train):,}  |  Test (held out): {len(X_test):,}\n")

    # Full model (16 features), identical to train_model.py
    _, y_pred, full = evaluate(X_train, X_test, y_train, y_test)

    # URL-only model (9 features)
    _, _, url_only = evaluate(X_train[URL_FEATURES], X_test[URL_FEATURES], y_train, y_test)

    print("=== Full model (16 URL + DOM features) ===")
    print(classification_report(y_test, y_pred, target_names=["phishing (0)", "legitimate (1)"], digits=4))
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[1, PHISHING_LABEL]).ravel()
    print("Confusion matrix (phishing = positive):")
    print(f"  Phishing caught:        {tp:,}")
    print(f"  Phishing missed:        {fn:,}")
    print(f"  Legitimate flagged:     {fp:,}")
    print(f"  Legitimate passed:      {tn:,}\n")

    # Markdown table ready to paste into README.md
    def pct(v):
        return f"{v * 100:.2f}%"

    print("=== README table ===")
    print("| Model | Accuracy | Precision | Recall | F1 (phishing) | ROC-AUC |")
    print("| :--- | :---: | :---: | :---: | :---: | :---: |")
    print(f"| URL + DOM features (16) | {pct(full['accuracy'])} | {pct(full['precision'])} | "
          f"{pct(full['recall'])} | {pct(full['f1'])} | {full['roc_auc']:.4f} |")
    print(f"| URL features only (9) | {pct(url_only['accuracy'])} | {pct(url_only['precision'])} | "
          f"{pct(url_only['recall'])} | {pct(url_only['f1'])} | {url_only['roc_auc']:.4f} |")

    with open("evaluation_results.json", "w") as f:
        json.dump({"full_model": full, "url_only_model": url_only,
                   "test_size": len(X_test)}, f, indent=2)
    print("\nSaved metrics to evaluation_results.json")


if __name__ == "__main__":
    main()
