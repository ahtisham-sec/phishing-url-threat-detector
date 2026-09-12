"""
train_model.py
Trains a RandomForestClassifier on the features extracted from
data/urls_dataset.csv and saves the trained model + feature order to
model/phishing_model.joblib.

Run:
    python generate_dataset.py     # only needed once, or to regenerate
    python train_model.py
"""

import csv
import os

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                              confusion_matrix, precision_score, recall_score, f1_score)
from sklearn.model_selection import train_test_split

from feature_extractor import extract_features, features_to_vector, FEATURE_ORDER

DATASET_PATH = "data/urls_dataset.csv"
MODEL_PATH = "model/phishing_model.joblib"


def load_dataset(path=DATASET_PATH):
    urls, labels = [], []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"])
            labels.append(int(row["label"]))
    return urls, labels


def build_feature_matrix(urls):
    return [features_to_vector(extract_features(u)) for u in urls]


def train(dataset_path=DATASET_PATH, model_path=MODEL_PATH):
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(
            f"{dataset_path} not found. Run `python generate_dataset.py` first "
            "(or point this at a real labeled dataset with the same url,label columns)."
        )

    print(f"Loading dataset from {dataset_path}...")
    urls, labels = load_dataset(dataset_path)
    print(f"Loaded {len(urls)} URLs ({sum(labels)} phishing, {len(labels) - sum(labels)} legitimate).")

    print("Extracting features...")
    X = build_feature_matrix(urls)
    y = labels

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=12, random_state=42, class_weight="balanced"
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\n--- Evaluation on held-out test set ---")
    print(f"Accuracy:  {acc:.3f}")
    print(f"Precision: {prec:.3f}")
    print(f"Recall:    {rec:.3f}")
    print(f"F1 score:  {f1:.3f}")
    print("\nConfusion matrix (rows=actual, cols=predicted) [legit, phishing]:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

    importances = sorted(
        zip(FEATURE_ORDER, clf.feature_importances_), key=lambda x: -x[1]
    )
    print("Top 10 most important features:")
    for name, score in importances[:10]:
        print(f"  {name:<22} {score:.4f}")

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump({"model": clf, "feature_order": FEATURE_ORDER}, model_path)
    print(f"\nSaved trained model to {model_path}")

    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1}


if __name__ == "__main__":
    train()
