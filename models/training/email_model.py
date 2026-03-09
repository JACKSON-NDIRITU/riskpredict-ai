"""
RiskPredict AI — Email Model Trainer
Trains a Random Forest classifier on the email dataset and saves:
  - models/email_model.pkl       (the trained model)
  - models/email_vectorizer.pkl  (the TF-IDF vectorizer for text)
"""

import os
import pickle
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import scipy.sparse as sp

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_PATH  = os.path.join(BASE_DIR, "data", "riskpredict_emails.csv")
MODEL_DIR  = os.path.join(BASE_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# ── Load data ─────────────────────────────────────────────────────────────────
print("Loading email dataset...")
df = pd.read_csv(DATA_PATH)
print(f"  Rows: {len(df)} | Labels: {df['label'].value_counts().to_dict()}")

# ── Feature engineering ───────────────────────────────────────────────────────
# Combine subject + body into one text field for TF-IDF
df["text"] = df["subject"].fillna("") + " " + df["body"].fillna("")

# TF-IDF on combined text (max 500 features to keep it lightweight)
print("Fitting TF-IDF vectorizer...")
vectorizer = TfidfVectorizer(max_features=500, stop_words="english", ngram_range=(1, 2))
text_features = vectorizer.fit_transform(df["text"])

# Encode sender domain as a simple feature (has @ sign = legitimate format)
df["sender_has_at"] = df["sender"].apply(lambda x: 1 if "@" in str(x) else 0)

# Combine TF-IDF features with sender feature
import numpy as np
sender_feature = sp.csr_matrix(df[["sender_has_at"]].values)
X = sp.hstack([text_features, sender_feature])

# ── Encode labels ─────────────────────────────────────────────────────────────
label_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
y = df["label"].map(label_order).values

# ── Train / test split ────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"  Training samples: {X_train.shape[0]} | Test samples: {X_test.shape[0]}")

# ── Train Random Forest ───────────────────────────────────────────────────────
print("Training Random Forest...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    max_features="sqrt",
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# ── Evaluate ──────────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)
label_names = ["LOW", "MEDIUM", "HIGH"]
print(f"\n  Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=label_names))

# ── Save model + vectorizer ───────────────────────────────────────────────────
model_path      = os.path.join(MODEL_DIR, "email_model.pkl")
vectorizer_path = os.path.join(MODEL_DIR, "email_vectorizer.pkl")

with open(model_path, "wb") as f:
    pickle.dump(model, f)
with open(vectorizer_path, "wb") as f:
    pickle.dump(vectorizer, f)

print(f"\nModel saved      → {model_path}")
print(f"Vectorizer saved → {vectorizer_path}")
print("Email model training complete!")
