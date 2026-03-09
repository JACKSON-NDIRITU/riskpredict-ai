"""
RiskPredict AI — Log Events Model Trainer
Trains a Random Forest classifier on the log dataset and saves:
  - models/log_model.pkl  (the trained model)

Features are numerical/boolean — no vectorizer needed.
"""

import os
import pickle
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_PATH = os.path.join(BASE_DIR, "data", "riskpredict_logs.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# ── Load data ─────────────────────────────────────────────────────────────────
print("Loading log dataset...")
df = pd.read_csv(DATA_PATH)
print(f"  Rows: {len(df)} | Labels: {df['label'].value_counts().to_dict()}")

# ── Features ──────────────────────────────────────────────────────────────────
FEATURE_COLS = [
    "is_privileged_user",
    "keyword_match_count",
    "has_ip",
    "is_external_ip",
    "indicator_count",
    "risk_score"
]

# Convert booleans to integers
for col in ["is_privileged_user", "has_ip", "is_external_ip"]:
    df[col] = df[col].astype(int)

X = df[FEATURE_COLS].values

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
y_pred      = model.predict(X_test)
label_names = ["LOW", "MEDIUM", "HIGH"]
print(f"\n  Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=label_names))

# ── Feature importance ────────────────────────────────────────────────────────
print("\nFeature Importances:")
importances = zip(FEATURE_COLS, model.feature_importances_)
for feat, imp in sorted(importances, key=lambda x: x[1], reverse=True):
    print(f"  {feat:<25} {imp:.4f}")

# ── Save model ────────────────────────────────────────────────────────────────
model_path = os.path.join(MODEL_DIR, "log_model.pkl")
with open(model_path, "wb") as f:
    pickle.dump(model, f)

meta_path = os.path.join(MODEL_DIR, "log_features.pkl")
with open(meta_path, "wb") as f:
    pickle.dump(FEATURE_COLS, f)

print(f"\nModel saved    → {model_path}")
print(f"Features saved → {meta_path}")
print("Log model training complete!")
