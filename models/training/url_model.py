"""
RiskPredict AI — URL Model Trainer
Trains a Random Forest classifier on the URL dataset and saves:
  - models/url_model.pkl  (the trained model)

No vectorizer needed — all features are already numerical/boolean.
"""

import os
import pickle
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_PATH = os.path.join(BASE_DIR, "data", "riskpredict_urls.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# ── Load data ─────────────────────────────────────────────────────────────────
print("Loading URL dataset...")
df = pd.read_csv(DATA_PATH)
print(f"  Rows: {len(df)} | Labels: {df['label'].value_counts().to_dict()}")

# ── Features ──────────────────────────────────────────────────────────────────
# All numerical/boolean — no text encoding needed
FEATURE_COLS = [
    "url_length",
    "has_https",
    "has_ip_address",
    "uses_shortener",
    "suspicious_keyword_count",
    "suspicious_tld",
    "special_char_count",
    "subdomain_count",
    "digit_count"
]

# Convert booleans to integers (True → 1, False → 0)
for col in ["has_https", "has_ip_address", "uses_shortener", "suspicious_tld"]:
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
y_pred     = model.predict(X_test)
label_names = ["LOW", "MEDIUM", "HIGH"]
print(f"\n  Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=label_names))

# ── Feature importance ────────────────────────────────────────────────────────
print("\nFeature Importances:")
importances = zip(FEATURE_COLS, model.feature_importances_)
for feat, imp in sorted(importances, key=lambda x: x[1], reverse=True):
    print(f"  {feat:<30} {imp:.4f}")

# ── Save model ────────────────────────────────────────────────────────────────
model_path = os.path.join(MODEL_DIR, "url_model.pkl")
with open(model_path, "wb") as f:
    pickle.dump(model, f)

# Save feature column names for consistent ordering during inference
meta_path = os.path.join(MODEL_DIR, "url_features.pkl")
with open(meta_path, "wb") as f:
    pickle.dump(FEATURE_COLS, f)

print(f"\nModel saved   → {model_path}")
print(f"Features saved → {meta_path}")
print("URL model training complete!")
