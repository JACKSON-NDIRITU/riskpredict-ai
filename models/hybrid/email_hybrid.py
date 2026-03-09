"""
RiskPredict AI — Email Hybrid Analyzer
Combines your existing rule engine with the trained ML model.
Always returns the higher risk of the two (safety first).
"""

import os
import re
import pickle
import scipy.sparse as sp

# ── Load model + vectorizer once at startup ───────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH      = os.path.join(BASE_DIR, "email_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "email_vectorizer.pkl")

_model      = None
_vectorizer = None

def _load_model():
    global _model, _vectorizer
    if _model is None:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        with open(VECTORIZER_PATH, "rb") as f:
            _vectorizer = pickle.load(f)

# ── Risk ordering helper ──────────────────────────────────────────────────────
RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
RISK_LABELS = {0: "LOW", 1: "MEDIUM", 2: "HIGH"}

def higher_risk(a, b):
    return a if RISK_ORDER[a] >= RISK_ORDER[b] else b

# ── Rule engine (your existing logic) ────────────────────────────────────────
def _rule_analyze(sender, subject, body):
    indicators = []
    email_text = f"{subject} {body}".lower()

    scam_phrases = [
        "urgent action required", "verify your identity",
        "account suspended", "click the link",
        "your package is on hold", "update payment method"
    ]
    if any(phrase in email_text for phrase in scam_phrases):
        indicators.append("Scam-like language detected")

    finance_indicators = ["wire transfer", "gift card", "crypto payment", "invoice due"]
    if any(f in email_text for f in finance_indicators):
        indicators.append("Potential financial fraud")

    urls = re.findall(r"https?://\S+", email_text)
    if urls:
        indicators.append(f"Contains {len(urls)} external link(s)")

    if sender and "@" not in str(sender):
        indicators.append("Possible spoofed sender address")

    score = len(indicators)
    risk  = "LOW" if score == 0 else "MEDIUM" if score <= 2 else "HIGH"
    return risk, indicators

# ── ML prediction ─────────────────────────────────────────────────────────────
def _ml_predict(sender, subject, body):
    _load_model()
    text            = f"{subject} {body}"
    text_features   = _vectorizer.transform([text])
    sender_has_at   = 1 if "@" in str(sender) else 0
    sender_feature  = sp.csr_matrix([[sender_has_at]])
    X               = sp.hstack([text_features, sender_feature])
    pred            = _model.predict(X)[0]
    proba           = _model.predict_proba(X)[0]
    label_map       = {0: "LOW", 1: "MEDIUM", 2: "HIGH"}
    return label_map[pred], proba

# ── Hybrid analyzer (main entry point) ───────────────────────────────────────
def analyze_email_hybrid(sender: str, subject: str, body: str) -> dict:
    """
    Run both rule engine and ML model on an email.
    Returns the higher risk label with full explanation.
    
    Usage:
        result = analyze_email_hybrid(
            sender="noreply@bank.com",
            subject="Urgent: verify your identity",
            body="Click the link to update payment method"
        )
    """
    # Step 1: Rule engine
    rule_label, indicators = _rule_analyze(sender, subject, body)

    # Step 2: ML model
    ml_label, ml_proba = _ml_predict(sender, subject, body)

    # Step 3: Combine — take the higher risk
    final_label = higher_risk(rule_label, ml_label)

    # Step 4: Confidence — HIGH if both agree, REVIEW if they differ
    confidence = "HIGH" if rule_label == ml_label else "REVIEW"

    return {
        "final_label":   final_label,
        "rule_label":    rule_label,
        "ml_label":      ml_label,
        "confidence":    confidence,
        "indicators":    indicators,
        "ml_probability": {
            "LOW":    round(float(ml_proba[0]), 4),
            "MEDIUM": round(float(ml_proba[1]), 4),
            "HIGH":   round(float(ml_proba[2]), 4),
        }
    }
