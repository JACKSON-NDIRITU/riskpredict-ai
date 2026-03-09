"""
RiskPredict AI — URL Hybrid Analyzer
Combines your existing rule engine with the trained ML model.
"""

import os
import re
import pickle
from urllib.parse import urlparse

# ── Load model once at startup ────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "url_model.pkl")
META_PATH  = os.path.join(BASE_DIR, "url_features.pkl")
_model        = None
_feature_cols = None

def _load_model():
    global _model, _feature_cols
    if _model is None:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        with open(META_PATH, "rb") as f:
            _feature_cols = pickle.load(f)

# ── Risk ordering ─────────────────────────────────────────────────────────────
RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

def higher_risk(a, b):
    return a if RISK_ORDER[a] >= RISK_ORDER[b] else b

# ── Feature extractors ────────────────────────────────────────────────────────
SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"]
SUSP_KEYWORDS = ["login", "verify", "secure", "account", "update", "confirm", "password", "bank"]
SUSP_TLDS = [".ru", ".cn", ".tk", ".ml", ".ga"]

def _extract_features(url: str) -> dict:
    url_lower = url.strip().lower()
    try:
        netloc = urlparse(url_lower).netloc
    except Exception:
        netloc = ""

    return {
        "url_length":               len(url_lower),
        "has_https":                int(url_lower.startswith("https://")),
        "has_ip_address":           int(bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url_lower))),
        "uses_shortener":           int(any(netloc == s or netloc.endswith("." + s) for s in SHORTENERS)),
        "suspicious_keyword_count": sum(k in url_lower for k in SUSP_KEYWORDS),
        "suspicious_tld":           int(any(netloc.endswith(t) for t in SUSP_TLDS)),
        "special_char_count":       sum(url_lower.count(c) for c in ["@", "%", "=", "-", "_"]),
        "subdomain_count":          max(0, len(netloc.split(".")) - 2),
        "digit_count":              sum(c.isdigit() for c in netloc),
    }

# ── Rule engine (your existing logic) ────────────────────────────────────────
def _rule_analyze(url: str) -> tuple:
    indicators = []
    url_lower  = url.strip().lower()

    if len(url_lower) > 75:
        indicators.append("Unusually long URL")
    if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url_lower):
        indicators.append("IP address used instead of domain")

    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]
    if any(s in url_lower for s in shorteners):
        indicators.append("URL shortener detected")
    if any(k in url_lower for k in SUSP_KEYWORDS):
        indicators.append("Suspicious keyword in URL")
    if not url_lower.startswith("https://"):
        indicators.append("URL not using HTTPS")

    try:
        parsed = urlparse(url_lower)
        if any(parsed.netloc.endswith(tld) for tld in SUSP_TLDS):
            indicators.append("Suspicious top-level domain")
    except Exception:
        pass

    score = len(indicators)
    risk  = "LOW" if score == 0 else "MEDIUM" if score <= 2 else "HIGH"
    return risk, indicators

# ── ML prediction ─────────────────────────────────────────────────────────────
def _ml_predict(url: str) -> tuple:
    _load_model()
    features = _extract_features(url)
    X        = [[features[col] for col in _feature_cols]]
    pred     = _model.predict(X)[0]
    proba    = _model.predict_proba(X)[0]
    label_map = {0: "LOW", 1: "MEDIUM", 2: "HIGH"}
    return label_map[pred], proba

# ── Hybrid analyzer (main entry point) ───────────────────────────────────────
def analyze_url_hybrid(url: str) -> dict:
    """
    Run both rule engine and ML model on a URL.
    Returns the higher risk label with full explanation.

    Usage:
        result = analyze_url_hybrid("http://secure-login.bank-verify.ru/confirm")
    """
    rule_label, indicators = _rule_analyze(url)
    ml_label, ml_proba     = _ml_predict(url)
    final_label            = higher_risk(rule_label, ml_label)
    confidence             = "HIGH" if rule_label == ml_label else "REVIEW"

    return {
        "final_label":    final_label,
        "rule_label":     rule_label,
        "ml_label":       ml_label,
        "confidence":     confidence,
        "indicators":     indicators,
        "url_features":   _extract_features(url),
        "ml_probability": {
            "LOW":    round(float(ml_proba[0]), 4),
            "MEDIUM": round(float(ml_proba[1]), 4),
            "HIGH":   round(float(ml_proba[2]), 4),
        }
    }
