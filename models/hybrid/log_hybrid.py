"""
RiskPredict AI — Log Events Hybrid Analyzer
Combines your existing rule engine with the trained ML model.
"""

import os
import re
import pickle

# ── Load model once at startup ────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "log_model.pkl")
META_PATH  = os.path.join(BASE_DIR, "log_features.pkl")

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

# ── Suspicious keywords (matches your rule engine exactly) ───────────────────
SUSPICIOUS_KEYWORDS = [
    "unauthorized", "failed login", "privilege escalation", "escalation",
    "sudo", "root access", "multiple failed", "malicious", "attack",
    "breach", "suspicious", "login attempt", "connection refused", "denied"
]

# ── Feature extractors ────────────────────────────────────────────────────────
def _is_privileged(user: str) -> bool:
    return user.strip().lower() in ["root", "admin"]

def _keyword_match_count(text: str) -> int:
    return sum(1 for w in SUSPICIOUS_KEYWORDS if w in text.lower())

def _extract_ips(text: str) -> list:
    return list(set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)))

def _is_external(ip: str) -> bool:
    return not (
        ip.startswith("192.168.") or
        ip.startswith("10.")      or
        ip.startswith("127.")
    )

def _compute_indicators(user: str, event: str, ip: str = "") -> int:
    text  = f"{user} {event}".lower()
    if ip and ip != "0.0.0.0":
        text += f" {ip}"
    count = 0
    if _is_privileged(user) and any(w in text for w in ["failed", "unauthorized", "escalation"]):
        count += 1
    count += _keyword_match_count(text)
    for ip_found in _extract_ips(text):
        count += 1
        if _is_external(ip_found):
            count += 1
    return count

def _extract_features(user: str, event: str, ip: str) -> dict:
    ind_count = _compute_indicators(user, event, ip)
    all_ips   = _extract_ips(f"{user} {event} {ip}")
    return {
        "is_privileged_user":  int(_is_privileged(user)),
        "keyword_match_count": _keyword_match_count(f"{user} {event} {ip}"),
        "has_ip":              int(bool(all_ips)),
        "is_external_ip":      int(any(_is_external(i) for i in all_ips)),
        "indicator_count":     ind_count,
        "risk_score":          round(min(ind_count * 0.25, 1.0), 2),
    }

# ── Rule engine (your existing logic) ────────────────────────────────────────
def _rule_analyze(user: str, event: str, ip: str) -> tuple:
    indicators = []
    text       = f"{user} {event} {ip}".lower()

    if _is_privileged(user):
        if any(w in text for w in ["failed", "unauthorized", "escalation"]):
            indicators.append("Suspicious activity under privileged account")

    for word in SUSPICIOUS_KEYWORDS:
        if word in text:
            indicators.append(f"Found keyword: {word}")

    ips = _extract_ips(text)
    for ip_found in ips:
        indicators.append(f"IP detected: {ip_found}")
        if _is_external(ip_found):
            indicators.append(f"External IP detected: {ip_found}")

    score     = min(len(indicators) * 0.25, 1.0)
    rule_label = "LOW" if score == 0 else "MEDIUM" if score <= 0.50 else "HIGH"
    return rule_label, indicators, round(score, 2)

# ── ML prediction ─────────────────────────────────────────────────────────────
def _ml_predict(user: str, event: str, ip: str) -> tuple:
    _load_model()
    features = _extract_features(user, event, ip)
    X        = [[features[col] for col in _feature_cols]]
    pred     = _model.predict(X)[0]
    proba    = _model.predict_proba(X)[0]
    label_map = {0: "LOW", 1: "MEDIUM", 2: "HIGH"}
    return label_map[pred], proba

# ── Hybrid analyzer (main entry point) ───────────────────────────────────────
def analyze_log_hybrid(user: str, event: str, ip: str = "0.0.0.0",
                        timestamp: str = "") -> dict:
    """
    Run both rule engine and ML model on a log event.
    Returns the higher risk label with full explanation.

    Usage:
        result = analyze_log_hybrid(
            user="root",
            event="Unauthorized failed login attempt",
            ip="185.220.101.45",
            timestamp="2025-03-07 14:22:01"
        )
    """
    rule_label, indicators, rule_score = _rule_analyze(user, event, ip)
    ml_label, ml_proba                 = _ml_predict(user, event, ip)
    final_label                        = higher_risk(rule_label, ml_label)
    confidence                         = "HIGH" if rule_label == ml_label else "REVIEW"

    return {
        "final_label":    final_label,
        "rule_label":     rule_label,
        "ml_label":       ml_label,
        "rule_score":     rule_score,
        "confidence":     confidence,
        "indicators":     indicators,
        "log_features":   _extract_features(user, event, ip),
        "ml_probability": {
            "LOW":    round(float(ml_proba[0]), 4),
            "MEDIUM": round(float(ml_proba[1]), 4),
            "HIGH":   round(float(ml_proba[2]), 4),
        }
    }
