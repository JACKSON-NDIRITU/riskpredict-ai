import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from app.auth import verify_api_key
from fastapi import Depends
from fastapi import APIRouter
from app.schemas import EmailInput, URLInput, LogInput
from detectors.phishing_detector import analyze_email
from detectors.url_detector import analyze_url
from detectors.anomaly_detector import analyze_log
from utils.risk_aggregator import aggregate_risk
from models.hybrid.email_hybrid import analyze_email_hybrid
from models.hybrid.url_hybrid import analyze_url_hybrid
from models.hybrid.log_hybrid import analyze_log_hybrid

router = APIRouter(prefix="/ingest")

RISK_TO_SCORE = {"LOW": 0.0, "MEDIUM": 0.5, "HIGH": 0.9}

@router.post("/email", dependencies=[Depends(verify_api_key)])
def ingest_email(email: EmailInput):
    rule_score = analyze_email(email)
    hybrid = analyze_email_hybrid(
        sender=email.sender,
        subject=email.subject,
        body=email.body
    )
    hybrid_score = RISK_TO_SCORE[hybrid["final_label"]]
    final_score = max(rule_score["score"], hybrid_score)
    rule_score["score"] = final_score
    rule_score["ml_label"] = hybrid["ml_label"]
    rule_score["confidence"] = hybrid["confidence"]
    risk = aggregate_risk(rule_score)
    return {"type": "email", "risk_score": risk, "details": rule_score}

@router.post("/url", dependencies=[Depends(verify_api_key)])
def ingest_url(url: URLInput):
    rule_score = analyze_url(url)
    hybrid = analyze_url_hybrid(url=url.url)
    hybrid_score = RISK_TO_SCORE[hybrid["final_label"]]
    final_score = max(rule_score["score"], hybrid_score)
    rule_score["score"] = final_score
    rule_score["ml_label"] = hybrid["ml_label"]
    rule_score["confidence"] = hybrid["confidence"]
    risk = aggregate_risk(rule_score)
    return {"type": "url", "risk_score": risk, "details": rule_score}

@router.post("/log", dependencies=[Depends(verify_api_key)])
def ingest_log(log: LogInput):
    rule_score = analyze_log(log)
    hybrid = analyze_log_hybrid(
        user=log.user,
        event=log.event,
        ip=getattr(log, "ip", "0.0.0.0"),
        timestamp=getattr(log, "timestamp", "")
    )
    hybrid_score = RISK_TO_SCORE[hybrid["final_label"]]
    final_score = max(rule_score["score"], hybrid_score)
    rule_score["score"] = final_score
    rule_score["ml_label"] = hybrid["ml_label"]
    rule_score["confidence"] = hybrid["confidence"]
    risk = aggregate_risk(rule_score)
    return {"type": "log", "risk_score": risk, "details": rule_score}