from fastapi import APIRouter
from app.schemas import EmailInput, URLInput, LogInput
from detectors.phishing_detector import analyze_email
from detectors.url_detector import analyze_url
from detectors.anomaly_detector import analyze_log
from utils.risk_aggregator import aggregate_risk

router = APIRouter(prefix="/ingest")

@router.post("/email")
def ingest_email(email: EmailInput):
    score = analyze_email(email)
    risk = aggregate_risk(score)
    return {"type": "email", "risk_score": risk, "details": score}

@router.post("/url")
def ingest_url(url: URLInput):
    score = analyze_url(url)
    risk = aggregate_risk(score)
    return {"type": "url", "risk_score": risk, "details": score}

@router.post("/log")
def ingest_log(log: LogInput):
        score = analyze_log(log)
        risk = aggregate_risk(score)
        return {"type": "log", "risk_score": risk, "details": score}
