import streamlit as st
import requests
import json
from datetime import datetime

# ────────────────────────────────────────────────
#   CONFIG
# ────────────────────────────────────────────────
st.set_page_config(
    page_title="RiskPredict AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_BASE = "http://127.0.0.1:8000/ingest"

# Risk visualization mapping
RISK_STYLES = {
    "LOW":    {"emoji": "🟢", "color": "#22c55e", "label": "Low Risk",    "bg": "rgba(34, 197, 94, 0.12)"},
    "MEDIUM": {"emoji": "🟡", "color": "#eab308", "label": "Medium Risk", "bg": "rgba(234, 179, 8,   0.12)"},
    "HIGH":   {"emoji": "🔴", "color": "#ef4444", "label": "High Risk",   "bg": "rgba(239, 68,  68,  0.12)"},
    "UNKNOWN": {"emoji": "⚪", "color": "#6b7280", "label": "Unknown",     "bg": "rgba(107,114,128,0.08)"},
}

def get_risk_display(risk: str):
    risk = risk.upper()
    style = RISK_STYLES.get(risk, RISK_STYLES["UNKNOWN"])
    return (
        f"**{style['emoji']} {style['label']}**",
        style["color"],
        style["bg"]
    )

# ────────────────────────────────────────────────
#   SIDEBAR
# ────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ RiskPredict AI")

    st.markdown("**Analyze emails, URLs & logs in real-time**")

    st.divider()

    api_status = st.status("Backend API", state="running", expanded=False)
    try:
        resp = requests.get(API_BASE.replace("/ingest", "/health"), timeout=2)
        if resp.ok:
            api_status.update(label="Backend API • Connected", state="complete")
        else:
            api_status.update(label=f"Backend API • Error {resp.status_code}", state="error")
    except:
        api_status.update(label="Backend API • Unreachable", state="error")

    st.divider()

    with st.expander("Risk Legend", expanded=True):
        for level, style in RISK_STYLES.items():
            st.markdown(
                f"<span style='background:{style['bg']}; color:{style['color']}; "
                f"padding:4px 10px; border-radius:6px; font-weight:bold;'>"
                f"{style['emoji']} {style['label']}</span>",
                unsafe_allow_html=True
            )

# ────────────────────────────────────────────────
#   HEADER
# ────────────────────────────────────────────────
st.title("Real-Time Threat Detection Dashboard")
st.markdown("Submit suspicious content for instant risk scoring and threat insights.")

tab_email, tab_url, tab_log = st.tabs([
    "📧  Email Analysis",
    "🔗  URL Analysis",
    "🗂️  Log / Event Analysis"
])

# ────────────────────────────────────────────────
#   Reusable analysis function
# ────────────────────────────────────────────────
def run_analysis(endpoint: str, data: dict, success_msg: str, loading_msg: str):
    if not any(data.values()):  # very basic check — improve per tab if needed
        st.error("Please fill in at least one field.")
        return

    with st.spinner(loading_msg):
        try:
            r = requests.post(f"{API_BASE}/{endpoint}", json=data, timeout=12)
            r.raise_for_status()
            result = r.json()

            risk_score = result.get("risk_score", "UNKNOWN").upper()

            title, color, bg = get_risk_display(risk_score)

            # Main result card
            st.markdown(
                f"<div style='padding:16px; border-radius:8px; background:{bg}; border:1px solid {color}40;'>"
                f"<h3 style='margin:0; color:{color};'>{title}</h3>"
                f"<div style='margin-top:8px; font-size:0.95em; opacity:0.9;'>"
                f"Confidence: {result.get('confidence', '—')}% • "
                f"Detected: {', '.join(result.get('threats_detected', ['None']))}</div>"
                f"</div>",
                unsafe_allow_html=True
            )

            st.success(success_msg)

            with st.expander("🔍 Full Analysis Report", expanded=False):
                st.json(result)

        except requests.exceptions.RequestException as e:
            st.error(f"Backend communication error\n{str(e)}")
            if hasattr(e.response, 'text'):
                with st.expander("Server response"):
                    st.code(e.response.text)

# ────────────────────────────────────────────────
#   EMAIL TAB
# ────────────────────────────────────────────────
with tab_email:
    st.subheader("Analyze Suspicious Email")

    col1, col2 = st.columns([2, 3])

    with col1:
        sender = st.text_input("Sender", placeholder="alerts@paypal-secure.com", help="Full email address")
        subject = st.text_input("Subject", placeholder="Your account has been limited!")

    with col2:
        body = st.text_area("Email Body", height=180, placeholder="Dear user, we detected unusual activity...")

    if st.button("🚀 Analyze Email", type="primary", use_container_width=True):
        run_analysis(
            "email",
            {"type": "email", "sender": sender, "subject": subject, "body": body},
            "Email analysis complete.",
            "Scanning email for phishing & malicious patterns…"
        )

# ────────────────────────────────────────────────
#   URL TAB
# ────────────────────────────────────────────────
with tab_url:
    st.subheader("Analyze Suspicious URL")

    url = st.text_input("URL", placeholder="https://suspicious-login[.]net/update", help="Include http/https")

    if st.button("🚀 Analyze URL", type="primary", use_container_width=True):
        run_analysis(
            "url",
            {"type": "url", "url": url},
            "URL reputation & threat check complete.",
            "Checking domain, reputation, redirects and payloads…"
        )

# ────────────────────────────────────────────────
#   LOG TAB
# ────────────────────────────────────────────────
with tab_log:
    st.subheader("Analyze System / Audit Log Event")

    col1, col2, col3 = st.columns(3)

    with col1:
        timestamp = st.text_input("Timestamp", placeholder="2026-01-23 16:45:12")
    with col2:
        user = st.text_input("User", placeholder="admin / john.doe@corp.com")
    with col3:
        event = st.text_input("Event", placeholder="Failed login attempt x5")

    if st.button("🚀 Analyze Log Event", type="primary", use_container_width=True):
        run_analysis(
            "log",
            {"type": "log", "timestamp": timestamp, "user": user, "event": event},
            "Log event threat scoring complete.",
            "Evaluating anomalous behavior…"
        )

# Footer / hint
st.markdown("---")
st.caption("RiskPredict AI — Defending the future, one prediction at a time")