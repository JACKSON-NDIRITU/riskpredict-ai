RiskPredict AI

RiskPredict AI is a real-time cyber threat detection MVP designed to analyze emails, URLs, and system logs for potential security risks.  
The system focuses on explainable detection, providing clear indicators and risk scores rather than black-box predictions.

This project was developed as part of a hackathon and represents a functional, extensible foundation for intelligent cybersecurity systems.


Problem Statement

Organizations and individuals are constantly exposed to cyber threats such as phishing emails, malicious links, and suspicious system activity.  
Many existing solutions are complex, opaque, or inaccessible to smaller teams.

RiskPredict AI addresses this by providing:
- Simple inputs
- Clear risk scoring
- Explainable threat indicators
- A lightweight, modular architecture


Solution Overview

RiskPredict AI provides an end-to-end system that:
- Accepts security-related inputs (email, URL, logs)
- Analyzes them using rule-based detection logic
- Returns a structured risk assessment
- Displays results in an interactive dashboard

The MVP is intentionally rule-based to ensure transparency and reliability, with future plans to integrate machine learning models.

Key Features

Email Threat Analysis
- Detects phishing and scam language
- Identifies financial fraud indicators
- Flags suspicious external links

URL Threat Analysis
- Detects IP-based and suspicious URLs
- Flags non-secure (HTTP) links
- Identifies potentially malicious patterns

Log Anomaly Detection
- Detects privilege escalation attempts
- Identifies suspicious commands and keywords
- Flags external IP activity

Interactive Dashboard
- Built with Streamlit
- Real-time risk analysis
- Clear severity levels: LOW / MEDIUM / HIGH
- Human-readable indicators for every result


System Architecture

- Backend:FastAPI (ASGI-based REST API)
- Frontend:Streamlit dashboard
- Detection Engine: Rule-based analyzers
- Validation: Pydantic schemas
- Communication:JSON over HTTP


Tech Stack

- Python
- FastAPI
- Uvicorn
- Streamlit
- Pydantic
- Requests


How to Run the Project Locally

1. Clone the repository
bash
git clone https://github.com/JACKSON-NDIRITU/riskpredict-ai.git
cd riskpredict-ai

2. Create and activate a virtual environment
python -m venv .venv
	i) Windows
	.venv\Scripts\activate

	ii) Linux\macOS
	source .venv/bin/activate
3. Install dependencies
pip install -r requirements.txt

4.Run the backend API
Open the terminal
cd backend
uvicorn app.main:app --reload

The backend will be available at:
http://127.0.0.1:8000

Health check endpoint:
http://127.0.0.1:8000/health

5. Run the Streamlit dashboard

Open a new terminal window:

cd dashboard
streamlit run streamlit_app.py

The dashboard will open automatically in your browser.

