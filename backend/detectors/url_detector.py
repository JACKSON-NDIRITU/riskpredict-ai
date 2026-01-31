import re
from urllib.parse import urlparse

def analyze_url(url):
    indicators = []

    # Extract actual URL string
    url_text = url.url.strip().lower()

    # Length-based suspicion
    if len(url_text) > 75:
        indicators.append("Unusually long URL")

    # IP-based URL detection
    if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url_text):
        indicators.append("IP address used instead of domain")

    # URL shorteners
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]
    if any(s in url_text for s in shorteners):
        indicators.append("URL shortener detected")

    # Suspicious keywords
    suspicious_keywords = [
        "login", "verify", "secure", "account",
        "update", "confirm", "password", "bank"
    ]
    if any(k in url_text for k in suspicious_keywords):
        indicators.append("Suspicious keyword in URL")

    # HTTPS check
    if not url_text.startswith("https://"):
        indicators.append("URL not using HTTPS")

    # Suspicious TLDs
    suspicious_tlds = [".ru", ".cn", ".tk", ".ml", ".ga"]
    parsed = urlparse(url_text)
    if any(parsed.netloc.endswith(tld) for tld in suspicious_tlds):
        indicators.append("Suspicious top-level domain")

    # Scoring
    score = len(indicators)
    risk = "LOW" if score == 0 else "MEDIUM" if score <= 2 else "HIGH"

    return {
        "score": score,
        "indicators": indicators
    }
