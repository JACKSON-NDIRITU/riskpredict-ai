def analyze_log(log):
    indicators = []
    text = f"{log.timestamp} {log.user} {log.event}".lower()

    suspicious_keywords = [
        "unauthorized",
        "failed login",
        "privilege escalation",
        "escalation",
        "sudo",
        "root access",
        "multiple failed",
        "malicious",
        "attack",
        "breach",
        "suspicious",
        "login attempt",
        "connection refused",
        "denied"
    ]

    # Flag when user is root but event contains strange or failed behavior
    if log.user.lower() in ["root", "admin"]:
        if "failed" in text or "unauthorized" in text or "escalation" in text:
            indicators.append("Suspicious activity under privileged account")

    # Keyword-based detection
    for word in suspicious_keywords:
        if word in text:
            indicators.append(f"Found keyword: {word}")

    # Detect external IPs
    import re
    ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    ips = re.findall(ip_pattern, text)
    for ip in ips:
        indicators.append(f"IP detected: {ip}")

        # Flag public IPs (not local network)
        if not ip.startswith("192.168.") and not ip.startswith("10.") and not ip.startswith("127."):
            indicators.append(f"External IP detected: {ip}")

    # Risk scoring
    score = len(indicators) * 0.25  # Simple scoring model
    score = min(score, 1.0)

    return {
        "score": score,
        "indicators": indicators
    }
