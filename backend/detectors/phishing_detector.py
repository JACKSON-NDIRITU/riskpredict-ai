def analyze_email(email):
    indicators = []

    # Combine email fields into analyzable text
    email_text = f"{email.subject} {email.body}".lower()

    # Suspicious phrases
    scam_phrases = [
        "urgent action required",
        "verify your identity",
        "account suspended",
        "click the link",
        "your package is on hold",
        "update payment method"
    ]

    if any(phrase in email_text for phrase in scam_phrases):
        indicators.append("Scam-like language detected")

    # Financial fraud indicators
    finance_indicators = [
        "wire transfer",
        "gift card",
        "crypto payment",
        "invoice due"
    ]

    if any(f in email_text for f in finance_indicators):
        indicators.append("Potential financial fraud")

    # External links detection
    import re
    urls = re.findall(r"https?://\S+", email_text)
    if urls:
        indicators.append(f"Contains {len(urls)} external link(s)")

    # Spoofed sender patterns (use sender field properly)
    if email.sender and "@" not in email.sender:
        indicators.append("Possible spoofed sender address")

    # Score logic
    score = len(indicators)
    risk = "LOW" if score == 0 else "MEDIUM" if score <= 2 else "HIGH"

    return {
        "score": score,
        "indicators": indicators
    }
