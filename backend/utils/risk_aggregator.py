def aggregate_risk(details):
    base = details["score"]

    if base >= 0.7:
        return "HIGH"
    elif base >= 0.4:
        return "MEDIUM"
    else:
        return "LOW"
