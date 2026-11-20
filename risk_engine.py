def calculate_risk(events):
    total =0
    for event in events:
        total = total + event["risk_points"]

    score = min(total, 100)

    if score >= 75:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    elif score > 0:
        severity = "LOW"
    else:
        severity = "INFO"

    return score, severity