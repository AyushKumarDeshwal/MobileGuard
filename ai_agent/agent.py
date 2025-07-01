def analyze_log(log_path):
    import json
    alerts = []
    with open(log_path) as f:
        logs = json.load(f)
    for log in logs:
        msg = log.get("message", "").lower()
        if "sql" in msg or "unauthorized" in msg or "script" in msg:
            alerts.append(f"Suspicious: {msg}")
    return alerts
