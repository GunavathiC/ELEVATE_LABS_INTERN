def get_mock_threat_feed():
    return [
        {"name": "192.168.1.105", "type": "Malware", "level": "High", "timestamp": "2025-10-26 13:00:00"},
        {"name": "10.0.0.25", "type": "Phishing", "level": "Medium", "timestamp": "2025-10-26 14:15:00"},
        {"name": "hash123abc", "type": "Botnet", "level": "Critical", "timestamp": "2025-10-26 14:45:00"},
    ]

def get_mock_summary(feed=None):
    if not feed:
        feed = get_mock_threat_feed()
    critical = sum(1 for t in feed if t["level"].lower() == "critical")
    high = sum(1 for t in feed if t["level"].lower() == "high")
    medium = sum(1 for t in feed if t["level"].lower() == "medium")
    low = sum(1 for t in feed if t["level"].lower() == "low")
    return {
        "total_threats": len(feed),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }

GEO_IP_MAP = {
    "192.168.1.105": {"lat": 37.7749, "lng": -122.4194, "label": "San Francisco"},
    "10.0.0.25": {"lat": 51.5074, "lng": -0.1278, "label": "London"},
    "hash123abc": {"lat": 35.6895, "lng": 139.6917, "label": "Tokyo"}
}

def recommendations(summary):
    reccos = []
    if summary["critical"] > 0:
        reccos.append("⚠️ Immediate investigation required: Critical threats detected!")
    if summary["high"] > 0:
        reccos.append("• Review high severity threats for potential targeted attacks.")
    if summary["medium"] > 0 or summary["low"] > 0:
        reccos.append("• Maintain regular oversight of medium/low alerts; update signatures.")
    if summary["total_threats"] == 0:
        reccos.append("✅ Environment appears clean at this time.")
    return reccos

USERS = {"abc": "abc123", "admin": "adminpass"}

PLAYBOOKS = {
    "Malware": [
        "1. Isolate infected system.",
        "2. Scan and remove malware.",
        "3. Reset passwords.",
        "4. Review network logs."
    ],
    "Phishing": [
        "1. Block malicious sender.",
        "2. Warn affected users.",
        "3. Review compromised accounts."
    ],
    "Botnet": [
        "1. Quarantine device.",
        "2. Block C2 IPs/domains.",
        "3. Patch vulnerabilities."
    ],
}

