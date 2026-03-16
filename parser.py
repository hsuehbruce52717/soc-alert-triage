import json
from datetime import datetime

def load_alerts(file_path):
    alerts= []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                alerts.append(json.loads(line))
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
    except json.JSONDecodeError:
        print("Error: Could not decode JSON.")
    return alerts

def extract_relevant_fields(alert):
    timestamp_str = alert.get("timestamp")

    try:
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")
    except Exception:
        timestamp = None


    return {
        "timestamp": timestamp,
        "rule_id": alert.get("rule", {}).get("id"),
        "rule_level": alert.get("rule", {}).get("level"),
        "description": alert.get("rule", {}).get("description"),
        "rule_groups": alert.get("rule", {}).get("groups", []),
        "agent_name": alert.get("agent", {}).get("name"),
        "srcip": alert.get("data", {}).get("srcip")
    }

