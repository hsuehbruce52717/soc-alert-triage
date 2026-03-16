from parser import load_alerts, extract_relevant_fields
from scorer import map_severity
from classifier import classify_threat
from attack_mapping import map_to_mitre
from report_generator import generate_report
from correlator import detect_brute_force

alerts = load_alerts("sample_alerts.json")
triaged_alerts = []
parsed_alerts = [extract_relevant_fields(alert) for alert in alerts]

# Detect brute force IPs
brute_force_ips = detect_brute_force(parsed_alerts)

for parsed in parsed_alerts:
    
    severity = map_severity(parsed.get("rule_level"))
    threat_type = classify_threat(parsed.get("description"))
    mitre_id = map_to_mitre(threat_type)

    # Escalate severity if brute force detected
    if parsed.get("srcip") in brute_force_ips:
        severity = "Critical"
        parsed["correlation_tag"] = "Brute Force Pattern Detected"
    else:
        parsed["correlation_tag"] = "None"
        
    parsed["severity"] = severity
    parsed["threat_type"] = threat_type
    parsed["mitre_technique"] = mitre_id

    triaged_alerts.append(parsed)

generate_report(triaged_alerts)

print("SOC Triage Report Generated Successfully.")
