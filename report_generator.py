def generate_report(triaged_alerts, output_file="triage_report.txt"):
    with open(output_file, "w") as f:
        for alert in triaged_alerts:
            f.write(f"""
Timestamp: {alert['timestamp']}
Agent: {alert['agent_name']}
Rule ID: {alert['rule_id']}
Description: {alert['description']}
Severity: {alert['severity']}
Threat Type: {alert['threat_type']}
MITRE Technique: {alert['mitre_technique']}
Source IP: {alert['srcip']}
Correlation Tag: {alert['correlation_tag']}
------------------------------------------------------------
""")