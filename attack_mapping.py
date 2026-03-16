def map_to_mitre(threat_type):
    #Map threat types to MITRE ATT&CK technique IDs.

    mapping = {
        "Brute Force Attack": "T1110",
        "Malware Infection": "T1204",
        "Reconnaissance": "T1595",
        "Web Application Attack": "T1190",
        "Privilege Escalation": "T1068"
    }

    return mapping.get(threat_type, "Unmapped")