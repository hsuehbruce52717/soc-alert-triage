def classify_threat(description):
    #   Classify alert into threat categories based on rule description.
    if not description:
        return "unknown"
    desc = description.lower()
    
    if "host-based anomaly detection event" in desc:
        return "Root Check"
    
    elif "authentication failed" in desc or "failed login" in desc:
            return "Brute Force Attack"

    elif "malware" in desc or "trojan" in desc:
            return "Malware Infection"

    elif "port scan" in desc:
            return "Reconnaissance"

    elif "sql injection" in desc:
            return "Web Application Attack"

    elif "rootkit" in desc:
        return "Privilege Escalation"

    else:
        return "General Security Event"