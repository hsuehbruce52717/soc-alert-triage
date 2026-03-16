def map_severity(rule_level):
    # Convert Wazuh rule level (0-15) into SOC severity categories.
    
    if rule_level is None:
        return "Unknown"
    if rule_level >= 13:
        return "Critical"
    elif rule_level >= 10:
        return "High"
    elif rule_level >= 7:
        return "Medium"
    elif rule_level >= 4:
        return "Low"
    else:
        return "Informational"