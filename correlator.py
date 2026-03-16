from collections import defaultdict
from datetime import timedelta

def detect_brute_force(alerts, threshold=5, windows_minutes=5):
    # Detect brute force attacks: If an IP has >= threshold failed logins within windows_minutes.

    failed_logins = defaultdict(list)

    for alert in alerts:
        description = alert.get("description", "")
        srcip = alert.get("srcip")
        timestamp = alert.get("timestamp")

        if not timestamp or not srcip:
            continue
        
        # Identify failed login alerts
        groups = alert.get("rule_groups", [])
        if "authentication_failures" in groups:
            failed_logins[srcip].append(timestamp)

    brute_force_ips = set()

    for ip, timestamps in failed_logins.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            count = 1
            for j in range(i + 1, len(timestamps)):
                if  timestamps[j] - timestamps[i] <= timedelta(minutes=windows_minutes):
                    count += 1
                else:
                    break
            if count >= threshold:
                brute_force_ips.add(ip)
                break
    return brute_force_ips # Return set of IPs

