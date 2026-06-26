import os

import requests


CRITICAL_THRESHOLD = 14
HIGH_THRESHOLD = 12


def get_alerts(wazuh_url, token, limit=100, time_range="7d"):
    """
    Fetch Wazuh alerts and bucket into critical / high / warning.

    Critical = rule.level >= 14, High = 12-13, Warning = 7-11.
    Levels 0-6 are excluded (noise, low-priority notifications).

    Each alert is the full Wazuh object with original fields:
    timestamp, rule.{id,level,description,groups},
    agent.{id,name,ip}, full_log, etc.
    """
    verify_ssl = os.environ.get("WAZUH_SSL_VERIFY", "true").lower() == "true"

    params = {
        "q": "rule.level>6",
        "limit": limit,
        "sort": "-timestamp",
        "time_range": time_range,
    }

    resp = requests.get(
        f"{wazuh_url}/security/alerts",
        params=params,
        headers={"Authorization": f"Bearer {token}"},
        verify=verify_ssl,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    if data.get("error") != 0:
        raise ValueError(f"Wazuh API error: {data.get('message')}")

    alerts = data.get("data", {}).get("affected_items", [])

    categorized = {"critical": [], "high": [], "warning": [], "total": len(alerts)}

    for alert in alerts:
        level = alert.get("rule", {}).get("level", 0)
        if level >= CRITICAL_THRESHOLD:
            categorized["critical"].append(alert)
        elif level >= HIGH_THRESHOLD:
            categorized["high"].append(alert)
        else:
            categorized["warning"].append(alert)

    return categorized
