import os

import requests


CRITICAL_THRESHOLD = 14
HIGH_THRESHOLD = 12


def get_agent_details(wazuh_url, token, agent_id, groups=None):
    """Fetch details for a single Wazuh agent and verify tenant scope.

    Args:
        wazuh_url (str): Base URL of the Wazuh API.
        token (str): JWT for Wazuh API auth.
        agent_id (str): Wazuh agent ID.
        groups (list[str], optional): Tenant's Wazuh groups. If provided,
            the agent must belong to at least one of them.

    Returns:
        dict: Agent info with the shape:
            {
                "id": str,
                "name": str,
                "os": str | None,          # e.g. "Windows 10.0.19041"
                "version": str | None,     # e.g. "Wazuh v4.7.0"
                "last_seen": str | None,   # ISO timestamp
                "status": str | None,      # e.g. "active"
                "groups": list[str]
            }

    Raises:
        ValueError: If the agent doesn't exist or isn't in the tenant's
            group scope.
        requests.HTTPError: On Wazuh API failure.
    """
    verify_ssl = os.environ.get("WAZUH_SSL_VERIFY", "true").lower() == "true"

    resp = requests.get(
        f"{wazuh_url}/agents/{agent_id}",
        headers={"Authorization": f"Bearer {token}"},
        verify=verify_ssl,
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()

    if data.get("error") != 0:
        raise ValueError(f"Wazuh API error: {data.get('message')}")

    items = data.get("data", {}).get("affected_items", [])
    if not items:
        raise ValueError("Agent not found")

    agent = items[0]

    if groups:
        agent_groups = agent.get("group", [])
        if isinstance(agent_groups, str):
            agent_groups = [agent_groups]
        if not any(g in agent_groups for g in groups):
            raise ValueError("Agent not found in your tenant scope")

    os_info = agent.get("os", {}) or {}
    os_name = os_info.get("name", "")
    os_version = os_info.get("version", "")
    os_str = f"{os_name} {os_version}".strip()

    return {
        "id": agent.get("id"),
        "name": agent.get("name"),
        "os": os_str or None,
        "version": agent.get("version"),
        "last_seen": agent.get("lastKeepAlive"),
        "status": agent.get("status"),
        "groups": agent.get("groups") or [],
    }


def get_agent_alerts(wazuh_url, token, agent_id, groups=None, limit=100, time_range="7d"):
    """Fetch alerts for a specific agent, bucketed by severity.

    Severity buckets: critical (>=14), high (12-13), warning (7-11).
    Levels 0-6 are excluded.

    Args:
        wazuh_url (str): Base URL of the Wazuh API.
        token (str): JWT for Wazuh API auth.
        agent_id (str): Wazuh agent ID to filter alerts for.
        groups (list[str], optional): Tenant's Wazuh groups for
            additional scoping.
        limit (int): Max alerts to return.
        time_range (str): Lookback window (e.g. "7d", "24h").

    Returns:
        dict: Categorized alerts with the shape:
            {
                "critical": list[dict],
                "high": list[dict],
                "warning": list[dict],
                "total": int
            }

    Raises:
        ValueError: On Wazuh API error response.
        requests.HTTPError: On HTTP failure.
    """
    verify_ssl = os.environ.get("WAZUH_SSL_VERIFY", "true").lower() == "true"

    query = f"rule.level>6;agent.id={agent_id}"
    if groups:
        query += ";agent.groups=" + ",".join(groups)

    params = {
        "q": query,
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
