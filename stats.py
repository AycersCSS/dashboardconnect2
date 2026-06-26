import os

import requests


def get_agent_count(wazuh_url, token, status=None, groups=None):
    """
    Get the total number of agents from the Wazuh API.

    Args:
        wazuh_url (str): Base URL of the Wazuh API
        token (str): JWT token for authentication
        status (str, optional): Filter agents by status: "active",
            "disconnected", "pending", or "never_connected".
        groups (list[str], optional): Wazuh agent group names to
            scope the count to. Agents are counted independently per
            group and summed. If an agent belongs to multiple groups
            within the same tenant, it will be counted more than once —
            design group mappings to avoid overlapping groups.

    Returns:
        int: Total number of agents matching the given filters.

    Raises:
        requests.HTTPError: If the HTTP request fails.
        ValueError: If the Wazuh API returns an error response.
    """
    verify_ssl = os.environ.get("WAZUH_SSL_VERIFY", "true").lower() == "true"

    default_params = {"limit": 1}
    if status:
        default_params["status"] = status

    total = 0
    targets = groups or [None]

    for group in targets:
        params = dict(default_params)
        if group:
            params["group"] = group

        resp = requests.get(
            f"{wazuh_url}/agents",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            verify=verify_ssl,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("error") != 0:
            raise ValueError(f"Wazuh API error: {data.get('message')}")
        total += data["data"]["total_affected_items"]

    return total

