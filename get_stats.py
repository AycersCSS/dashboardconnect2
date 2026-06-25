import requests

def get_agent_count(wazuh_url, token, status=None):
    """
    Get the total number of agents from the Wazuh API.

    Args:
        wazuh_url (str): Base URL of the Wazuh API
        token (str): JWT token for authentication
        status (str, optional): Filter agents by status: "active", "disconnected", "pending", or "never_connected". Defaults to None (which would be all agents).

    Returns:
        int: Total number of agents matching the given status, or all agents if no status given.

    Raises:
        requests.HTTPError: If the HTTP request fails.
        ValueError: If the Wazuh API returns an error response.
    """
    
    params = {"limit": 1}
    if status:
        params["status"] = status
    
    resp = requests.get(
        f"{wazuh_url}/agents",
        params=params,
        headers={"Authorization": f"Bearer {token}"},
        verify=False
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("error") != 0:
        raise ValueError(f"Wazuh API error: {data.get('message')}")
    return data["data"]["total_affected_items"]

