import json
from models import get_db


def list_tenants():
    """Return all registered tenant IDs.

    Returns:
        list[str]: Every tenant_id from the customers table.
    """
    conn = get_db()
    rows = conn.execute("SELECT tenant_id FROM customers").fetchall()
    conn.close()
    return [row["tenant_id"] for row in rows]


def check_tenant_available(name):
    """Check whether a tenant ID is available (not taken).

    Returns:
        bool: True if the name is not registered, False otherwise.
    """
    conn = get_db()
    row = conn.execute(
        "SELECT 1 FROM customers WHERE tenant_id = ?", (name,)
    ).fetchone()
    conn.close()
    return row is None


def resolve_groups(tenant_id):
    """Look up the Wazuh group names mapped to a tenant.

    Args:
        tenant_id (str): The tenant identifier.

    Returns:
        list[str] | None: The Wazuh groups for this tenant, or None if
        the tenant doesn't exist or tenant_id is falsy.
    """
    if not tenant_id:
        return None
    conn = get_db()
    row = conn.execute(
        "SELECT wazuh_groups FROM customers WHERE tenant_id = ?", (tenant_id,)
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return json.loads(row["wazuh_groups"])
