import json
from models import get_db


def list_tenants():
    conn = get_db()
    rows = conn.execute("SELECT tenant_id FROM customers").fetchall()
    conn.close()
    return [row["tenant_id"] for row in rows]


def check_tenant_available(name):
    conn = get_db()
    row = conn.execute(
        "SELECT 1 FROM customers WHERE tenant_id = ?", (name,)
    ).fetchone()
    conn.close()
    return row is None


def resolve_groups(tenant_id):
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
