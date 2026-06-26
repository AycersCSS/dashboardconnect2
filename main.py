from dotenv import load_dotenv
load_dotenv()

import json
import os

import requests
from flask import Flask, jsonify, request

import alerts
import login
import stats

WAZUH_API_URL = os.environ.get("WAZUH_API_URL")
if not WAZUH_API_URL:
    raise RuntimeError(
        "WAZUH_API_URL is not set.\n\n"
        "Create a .env file in the project root with:\n"
        '  WAZUH_API_URL="https://your-wazuh-server:55000"\n\n'
        "For development with self-signed certificates, add:\n"
        '  WAZUH_SSL_VERIFY="false"'
    )

TENANTS_FILE = os.environ.get("TENANTS_FILE", "tenants.json")


def _load_tenants():
    """
    Load tenant-to-group mappings from the JSON file specified by the
    TENANTS_FILE environment variable (defaults to tenants.json).

    Expected format:
        {
          "<tenant_id>": ["<wazuh_group1>", "<wazuh_group2>", ...],
          ...
        }

    Returns the parsed dict, or an empty dict if the file is missing
    or unreadable.
    """
    try:
        with open(TENANTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Warning: could not load tenants file ({e})")
        return {}


def _resolve_tenant_groups(tenant_id):
    """
    Look up the Wazuh agent groups for a given tenant.

    Args:
        tenant_id (str | None): The tenant identifier from the
            request query string. None or empty means "all tenants".

    Returns:
        list[str] | None: The list of Wazuh group names for the
        tenant, or None if no tenant was specified (meaning no
        group filter should be applied). Returns None for unknown
        tenant IDs as well.
    """
    if not tenant_id:
        return None
    tenants = _load_tenants()
    groups = tenants.get(tenant_id)
    if groups is None:
        print(f"Warning: unknown tenant '{tenant_id}' — no group filter applied")
    return groups


app = Flask(__name__)


@app.route("/authenticate", methods=["POST"])
def login_user():
    return login.login_user(request=request, wazuh_url=WAZUH_API_URL)


@app.route("/stats/agents", methods=["GET"])
def agent_stats():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401
    token = auth.split(" ", 1)[1]
    status = request.args.get("status")
    tenant = request.args.get("tenant")
    try:
        groups = _resolve_tenant_groups(tenant)
        count = stats.get_agent_count(WAZUH_API_URL, token, status, groups)
        return jsonify({"total_agents": count}), 200
    except (requests.HTTPError, ValueError) as e:
        return jsonify({"error": str(e)}), 502


@app.route("/alerts", methods=["GET"])
def categorized_alerts():
    """Return { critical, high, warning, total }. Requires Bearer token."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401
    token = auth.split(" ", 1)[1]

    limit = request.args.get("limit", default=100, type=int)
    time_range = request.args.get("time_range", default="7d")
    tenant = request.args.get("tenant")

    try:
        groups = _resolve_tenant_groups(tenant)
        result = alerts.get_alerts(
            WAZUH_API_URL, token, limit=limit, time_range=time_range, groups=groups
        )
        return jsonify(result), 200
    except (requests.HTTPError, ValueError) as e:
        return jsonify({"error": str(e)}), 502


if __name__ == "__main__":
    app.run(debug=True)
