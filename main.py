from dotenv import load_dotenv
load_dotenv()

import os
import datetime

import requests
from flask import Flask, jsonify, request

import alerts
import login
import stats
from models import init_db
import tenants
import customer_auth
import agent

WAZUH_API_URL = os.environ.get("WAZUH_API_URL")
if not WAZUH_API_URL:
    raise RuntimeError(
        "WAZUH_API_URL is not set.\n\n"
        "Create a .env file in the project root with:\n"
        '  WAZUH_API_URL="https://your-wazuh-server:55000"\n\n'
        "For development with self-signed certificates, add:\n"
        '  WAZUH_SSL_VERIFY="false"'
    )

app = Flask(__name__)

# --- Internal Wazuh token cache ---
_wazuh_token = None
_wazuh_token_obtained = None


def _ensure_wazuh_token():
    global _wazuh_token, _wazuh_token_obtained
    now = datetime.datetime.now(datetime.timezone.utc)
    if (
        _wazuh_token
        and _wazuh_token_obtained
        and (now - _wazuh_token_obtained).total_seconds() < 1800
    ):
        return _wazuh_token

    username = os.environ.get("WAZUH_API_USERNAME")
    password = os.environ.get("WAZUH_API_PASSWORD")
    if not username or not password:
        raise RuntimeError("WAZUH_API_USERNAME and WAZUH_API_PASSWORD are not set")

    verify_ssl = os.environ.get("WAZUH_SSL_VERIFY", "true").lower() == "true"
    auth_url = f"{WAZUH_API_URL}/security/user/authenticate"

    try:
        resp = requests.post(
            auth_url, verify=verify_ssl, auth=(username, password), timeout=5
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Wazuh authentication service unavailable: {e}")

    data = resp.json()
    token = data.get("data", {}).get("token")
    if not token:
        raise RuntimeError("Malformed response from Wazuh auth service")

    _wazuh_token = token
    _wazuh_token_obtained = now
    return token


def _resolve_tenant_groups(tenant_id):
    if not tenant_id:
        return None
    groups = tenants.resolve_groups(tenant_id)
    if groups is None:
        print(f"Warning: unknown tenant '{tenant_id}' — no group filter applied")
    return groups


def _get_request_context():
    """Return (groups, wazuh_token, error_response).

    error_response is None on success, or a (body_dict, status_code) tuple.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None, ({"error": "Missing or invalid Authorization header"}, 401)

    raw_token = auth.split(" ", 1)[1]

    payload = customer_auth.decode_token(raw_token)
    if payload:
        tenant_id = payload.get("tenant_id")
        groups = _resolve_tenant_groups(tenant_id)
        try:
            wazuh_token = _ensure_wazuh_token()
        except RuntimeError as e:
            return None, None, ({"error": str(e)}, 503)
        return groups, wazuh_token, None

    # Fallback: treat as a Wazuh JWT
    if raw_token.count(".") != 2:
        return None, None, ({"error": "Invalid token format"}, 401)

    tenant_override = request.args.get("tenant")
    groups = _resolve_tenant_groups(tenant_override)
    return groups, raw_token, None


# --- Existing routes ---

@app.route("/authenticate", methods=["POST"])
def login_user():
    return login.login_user(request=request, wazuh_url=WAZUH_API_URL)


@app.route("/stats/agents", methods=["GET"])
def agent_stats():
    groups, wazuh_token, err = _get_request_context()
    if err:
        return jsonify(err[0]), err[1]

    status = request.args.get("status")
    try:
        count = stats.get_agent_count(WAZUH_API_URL, wazuh_token, status, groups)
        return jsonify({"total_agents": count}), 200
    except (requests.HTTPError, ValueError) as e:
        return jsonify({"error": str(e)}), 502


@app.route("/alerts", methods=["GET"])
def categorized_alerts():
    groups, wazuh_token, err = _get_request_context()
    if err:
        return jsonify(err[0]), err[1]

    limit = request.args.get("limit", default=100, type=int)
    time_range = request.args.get("time_range", default="7d")

    try:
        result = alerts.get_alerts(
            WAZUH_API_URL,
            wazuh_token,
            limit=limit,
            time_range=time_range,
            groups=groups,
        )
        return jsonify(result), 200
    except (requests.HTTPError, ValueError) as e:
        return jsonify({"error": str(e)}), 502


# --- Customer routes ---

@app.route("/customer/register", methods=["POST"])
def register_customer():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    tenant_id = data.get("tenant_id")
    wazuh_groups = data.get("wazuh_groups", [])

    if not username or not password or not tenant_id:
        return jsonify({"error": "username, password, and tenant_id are required"}), 400

    try:
        customer_auth.register(username, password, tenant_id, wazuh_groups)
        return jsonify({"message": "Customer registered"}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 409


@app.route("/customer/login", methods=["POST"])
def login_customer():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    token = customer_auth.login(username, password)
    if token is None:
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"token": token}), 200


@app.route("/tenants", methods=["GET"])
def list_tenants():
    return jsonify({"tenants": tenants.list_tenants()}), 200


@app.route("/tenants/check", methods=["GET"])
def check_tenant():
    name = request.args.get("name")
    if not name:
        return jsonify({"error": "name query parameter is required"}), 400
    available = tenants.check_tenant_available(name)
    return jsonify({"available": available}), 200


@app.route("/agents/<agent_id>", methods=["GET"])
def agent_detail(agent_id):
    groups, wazuh_token, err = _get_request_context()
    if err:
        return jsonify(err[0]), err[1]

    limit = request.args.get("limit", default=100, type=int)
    time_range = request.args.get("time_range", default="7d")

    try:
        details = agent.get_agent_details(
            WAZUH_API_URL, wazuh_token, agent_id, groups
        )
        alerts = agent.get_agent_alerts(
            WAZUH_API_URL, wazuh_token, agent_id, groups, limit, time_range
        )
        return jsonify({"agent": details, "alerts": alerts}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except requests.HTTPError as e:
        return jsonify({"error": str(e)}), 502


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
