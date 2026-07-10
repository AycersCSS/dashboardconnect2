from dotenv import load_dotenv
load_dotenv()

import os

import requests
from flask import Flask, jsonify, request, redirect, send_from_directory

import alerts
import agent
import login
import stats
from models import init_db
import tenants
import customer_auth
from wazuh_auth import (
    WAZUH_API_URL,
    _get_request_context,
    _ensure_wazuh_token,
    clear_wazuh_token,
)

if not WAZUH_API_URL:
    raise RuntimeError(
        "WAZUH_API_URL is not set.\n\n"
        "Create a .env file in the project root with:\n"
        '  WAZUH_API_URL="https://your-wazuh-server:55000"\n\n'
        "For development with self-signed certificates, add:\n"
        '  WAZUH_SSL_VERIFY="false"'
    )

app = Flask(__name__)

import routes_agents
import routes_compliance
import routes_fim
import routes_integrations
import routes_logs
import routes_manager
import routes_rules
import routes_threat_actors
import routes_vulnerabilities

DASHBOARD_DIR = os.path.join(os.path.dirname(__file__), "dashboard")


@app.route("/dashboard/init", methods=["GET"])
def dashboard_init():
    """Return a fresh Wazuh JWT for the dashboard frontend.

    Called by dashboard JS on page load. Uses the connector's cached
    service-account token so the frontend never sees Wazuh credentials.
    """
    try:
        token = _ensure_wazuh_token()
        return jsonify({"token": token}), 200
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503


@app.route("/")
def root():
    return redirect("/dashboard/")


@app.route("/dashboard/")
@app.route("/dashboard/<path:filename>")
def dashboard_static(filename="index.html"):
    return send_from_directory(DASHBOARD_DIR, filename)


app.register_blueprint(routes_agents.bp)
app.register_blueprint(routes_compliance.bp)
app.register_blueprint(routes_fim.bp)
app.register_blueprint(routes_integrations.bp)
app.register_blueprint(routes_logs.bp)
app.register_blueprint(routes_manager.bp)
app.register_blueprint(routes_rules.bp)
app.register_blueprint(routes_threat_actors.bp)
app.register_blueprint(routes_vulnerabilities.bp)


@app.route("/authenticate", methods=["POST"])
def login_user():
    """Authenticate against Wazuh and return a JWT.

    Request body: {"username": str, "password": str}
    Response (200): {"token": str}
    Errors: 400, 401, 502, 503
    """
    return login.login_user(request=request, wazuh_url=WAZUH_API_URL)


@app.route("/stats/agents", methods=["GET"])
def agent_stats():
    """Return the total agent count, optionally filtered by status/tenant.

    Query params: status (str), tenant (str)
    Response (200): {"total_agents": int}
    Errors: 401, 502
    """
    groups, wazuh_token, err = _get_request_context()
    if err:
        return jsonify(err[0]), err[1]

    status = request.args.get("status")
    try:
        count = stats.get_agent_count(WAZUH_API_URL, wazuh_token, status, groups)
        return jsonify({"total_agents": count}), 200
    except (requests.HTTPError, ValueError) as e:
        if isinstance(e, requests.HTTPError) and e.response is not None and e.response.status_code == 401:
            clear_wazuh_token()
        return jsonify({"error": str(e)}), 502


@app.route("/alerts", methods=["GET"])
def categorized_alerts():
    """Fetch alerts bucketed by severity (critical/high/warning).

    Query params: limit (int), time_range (str), tenant (str)
    Response (200): {"critical": [...], "high": [...], "warning": [...], "total": int}
    Errors: 401, 502
    """
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
        if isinstance(e, requests.HTTPError) and e.response is not None and e.response.status_code == 401:
            clear_wazuh_token()
        return jsonify({"error": str(e)}), 502


@app.route("/customer/register", methods=["POST"])
def register_customer():
    """Register a new customer account.

    Request body: {"username": str, "password": str, "tenant_id": str, "wazuh_groups": list[str]}
    Response (201): {"message": "Customer registered"}
    Errors: 400 (missing fields), 409 (duplicate)
    """
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
    """Authenticate as a customer and receive a tenant-scoped JWT.

    Request body: {"username": str, "password": str}
    Response (200): {"token": str} (JWT with embedded tenant_id)
    Errors: 400, 401
    """
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
    """List all registered tenant IDs.

    Response (200): {"tenants": list[str]}
    """
    return jsonify({"tenants": tenants.list_tenants()}), 200


@app.route("/tenants/check", methods=["GET"])
def check_tenant():
    """Check if a tenant ID is available.

    Query params: name (str)
    Response (200): {"available": bool}
    Errors: 400 (missing name)
    """
    name = request.args.get("name")
    if not name:
        return jsonify({"error": "name query parameter is required"}), 400
    available = tenants.check_tenant_available(name)
    return jsonify({"available": available}), 200


@app.route("/agents/<agent_id>", methods=["GET"])
def agent_detail(agent_id):
    """Fetch agent details and alerts for a specific agent.

    Path param: agent_id (str)
    Query params: limit (int), time_range (str), tenant (str)
    Response (200): {"agent": {...}, "alerts": {...}}
        agent: {"id", "name", "os", "version", "last_seen", "status", "groups"}
        alerts: {"critical": [...], "high": [...], "warning": [...], "total": int}
    Errors: 401, 404, 502
    """
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
        if e.response is not None and e.response.status_code == 401:
            clear_wazuh_token()
        return jsonify({"error": str(e)}), 502


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
