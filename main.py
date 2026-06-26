from dotenv import load_dotenv
load_dotenv()

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
    try:
        count = stats.get_agent_count(WAZUH_API_URL, token, status)
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

    try:
        result = alerts.get_alerts(WAZUH_API_URL, token, limit=limit, time_range=time_range)
        return jsonify(result), 200
    except (requests.HTTPError, ValueError) as e:
        return jsonify({"error": str(e)}), 502


if __name__ == "__main__":
    app.run(debug=True)
