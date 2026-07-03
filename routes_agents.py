import requests
from flask import Blueprint, jsonify, request

from wazuh_auth import (
    WAZUH_API_URL,
    WAZUH_SSL_VERIFY,
    _get_request_context,
    clear_wazuh_token,
)

bp = Blueprint("agents", __name__)


@bp.route("/agents", methods=["GET"])
def list_agents():
    groups, wazuh_token, err = _get_request_context()
    if err:
        return jsonify(err[0]), err[1]

    params = {}
    for key in ("limit", "offset", "status", "group", "search"):
        val = request.args.get(key)
        if val is not None:
            params[key] = val

    if groups:
        params["q"] = "agent.groups=" + ",".join(groups)

    try:
        resp = requests.get(
            f"{WAZUH_API_URL}/agents",
            params=params,
            headers={"Authorization": f"Bearer {wazuh_token}"},
            verify=WAZUH_SSL_VERIFY,
            timeout=30,
        )
        resp.raise_for_status()
        return jsonify(resp.json()), 200
    except requests.HTTPError as e:
        if resp.status_code == 401:
            clear_wazuh_token()
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@bp.route("/agents/status-count", methods=["GET"])
def agents_status_count():
    groups, wazuh_token, err = _get_request_context()
    if err:
        return jsonify(err[0]), err[1]

    params = {"summary": "true"}
    if groups:
        params["q"] = "agent.groups=" + ",".join(groups)

    try:
        resp = requests.get(
            f"{WAZUH_API_URL}/agents",
            params=params,
            headers={"Authorization": f"Bearer {wazuh_token}"},
            verify=WAZUH_SSL_VERIFY,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        summary = data.get("data", {}).get("summary", {})
        return jsonify({
            "active": summary.get("active", 0),
            "disconnected": summary.get("disconnected", 0),
            "pending": summary.get("pending", 0),
            "never_connected": summary.get("never_connected", 0),
        }), 200
    except requests.HTTPError as e:
        if resp.status_code == 401:
            clear_wazuh_token()
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 502
