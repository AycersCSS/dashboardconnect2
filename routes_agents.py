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
        params["group"] = ",".join(groups)

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

    statuses = ["active", "disconnected", "pending", "never_connected"]
    counts = {}

    for status in statuses:
        params = {"limit": 1, "status": status}
        if groups:
            params["group"] = ",".join(groups)
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
            counts[status] = data.get("data", {}).get("total_affected_items", 0)
        except requests.HTTPError as e:
            if resp.status_code == 401:
                clear_wazuh_token()
            return jsonify({"error": str(e)}), 502
        except Exception as e:
            return jsonify({"error": str(e)}), 502

    return jsonify(counts), 200
