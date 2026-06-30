import requests
from flask import Blueprint, jsonify, request

from wazuh_auth import (
    WAZUH_API_URL,
    WAZUH_SSL_VERIFY,
    _get_request_context,
    clear_wazuh_token,
)

bp = Blueprint("fim", __name__)


@bp.route("/fim", methods=["GET"])
def list_fim_events():
    groups, wazuh_token, err = _get_request_context()
    if err:
        return jsonify(err[0]), err[1]

    params = {}
    for key in ("limit", "offset", "agent_id", "path", "action"):
        val = request.args.get(key)
        if val is not None:
            params[key] = val

    query_parts = []
    if groups:
        query_parts.append("agent.groups=" + ",".join(groups))
    agent_id = request.args.get("agent_id")
    if agent_id:
        query_parts.append(f"agent.id={agent_id}")

    if query_parts:
        params["q"] = ";".join(query_parts)

    try:
        resp = requests.get(
            f"{WAZUH_API_URL}/experimental/syscheck",
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
