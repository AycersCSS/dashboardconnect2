import requests
from flask import Blueprint, jsonify, request

from wazuh_auth import (
    WAZUH_API_URL,
    WAZUH_SSL_VERIFY,
    _get_request_context,
    clear_wazuh_token,
)

bp = Blueprint("logs", __name__)


@bp.route("/logs", methods=["GET"])
def get_logs():
    groups, wazuh_token, err = _get_request_context()
    if err:
        return jsonify(err[0]), err[1]

    params = {}
    limit = request.args.get("limit")
    if limit is not None:
        params["limit"] = limit

    try:
        resp = requests.get(
            f"{WAZUH_API_URL}/manager/logs",
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
