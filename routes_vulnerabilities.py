import time

import requests
from flask import Blueprint, jsonify, request

from wazuh_auth import (
    WAZUH_API_URL,
    WAZUH_SSL_VERIFY,
    _get_request_context,
    clear_wazuh_token,
)

bp = Blueprint("vulnerabilities", __name__)

_vuln_cache: dict[str, tuple[float, dict]] = {}
VULN_CACHE_TTL = 60


def _vuln_cache_key(groups, params):
    group_part = ",".join(sorted(groups)) if groups else ""
    param_part = "&".join(sorted(f"{k}={v}" for k, v in params.items()))
    return f"{group_part}|{param_part}"


@bp.route("/vulnerabilities", methods=["GET"])
def list_vulnerabilities():
    groups, wazuh_token, err = _get_request_context()
    if err:
        return jsonify(err[0]), err[1]

    params = {}
    for key in ("limit", "offset", "severity"):
        val = request.args.get(key)
        if val is not None:
            params[key] = val

    if groups:
        params["q"] = "agent.groups=" + ",".join(groups)

    cache_key = _vuln_cache_key(groups, params)
    now = time.time()
    cached = _vuln_cache.get(cache_key)
    if cached and (now - cached[0]) < VULN_CACHE_TTL:
        return jsonify(cached[1]), 200

    try:
        resp = requests.get(
            f"{WAZUH_API_URL}/vulnerability",
            params=params,
            headers={"Authorization": f"Bearer {wazuh_token}"},
            verify=WAZUH_SSL_VERIFY,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        _vuln_cache[cache_key] = (now, data)
        return jsonify(data), 200
    except requests.HTTPError as e:
        if resp.status_code == 401:
            clear_wazuh_token()
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 502
