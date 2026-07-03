import time
from collections import OrderedDict

import requests
from flask import Blueprint, jsonify, request

from wazuh_auth import (
    WAZUH_API_URL,
    WAZUH_SSL_VERIFY,
    _get_request_context,
    clear_wazuh_token,
)

bp = Blueprint("vulnerabilities", __name__)

VULN_CACHE_TTL = 60
VULN_CACHE_MAX = 200


class _VulnCache:
    def __init__(self):
        self._store: OrderedDict[str, tuple[float, dict]] = OrderedDict()

    def get(self, key):
        if key not in self._store:
            return None
        self._store.move_to_end(key)
        return self._store[key]

    def put(self, key, value):
        self._store[key] = value
        self._store.move_to_end(key)
        if len(self._store) > VULN_CACHE_MAX:
            self._store.popitem(last=False)

    def expire(self):
        now = time.time()
        stale = [k for k, (ts, _) in self._store.items() if (now - ts) >= VULN_CACHE_TTL]
        for k in stale:
            del self._store[k]


_vuln_cache = _VulnCache()


def _vuln_cache_key(groups, params):
    group_part = ",".join(sorted(groups)) if groups else ""
    param_part = "&".join(sorted(f"{k}={v}" for k, v in params.items()))
    return f"{group_part}|{param_part}"


def _strip_vulnerability(item):
    pkg = item.get("package") or {}
    return {
        "cve": item.get("cve") or item.get("name"),
        "title": item.get("title"),
        "package": pkg.get("name") if isinstance(pkg, dict) else pkg,
        "version": pkg.get("version") if isinstance(pkg, dict) else None,
        "severity": item.get("severity"),
        "cvss": item.get("cvss3_score") or item.get("cvss2_score"),
        "agentCount": item.get("agent_count"),
        "fixedVersion": item.get("fixed_version"),
        "publishedAt": item.get("published"),
    }


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

    _vuln_cache.expire()
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
        raw_items = data.get("data", {}).get("affected_items", [])
        stripped = [_strip_vulnerability(item) for item in raw_items]
        result = {"data": {"affected_items": stripped, "total_affected_items": data.get("data", {}).get("total_affected_items", len(stripped))}}
        _vuln_cache.put(cache_key, (now, result))
        return jsonify(result), 200
    except requests.HTTPError as e:
        if resp.status_code == 401:
            clear_wazuh_token()
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 502
