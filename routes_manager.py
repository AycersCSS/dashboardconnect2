import os

import requests
from flask import Blueprint, jsonify

from wazuh_auth import (
    WAZUH_API_URL,
    WAZUH_INDEXER_URL,
    WAZUH_SSL_VERIFY,
    _get_request_context,
    clear_wazuh_token,
)

bp = Blueprint("manager", __name__)


@bp.route("/manager", methods=["GET"])
def get_manager_status():
    """Combine /manager/status, /cluster/healthcheck, and indexer info."""
    _, wazuh_token, err = _get_request_context()
    if err:
        return jsonify(err[0]), err[1]

    headers = {"Authorization": f"Bearer {wazuh_token}"}

    try:
        mgmt_resp = requests.get(
            f"{WAZUH_API_URL}/manager/status",
            headers=headers,
            verify=WAZUH_SSL_VERIFY,
            timeout=30,
        )
        mgmt_resp.raise_for_status()
        mgmt_data = mgmt_resp.json()
    except requests.HTTPError as e:
        if mgmt_resp.status_code == 401:
            clear_wazuh_token()
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 502

    try:
        cluster_resp = requests.get(
            f"{WAZUH_API_URL}/cluster/healthcheck",
            headers=headers,
            verify=WAZUH_SSL_VERIFY,
            timeout=30,
        )
        cluster_resp.raise_for_status()
        cluster_data = cluster_resp.json()
    except requests.HTTPError as e:
        if cluster_resp.status_code == 401:
            clear_wazuh_token()
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 502

    indexer_info = {}
    if WAZUH_INDEXER_URL:
        username = os.environ.get("WAZUH_API_USERNAME", "")
        password = os.environ.get("WAZUH_API_PASSWORD", "")
        try:
            idx_resp = requests.get(
                WAZUH_INDEXER_URL,
                auth=(username, password),
                verify=WAZUH_SSL_VERIFY,
                timeout=10,
            )
            idx_resp.raise_for_status()
            idx_data = idx_resp.json()
            indexer_info = {
                "name": idx_data.get("cluster_name", ""),
                "version": idx_data.get("version", {}).get("number", ""),
            }
        except Exception:
            indexer_info = {"name": None, "version": None}

    manager_status = mgmt_data.get("data", {}).get("affected_items", [{}])[0] if mgmt_data.get("data", {}).get("affected_items") else {}

    cluster_nodes = cluster_data.get("data", {}).get("affected_items", [])
    worker_nodes = [n for n in cluster_nodes if n.get("info", {}).get("type") == "worker"]
    workers = {
        "total": len(worker_nodes),
        "active": sum(1 for n in worker_nodes if n.get("info", {}).get("n_active_agents", 0) > 0),
    }

    return jsonify({
        "manager": manager_status,
        "workers": workers,
        "indexer": indexer_info,
        "apiLatencyP95Ms": None,
    }), 200
