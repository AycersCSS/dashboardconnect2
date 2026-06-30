from flask import Blueprint, jsonify

from wazuh_auth import _get_request_context

KNOWN_INTEGRATIONS = [
    "microsoft-365",
    "ninjaone",
    "bitdefender",
    "cyber-essentials",
    "customer-portal",
]

bp = Blueprint("integrations", __name__)


@bp.route("/integrations/<integration_id>", methods=["GET"])
def get_integration(integration_id):
    _, _, err = _get_request_context()
    if err:
        return jsonify(err[0]), err[1]

    if integration_id not in KNOWN_INTEGRATIONS:
        return jsonify({"error": "unsupported_integration"}), 400

    return (
        jsonify({"ok": False, "error": "not_connected", "id": integration_id}),
        503,
    )
