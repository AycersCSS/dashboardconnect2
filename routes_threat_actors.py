from flask import Blueprint, jsonify

from wazuh_auth import _get_request_context

bp = Blueprint("threat_actors", __name__)


@bp.route("/threat-actors", methods=["GET"])
def get_threat_actors():
    _, _, err = _get_request_context()
    if err:
        return jsonify(err[0]), err[1]

    return jsonify({"actors": []}), 200
