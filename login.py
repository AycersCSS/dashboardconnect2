import os

import requests
from flask import jsonify

def login_user(request, wazuh_url):
    """
    Authenticate a user against the Wazuh API and return a JWT token.

    Extracts credentials from the JSON request body and forwards them to the
    Wazuh authentication endpoint, and returns the resulting JWT token

    Args:
        request (flask.Request): The incoming Flask request object. Must
                                 contain a JSON body with "username" and
                                 "password" fields.

    Returns:
        tuple: A Flask (Response, status_code) tuple. Possible responses:

            200 - Authentication successful:
                {"token": "<jwt_token>"}

            400 - Missing credentials:
                {"error": "Missing credentials"}

            401 - Invalid credentials (Wazuh rejected the login):
                {"error": "Invalid credentials"}

            502 - Wazuh returned an unexpected or malformed response:
                {"error": "Malformed response from auth service"}
                {"error": "Invalid response format"}

            503 - Wazuh authentication service is unreachable:
                {"error": "Authentication service unavailable"}

    Raises:
        No exceptions are raised; all errors are caught and returned
        as JSON error responses.
    """

    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    verify_ssl = os.environ.get("WAZUH_SSL_VERIFY", "true").lower() == "true"
    auth_url = f'{wazuh_url}/security/user/authenticate'

    try:
        response = requests.post(auth_url, verify=verify_ssl, auth=(username, password), timeout=5)
    except requests.exceptions.RequestException:
        return jsonify({"error": "Authentication service unavailable"}), 503

    if response.status_code != 200:
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        response_data = response.json()

        token = response_data.get("data", {}).get("token")
        if not token:
            return jsonify({"error": "Malformed response from auth service"}), 502
        
        return jsonify({"token": token}), 200
    except ValueError:
        return jsonify({"error": "Invalid response format"}), 502