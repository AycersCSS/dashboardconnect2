import requests
from flask import jsonify

def login_user(request):
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    auth_url = 'https://mpaf10113c70551d49a2.free.beeceptor.com/security/user/authenticate'

    try:
        # verify=True ensures SSL certificates are validated
        response = requests.post(auth_url, verify=True, auth=(username, password), timeout=5)
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
    except (ValueError, KeyError):
        return jsonify({"error": "Invalid response format"}), 502