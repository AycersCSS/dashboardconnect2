import datetime
import os

import requests
from flask import request

import customer_auth
import tenants

WAZUH_API_URL = os.environ.get("WAZUH_API_URL")
if not WAZUH_API_URL:
    raise RuntimeError(
        "WAZUH_API_URL is not set.\n\n"
        "Create a .env file in the project root with:\n"
        '  WAZUH_API_URL="https://your-wazuh-server:55000"\n\n'
        "For development with self-signed certificates, add:\n"
        '  WAZUH_SSL_VERIFY="false"'
    )

WAZUH_SSL_VERIFY = os.environ.get("WAZUH_SSL_VERIFY", "true").lower() == "true"

WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL")
if not WAZUH_INDEXER_URL:
    raise RuntimeError(
        "WAZUH_INDEXER_URL is not set.\n\n"
        "Add to .env:\n"
        '  WAZUH_INDEXER_URL="https://localhost:9200"'
    )

_wazuh_token = None
_wazuh_token_obtained = None


def _ensure_wazuh_token():
    """Get a cached Wazuh service-account JWT, refreshing at most every 30 min."""
    global _wazuh_token, _wazuh_token_obtained
    now = datetime.datetime.now(datetime.timezone.utc)
    if (
        _wazuh_token
        and _wazuh_token_obtained
        and (now - _wazuh_token_obtained).total_seconds() < 1800
    ):
        return _wazuh_token

    username = os.environ.get("WAZUH_API_USERNAME")
    password = os.environ.get("WAZUH_API_PASSWORD")
    if not username or not password:
        raise RuntimeError("WAZUH_API_USERNAME and WAZUH_API_PASSWORD are not set")

    auth_url = f"{WAZUH_API_URL}/security/user/authenticate"

    try:
        resp = requests.post(
            auth_url, verify=WAZUH_SSL_VERIFY, auth=(username, password), timeout=5
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Wazuh authentication service unavailable: {e}")

    data = resp.json()
    token = data.get("data", {}).get("token")
    if not token:
        raise RuntimeError("Malformed response from Wazuh auth service")

    _wazuh_token = token
    _wazuh_token_obtained = now
    return token


def clear_wazuh_token():
    """Force the next call to re-authenticate with Wazuh."""
    global _wazuh_token, _wazuh_token_obtained
    _wazuh_token = None
    _wazuh_token_obtained = None


def _resolve_tenant_groups(tenant_id):
    if not tenant_id:
        return None
    groups = tenants.resolve_groups(tenant_id)
    if groups is None:
        print(f"Warning: unknown tenant '{tenant_id}' — no group filter applied")
    return groups


def _get_request_context():
    """Return (groups, wazuh_token, error_response) from the incoming request.

    Decodes the customer JWT from the Authorization header, resolves the
    tenant's Wazuh groups, and returns a cached Wazuh service-account token.
    On failure, error_response is (body_dict, status_code).
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None, ({"error": "Missing or invalid Authorization header"}, 401)

    raw_token = auth.split(" ", 1)[1]

    payload = customer_auth.decode_token(raw_token)
    if payload:
        tenant_id = payload.get("tenant_id")
        groups = _resolve_tenant_groups(tenant_id)
        try:
            wazuh_token = _ensure_wazuh_token()
        except RuntimeError as e:
            return None, None, ({"error": str(e)}, 503)
        return groups, wazuh_token, None

    if raw_token.count(".") != 2:
        return None, None, ({"error": "Invalid token format"}, 401)

    tenant_override = request.args.get("tenant")
    groups = _resolve_tenant_groups(tenant_override)
    return groups, raw_token, None
