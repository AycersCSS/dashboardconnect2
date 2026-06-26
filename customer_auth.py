import json
import os
import sqlite3
import datetime

import bcrypt
import jwt

from models import get_db

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET is not set.\n\n"
        "Add to .env:\n"
        '  JWT_SECRET="your-random-secret-key"'
    )

JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24


def register(username, password, tenant_id, wazuh_groups):
    """Insert a new customer into the database with a bcrypt-hashed password.

    Args:
        username (str): Unique login name.
        password (str): Plain-text password (hashed before storage).
        tenant_id (str): Tenant identifier.
        wazuh_groups (list[str]): Wazuh group names to scope this tenant.

    Raises:
        ValueError: If the username or tenant_id already exists.
    """
    conn = get_db()
    try:
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        conn.execute(
            "INSERT INTO customers (tenant_id, username, password_hash, wazuh_groups) VALUES (?, ?, ?, ?)",
            (tenant_id, username, password_hash, json.dumps(wazuh_groups)),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise ValueError("Username or tenant ID already exists")
    conn.close()


def login(username, password):
    """Authenticate a customer by username/password.

    Args:
        username (str): Customer login name.
        password (str): Plain-text password.

    Returns:
        str | None: A signed JWT (valid 24h) embedding the customer's
        tenant_id, or None if credentials are invalid.
    """
    conn = get_db()
    row = conn.execute(
        "SELECT id, tenant_id, password_hash FROM customers WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    if row is None or not row["password_hash"]:
        return None
    if not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return None
    payload = {
        "sub": str(row["id"]),
        "tenant_id": row["tenant_id"],
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(hours=JWT_EXPIRATION_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token):
    """Decode and validate a customer JWT.

    Args:
        token (str): The JWT string.

    Returns:
        dict | None: The decoded payload (contains tenant_id, sub, exp, iat)
        or None if the token is invalid/expired.
    """
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None
