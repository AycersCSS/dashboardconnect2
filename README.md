# MergeIT-WazuhConnector

Lightweight Flask middleware that proxies authentication, agent stats, and categorized alerts from the [Wazuh](https://wazuh.com) API.

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Create a `.env` file in the project root:
   ```
   WAZUH_API_URL="https://your-wazuh-server:55000"
   WAZUH_SSL_VERIFY="false"
   WAZUH_API_USERNAME="wazuh-service-account"
   WAZUH_API_PASSWORD="wazuh-service-account-password"
   JWT_SECRET="generate-a-random-secret"
   ```

3. Initialise the database:
   ```
   python -c "from models import init_db; init_db()"
   ```

   The database (`connector.db` by default) stores customer accounts and tenant-to-group mappings. Tenants are managed through the API — see the **Customer API** section below.

4. Run the server:
   ```
   python main.py
   ```

   Runs on `http://localhost:5000` with Flask's debug mode enabled.

## API

Data endpoints accept either a **customer JWT** (from `/customer/login`) scoped automatically to the customer's tenant, or a **Wazuh JWT** (from `/authenticate`) for admin use with optional `?tenant=` override.

### `POST /authenticate`

Authenticate against the Wazuh API and receive a JWT token.

**Request:**
```json
{ "username": "wazuh-user", "password": "wazuh-pass" }
```

**Response (200):**
```json
{ "token": "eyJhbGciOiJFUzM4NCJ9..." }
```

**Errors:** `400` (missing credentials), `401` (invalid credentials), `502` (malformed response), `503` (unreachable).

---

### `GET /stats/agents`

Return the total count of Wazuh agents, optionally filtered by status and/or tenant.

| Query param | Type | Default | Description |
|---|---|---|---|
| `status` | string | — | Filter by agent status: `active`, `disconnected`, `pending`, `never_connected` |
| `tenant` | string | — | Tenant ID — scopes count to agents in the mapped Wazuh groups (only applies to Wazuh JWTs; customer JWTs are scoped automatically) |

**Examples:**

```
GET /stats/agents
→ { "total_agents": 150 }

GET /stats/agents?status=active
→ { "total_agents": 134 }

GET /stats/agents?tenant=acme-corp
→ { "total_agents": 42 }

GET /stats/agents?tenant=acme-corp&status=active
→ { "total_agents": 38 }
```

**Errors:** `401` (missing/invalid token), `502` (Wazuh API error).

---

### `GET /alerts`

Fetch Wazuh security alerts bucketed by severity.

| Query param | Type | Default | Description |
|---|---|---|---|
| `limit` | int | `100` | Maximum alerts to return |
| `time_range` | string | `7d` | Lookback window (e.g. `24h`, `30d`) |
| `tenant` | string | — | Tenant ID — filters alerts to agents in the mapped Wazuh groups (only applies to Wazuh JWTs; customer JWTs are scoped automatically) |

**Severity buckets:**

| Bucket | Rule level | Example rule |
|---|---|---|
| `critical` | >= 14 | Possible attack, security event |
| `high` | 12 – 13 | Multiple failed logins |
| `warning` | 7 – 11 | Unusual system behaviour |
| *(excluded)* | 0 – 6 | Low-priority notifications, noise |

**Examples:**

```
GET /alerts
→ { "critical": [...], "high": [...], "warning": [...], "total": 50 }

GET /alerts?tenant=globex-inc
→ { "critical": [...], "high": [...], "warning": [...], "total": 12 }

GET /alerts?limit=200&time_range=30d&tenant=acme-corp
→ { "critical": [...], "high": [...], "warning": [...], "total": 88 }
```

**Errors:** `401` (missing/invalid token), `502` (Wazuh API error).

---

### `GET /agents/<agent_id>`

Fetch details and alerts for a specific agent, scoped to the authenticated tenant.

Requires an `Authorization: Bearer <token>` header. The token can be a customer JWT (from `/customer/login`) or a Wazuh JWT (from `/authenticate`).

**Path param:**

| Param | Type | Description |
|---|---|---|
| `agent_id` | string | Wazuh agent ID (e.g. `001`) |

**Query params:**

| Param | Type | Default | Description |
|---|---|---|---|
| `limit` | int | `100` | Maximum alerts to return |
| `time_range` | string | `7d` | Lookback window (e.g. `24h`, `30d`) |
| `tenant` | string | — | Tenant ID override (only applies to Wazuh JWTs) |

**Examples:**

```
curl -H "Authorization: Bearer <token>" http://localhost:5000/agents/001

curl -H "Authorization: Bearer <token>" \
  "http://localhost:5000/agents/001?limit=50&time_range=24h"
```

**Response (200):**

```json
{
  "agent": {
    "id": "001",
    "name": "server-01",
    "os": "Ubuntu 22.04.3 LTS",
    "version": "Wazuh v4.7.0",
    "last_seen": "2026-06-25T14:30:00Z",
    "status": "active",
    "groups": ["acme-servers"]
  },
  "alerts": {
    "critical": [],
    "high": [],
    "warning": [ { ... } ],
    "total": 1
  }
}
```

**Errors:** `401` (missing/invalid token), `404` (agent not found or not in tenant scope), `502` (Wazuh API error).

---

## Customer API

### `POST /customer/register`

Create a new customer account with a tenant ID and Wazuh group mappings.

**Request:**
```json
{
    "username": "customer1",
    "password": "secure-password",
    "tenant_id": "acme-corp",
    "wazuh_groups": ["acme-servers", "acme-workstations"]
}
```

**Response (201):**
```json
{ "message": "Customer registered" }
```

**Errors:** `400` (missing fields), `409` (username or tenant ID already exists).

---

### `POST /customer/login`

Authenticate as a customer and receive a JWT scoped to the customer's tenant.

**Request:**
```json
{ "username": "customer1", "password": "secure-password" }
```

**Response (200):**
```json
{ "token": "eyJhbGciOiJIUzI1NiJ9..." }
```

**Errors:** `400` (missing credentials), `401` (invalid credentials).

The returned token embeds the customer's `tenant_id`. When used with `/stats/agents` or `/alerts`, results are automatically filtered to the Wazuh groups mapped to that tenant.

---

### `GET /tenants`

List all registered tenant IDs.

**Response (200):**
```json
{ "tenants": ["acme-corp", "globex-inc"] }
```

Useful for registration flows — a frontend can check available tenant IDs before a customer signs up.

---

### `GET /tenants/check?name=<id>`

Check if a tenant ID is available.

**Response (200):**
```json
{ "available": true }
```

**Errors:** `400` (missing `name` parameter).

---

## Wazuh prerequisites

- Agents must be assigned to Wazuh groups that match the tenant mappings in the database.
- The Wazuh service account (set in `.env`) needs read access to the `/agents` and `/security/alerts` endpoints.
