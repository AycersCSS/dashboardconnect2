# MergeIT-WazuhConnector

Lightweight Flask middleware that proxies requests from the MergeIT dashboard to the [Wazuh](https://wazuh.com) API, scoping each request to the caller's tenant via Wazuh group filters. Exposes 18 routes covering agents, alerts, vulnerabilities, FIM, rules, compliance, logs, manager status, and platform stubs.

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
   WAZUH_INDEXER_URL="https://localhost:9200"
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

### `GET /authenticate`

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

### `GET /agents`

Proxy to Wazuh's `GET /agents`. Returns a list of agents, filtered to the caller's tenant group scopes.

| Query param | Type | Description |
|---|---|---|
| `limit` | int | Maximum items to return |
| `offset` | int | Pagination offset |
| `status` | string | Filter by status: `active`, `disconnected`, `pending`, `never_connected` |
| `group` | string | Filter by Wazuh group name |
| `search` | string | Text search across agent fields |

**Response (200):**
```json
{ "data": { "affected_items": [...], "total_affected_items": 42 }, "error": 0 }
```

**Errors:** `401`, `502`.

---

### `GET /agents/status-count`

Return agent counts broken down by connection status. Uses a single `GET /agents?summary=true` call scoped to the caller's tenant.

**Response (200):**
```json
{ "active": 38, "disconnected": 2, "pending": 1, "never_connected": 1 }
```

**Errors:** `401`, `502`.

---

### `GET /agents/<agent_id>`

Fetch details and alerts for a specific agent, scoped to the authenticated tenant.

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

**Errors:** `401`, `404` (not found or not in tenant scope), `502`.

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

**Errors:** `401`, `502`.

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

**Response (200):**
```json
{ "critical": [...], "high": [...], "warning": [...], "total": 50 }
```

**Errors:** `401`, `502`.

---

### `GET /vulnerabilities`

Proxy to Wazuh's `GET /vulnerability`. Returns detected vulnerabilities scoped to the caller's tenant.

| Query param | Type | Description |
|---|---|---|
| `limit` | int | Maximum items to return |
| `offset` | int | Pagination offset |
| `severity` | string | Filter by severity level |

**Response (200):**
```json
{ "data": { "affected_items": [...], "total_affected_items": 12 }, "error": 0 }
```

**Caching:** Responses are cached for 60 seconds keyed by tenant and query parameters. Rapid consecutive requests with the same filters return the cached result without hitting the Wazuh API.

**Errors:** `401`, `502`.

---

### `GET /fim`

Proxy to Wazuh's `GET /experimental/syscheck`. Returns File Integrity Monitoring events scoped to the caller's tenant.

| Query param | Type | Description |
|---|---|---|
| `limit` | int | Maximum items to return |
| `offset` | int | Pagination offset |
| `agent_id` | string | Filter by agent ID |
| `path` | string | Filter by file path |
| `action` | string | Filter by action type |

**Response (200):**
```json
{ "data": { "affected_items": [...], "total_affected_items": 200 }, "error": 0 }
```

**Errors:** `401`, `502`.

---

### `GET /rules`

Proxy to Wazuh's `GET /rules`. Returns the Wazuh ruleset.

| Query param | Type | Description |
|---|---|---|
| `limit` | int | Maximum items to return |
| `offset` | int | Pagination offset |
| `level` | int | Filter by rule level |
| `group` | string | Filter by rule group |

**Response (200):**
```json
{ "data": { "affected_items": [...], "total_affected_items": 850 }, "error": 0 }
```

**Errors:** `401`, `502`.

---

### `GET /compliance?framework=...`

Proxy to Wazuh's `GET /compliance/{framework}`. Returns compliance data for the specified framework (Wazuh 4.9+).

| Query param | Type | Required | Description |
|---|---|---|---|
| `framework` | string | Yes | Compliance framework name (e.g. `nist`, `pci_dss`) |
| `limit` | int | No | Maximum items to return |
| `offset` | int | No | Pagination offset |

**Response (200):**
```json
{ "data": { "affected_items": [...] }, "error": 0 }
```

**Errors:** `400` (missing framework), `401`, `502`.

---

### `GET /logs`

Proxy to Wazuh's `GET /manager/logs`. Returns the Wazuh manager log stream.

| Query param | Type | Description |
|---|---|---|
| `limit` | int | Maximum log lines to return |

**Response (200):**
```json
{ "data": { "affected_items": [...], "total_affected_items": 100 }, "error": 0 }
```

**Errors:** `401`, `502`.

---

### `GET /manager`

Combine Wazuh's `GET /manager/status`, `GET /cluster/healthcheck`, and indexer root info into a single health summary.

**Response (200):**
```json
{
  "manager": { "wazuh-analysisd": "running", "wazuh-syscheckd": "running", ... },
  "workers": { "active": 2, "total": 3 },
  "indexer": { "name": "wazuh-cluster", "version": "7.17.1" },
  "apiLatencyP95Ms": 142.3
}
```

**Errors:** `401`, `502`.

---

### `GET /threat-actors`

**Stub.** Returns an empty list. Populated from the MergeIT platform in a future release.

**Response (200):**
```json
{ "actors": [] }
```

---

### `GET /integrations/<id>`

**Stub.** Returns a "not connected" status for a known integration. Populated from M365, NinjaOne, Bitdefender, Cyber Essentials, or Customer Portal data planes in a future release.

**Path param:**

| Param | Type | Valid values |
|---|---|---|
| `id` | string | `microsoft-365`, `ninjaone`, `bitdefender`, `cyber-essentials`, `customer-portal` |

**Response (503):**
```json
{ "ok": false, "error": "not_connected", "id": "microsoft-365" }
```

**Errors:** `400` (unsupported integration id).

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

The returned token embeds the customer's `tenant_id`. When used with any data endpoint, results are automatically filtered to the Wazuh groups mapped to that tenant.

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

- The Wazuh API must be reachable at the URL configured in `WAZUH_API_URL` (port `55000` by default).
- The Wazuh service account (set in `.env`) needs read access to the following endpoints:
  `GET /agents`, `GET /vulnerability`, `GET /experimental/syscheck`, `GET /rules`,
  `GET /compliance/{framework}`, `GET /manager/logs`, `GET /manager/status`,
  `GET /cluster/healthcheck`, `POST /security/user/authenticate`.
- Agents must be assigned to Wazuh groups that match the tenant-to-group mappings in the database.
- `WAZUH_INDEXER_URL` is required. The indexer uses the same service-account credentials as the Wazuh API. If the indexer is unreachable at runtime the `/manager` route returns `{"name": null, "version": null}` gracefully.
