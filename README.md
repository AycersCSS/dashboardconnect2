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
   ```

3. (Optional) Configure tenant-to-agent-group mappings in `tenants.json`:
   ```json
   {
       "acme-corp": ["acme-servers", "acme-workstations"],
       "globex-inc": ["globex-servers"]
   }
   ```

4. Run the server:
   ```
   python main.py
   ```

## API

All data endpoints require a Bearer token obtained from `/authenticate`.

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
| `tenant` | string | — | Tenant ID from `tenants.json` — scopes count to agents in the mapped Wazuh groups |

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
| `tenant` | string | — | Tenant ID from `tenants.json` — filters alerts to agents in the mapped Wazuh groups |

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

## Tenant filtering

Tenant support is optional. The connector maps tenant IDs to Wazuh agent groups via `tenants.json`. When `?tenant=` is omitted the endpoint returns data for **all** agents/alerts (original behaviour).

### Configuration

Set `TENANTS_FILE` in `.env` to use a different path (default: `tenants.json`):

```
TENANTS_FILE=/etc/opencode/tenants.json
```

### Wazuh prerequisites

- Agents must be assigned to Wazuh groups that match the values in your mapping file.
- The Wazuh user used for authentication needs read access to the `/agents` and `/security/alerts` endpoints.

## Development

```
python main.py
```

Runs on `http://localhost:5000` with Flask's debug mode enabled.
