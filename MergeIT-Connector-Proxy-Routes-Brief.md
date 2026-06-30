# MergeIT-WazuhConnector: New Proxy Routes
## Brief for the connector developer

_From: dashboard team  |  Repo: D:\projects\wazuh-dashboard  |  Date: 2026-06-30_

## Context

The dashboard at D:\projects\wazuh-dashboard talks to the connector, not to Wazuh directly. Today the connector exposes 8 routes. The dashboard needs ~10 more so the UI can show real data. Each new route is the same pattern: take a request from the dashboard, scope it to the caller's tenant, call Wazuh with the cached service-account JWT, return the result.

## What to build

For each of the endpoints below, add a Flask route in main.py following the existing pattern from /stats/agents and /alerts. The auth helper _get_request_context() already handles the customer JWT decode + Wazuh-group scoping. Use it. Forward to the matching Wazuh manager endpoint. Return the JSON unchanged. On Wazuh error, return {"error": str(e)} with status 502.

## Endpoint table

| Dashboard proxy route | Connector route (add) | Wazuh manager endpoint | Response shape (top-level) |
| --- | --- | --- | --- |
| `GET /api/wazuh/agents` | `GET /agents` | `GET /agents (whitelist: limit, offset, status, group, search)` | `{"data": {"affected_items": [...], "total_affected_items": N}}` |
| `GET /api/wazuh/agents/status-count` | `GET /agents/status-count` | `derive from GET /agents?summary=true (4 calls: one per status)` | `{"active": N, "disconnected": N, "pending": N, "never_connected": N}` |
| `GET /api/wazuh/vulnerabilities` | `GET /vulnerabilities` | `GET /vulnerability (whitelist: limit, offset, severity)` | `strip to {cve, title, package, version, severity, cvss, agentCount, fixedVersion, publishedAt}` |
| `GET /api/wazuh/fim` | `GET /fim` | `GET /experimental/syscheck (whitelist: limit, offset, agent_id, path, action)` | `{"data": {"affected_items": [...]}}` |
| `GET /api/wazuh/rules` | `GET /rules` | `GET /rules (whitelist: limit, offset, level, group)` | `{"data": {"affected_items": [...]}}` |
| `GET /api/wazuh/compliance` | `GET /compliance?framework=...` | `GET /compliance/:framework (Wazuh 4.9+; tenant scoped already)` | `{"data": {"affected_items": [...]}}` |
| `GET /api/wazuh/logs` | `GET /logs` | `GET /manager/logs?limit=... (or /logs/archives if archives are exposed)` | `{"data": {"affected_items": [...]}}` |
| `GET /api/wazuh/manager` | `GET /manager` | `GET /manager/status + GET /cluster/health combined` | `{manager, workers: {active, total}, indexer: {name, version}, apiLatencyP95Ms}` |
| `GET /api/wazuh/threat-actors` | `GET /threat-actors` | `NOT IN Wazuh - return {actors: []} for now; populate from MergeIT platform later` | `{"actors": []}` |
| `GET /api/wazuh/integrations/:id` | `GET /integrations/:id` | `NOT IN Wazuh - return 503 {error: "not_connected", id} for now; populate from M365/NinjaOne/Bitdefender/CE/CP data plane later` | `{"ok": false, "error": "not_connected", "id": ...}` |

## Auth (already implemented in `_get_request_context`)

- The connector decodes the dashboard's Authorization: Bearer <jwt> where <jwt> is the connector's own HS256 token (set via POST /customer/login).
- It looks up tenant_id and resolves wazuh_groups from the customers table.
- It adds agent.groups=<groups> to every Wazuh call that supports it (mirrors what stats.py and alerts.py already do).
- It caches the Wazuh service-account JWT for 30 minutes in module-level _wazuh_token / _wazuh_token_obtained (already implemented).
- If a Wazuh call needs a query the connector doesn't already add (for example GET /fim?agent_id=X), append the existing agent.groups filter and add agent.id=X to the q= parameter. See agent.py get_agent_alerts for the pattern.

## Group scoping (no extra work for you)

- For endpoints where the Wazuh query language supports agent.groups=... (most do), pass it.
- For endpoints that don't (e.g. /manager/status, /cluster/health, /compliance/:framework for now), return the unscoped result. The operator of the dashboard is allowed to see fleet-wide manager health regardless of tenant.

## Errors

- Wazuh 401: clear _wazuh_token so the next call re-auths (the dashboard will surface 401 as 'Sign in').
- Wazuh 4xx/5xx: return {"error": "<message>"} with status 502.
- Bad customer JWT: 401 {error: "Invalid token"} (already handled).
- Unknown integration id on /integrations/:id: 400 {error: "unsupported_integration"} (whitelist the 5 ids: microsoft-365, ninjaone, bitdefender, cyber-essentials, customer-portal).

## What stays on the dashboard side

The dashboard's app/(dashboard)/api/wazuh/* proxy routes will be rewritten to forward to ${CONNECTOR_BASE_URL}/<path>, not to ${WAZUH_API_URL}/<path>. No code on the connector side needs to know about Wazuh URLs or auth - the connector hides all of that.

## What I need back

- 1. A sample response from each new route (so the dashboard's lib/wazuh/types.ts can be confirmed).
- 2. A requirements.txt pin for the new wazuh_indexer or opensearch client if the developer decides to call those directly for /vulnerabilities instead of Wazuh's /vulnerability (cheaper, faster).

## One thing to confirm

The Wazuh manager's /vulnerability endpoint can be slow (10s+) on big fleets. The connector should cache responses for ~60s with the (wazuh_groups, query_params) tuple as the key. If caching isn't added now, at minimum set a 30s timeout on the upstream requests.get call so a slow Wazuh doesn't pin a worker.

## Suggested order of work

- 1. /agents (most-used, simplest)
- 2. /fim (small payload, well-bounded)
- 3. /vulnerabilities (consider the 60s cache note above)
- 4. /rules
- 5. /compliance
- 6. /logs
- 7. /manager
- 8. /threat-actors and /integrations/:id (return the documented stubs; fill in later)

## Quick smoke test

Once the first two routes are in, verify the chain with a real login:

```bash
TOKEN=$(curl -X POST https://connector:5000/customer/login \
  -d '{"username":"acme-admin","password":"..."}' \
  -H 'Content-Type: application/json' | jq -r .token)

curl -H "Authorization: Bearer $TOKEN" https://connector:5000/agents
curl -H "Authorization: Bearer $TOKEN" https://connector:5000/fim?limit=20
```
