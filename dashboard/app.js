// MergeIT Wazuh Dashboard — SPA Router & Data Layer
// No build step. No dependencies. Polls connector endpoints on localhost:5000.

const CONNECTOR_BASE = '';
let AUTH_TOKEN = null;

// Authenticate on startup
async function initAuth() {
  try {
    const data = await fetch('/dashboard/init').then(r => r.json());
    if (data.token) AUTH_TOKEN = data.token;
  } catch (e) {
    console.warn('Auth init failed, some requests may 401:', e.message);
  }
}

// --- Router ---

const routes = {
  overview: { title: 'Overview', page: 'overview' },
  agents: { title: 'Agents', page: 'agents' },
  alerts: { title: 'Alerts', page: 'alerts' },
  vulnerabilities: { title: 'Vulnerabilities', page: 'vulnerabilities' },
  manager: { title: 'Manager', page: 'manager' },
};

let currentPage = null;
let refreshTimer = null;

function navigate(path) {
  const route = path === '/' ? routes.overview : routes[path.replace('/dashboard/', '').replace('/', '')];
  if (!route) return navigate('/');
  loadPage(route);
}

function loadPage(route) {
  clearInterval(refreshTimer);
  currentPage = route.page;

  // Update nav active state
  document.querySelectorAll('.nav-link').forEach(link => {
    const page = link.dataset.page;
    link.classList.toggle('active', page === route.page);
  });

  // Update document title
  document.title = `${route.title} — MergeIT Wazuh Dashboard`;

  // Fetch the page partial
  const main = document.getElementById('mainContent');
  fetch(`/dashboard/pages/${route.page}.html`)
    .then(r => r.text())
    .then(html => {
      main.innerHTML = html;
      initPage(route.page);
    })
    .catch(err => {
      main.innerHTML = `<div class="error"><h2>Failed to load page</h2><p>${err.message}</p></div>`;
    });
}

// --- API helpers ---

async function api(path, params = {}) {
  const qs = Object.entries(params).filter(([, v]) => v !== undefined && v !== '').map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  const url = qs ? `${path}?${qs}` : path;
  const headers = {};
  if (AUTH_TOKEN) headers['Authorization'] = `Bearer ${AUTH_TOKEN}`;
  const resp = await fetch(url, { headers });
  if (resp.status === 401) {
    // Token expired — try re-auth once
    await initAuth();
    if (AUTH_TOKEN) {
      headers['Authorization'] = `Bearer ${AUTH_TOKEN}`;
      const retry = await fetch(url, { headers });
      if (retry.ok) return retry.json();
    }
    throw new Error('Unauthorized');
  }
  if (!resp.ok) throw new Error(`API error: ${resp.status}`);
  return resp.json();
}

function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString();
}

function severityClass(level) {
  if (level >= 14) return 'critical';
  if (level >= 12) return 'high';
  if (level >= 7) return 'warning';
  return 'info';
}

function sevBadgeHtml(severity) {
  const sev = (severity || '').toLowerCase();
  if (['critical','high','medium','low'].includes(sev)) {
    return `<span class="badge badge-${sev}">${sev.toUpperCase()}</span>`;
  }
  return `<span class="badge">${severity || '—'}</span>`;
}

// Auto-refresh for Overview and Alerts
function startAutoRefresh() {
  const refreshPages = ['overview', 'alerts'];
  if (!refreshPages.includes(currentPage)) return;
  refreshTimer = setInterval(() => {
    if (currentPage === 'overview') renderOverview();
    if (currentPage === 'alerts') loadAlerts();
  }, 30000);
}

// --- Page Init Dispatcher ---
function initPage(page) {
  switch (page) {
    case 'overview': renderOverview(); break;
    case 'agents': renderAgents(); break;
    case 'alerts': loadAlerts(); break;
    case 'vulnerabilities': renderVulnerabilities(); break;
    case 'manager': renderManager(); break;
  }
  startAutoRefresh();
}

// --- Overview ---

async function renderOverview() {
  try {
    const statuses = ['active', 'disconnected', 'pending', 'never_connected'];
    const counts = {};
    await Promise.all(statuses.map(async s => {
      const data = await api('/stats/agents', { status: s });
      counts[s] = data.total_agents;
    }));
    document.getElementById('agentTotal').textContent = counts.active + counts.disconnected + counts.pending + counts.never_connected;
    document.getElementById('countActive').textContent = counts.active;
    document.getElementById('countDisconnected').textContent = counts.disconnected;
    document.getElementById('countPending').textContent = counts.pending;
    document.getElementById('countNever').textContent = counts.never_connected;

    const mgr = await api('/manager');
    const el = document.getElementById('managerStatus');
    if (mgr && mgr.manager) {
      const svcs = Object.entries(mgr.manager).map(([name, status]) => {
        const cls = status === 'running' ? 'status-ok' : 'status-err';
        return `<div class="svc-row"><span>${name}</span><span class="${cls}">${status}</span></div>`;
      }).join('');
      el.innerHTML = `
        <div class="svc-list">${svcs}</div>
        <div class="manager-meta">
          <span>Workers: ${mgr.workers?.active || 0}/${mgr.workers?.total || 0}</span>
          <span>Indexer: ${mgr.indexer?.name || '—'} v${mgr.indexer?.version || '—'}</span>
          <span>P95 Latency: ${mgr.apiLatencyP95Ms ? mgr.apiLatencyP95Ms + 'ms' : '—'}</span>
        </div>`;
    }

    const alerts = await api('/alerts', { limit: 5 });
    const list = document.getElementById('recentAlerts');
    const allAlerts = [...(alerts.critical||[]), ...(alerts.high||[]), ...(alerts.warning||[])].slice(0, 5);
    if (allAlerts.length) {
      list.innerHTML = allAlerts.map(a => {
        const rule = a.rule || {};
        const level = rule.level || 0;
        const agent = a.agent || {};
        return `<div class="alert-card ${severityClass(level)}">
          <div class="alert-level">Lvl ${level}</div>
          <div class="alert-body">
            <div class="alert-desc">${rule.description || 'Unknown'}</div>
            <div class="alert-meta">${agent.name || '—'} · ${formatDate(a.timestamp)}</div>
          </div>
        </div>`;
      }).join('');
    } else {
      list.innerHTML = '<div class="empty">No recent alerts</div>';
    }
  } catch (e) {
    document.getElementById('agentTotal').textContent = 'Error';
  }
}

// --- Agents ---

async function renderAgents() {
  try {
    const data = await api('/agents', { limit: 200 });
    const items = data.data?.affected_items || [];
    const total = data.data?.total_affected_items || 0;

    document.getElementById('agentTotal').textContent = total;

    const statuses = ['active', 'disconnected', 'pending', 'never_connected'];
    const statusCount = {};
    await Promise.all(statuses.map(async s => {
      const d = await api('/stats/agents', { status: s });
      statusCount[s] = d.total_agents;
    }));
    const maxCount = Math.max(...Object.values(statusCount), 1);
    ['active', 'disconnected', 'pending', 'never_connected'].forEach(s => {
      const bar = document.getElementById(`bar${s.charAt(0).toUpperCase() + s.slice(1)}`);
      if (bar) {
        bar.style.width = `${(statusCount[s] / maxCount * 100).toFixed(0)}%`;
        bar.nextElementSibling.textContent = `${s}: ${statusCount[s]}`;
      }
    });

    const tbody = document.getElementById('agentsTableBody');
    if (items.length) {
      tbody.innerHTML = items.map(a => `<tr class="agent-row" data-id="${a.id}">
        <td>${a.id}</td>
        <td>${a.name || '—'}</td>
        <td>${a.os?.name || a.os || '—'}</td>
        <td><span class="badge badge-${a.status === 'active' ? 'active' : 'warn'}">${a.status || '—'}</span></td>
        <td>${formatDate(a.lastKeepAlive || a.lastSeen)}</td>
      </tr>`).join('');
    } else {
      tbody.innerHTML = '<tr><td colspan="5" class="empty">No agents found</td></tr>';
    }

    document.getElementById('agentSearch').addEventListener('input', e => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('.agent-row').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  } catch (e) {
    document.getElementById('agentsTableBody').innerHTML = `<tr><td colspan="5" class="empty">Error: ${e.message}</td></tr>`;
  }
}

// --- Alerts ---

async function loadAlerts() {
  try {
    const timeRange = document.getElementById('alertTimeRange')?.value || '24h';
    const data = await api('/alerts', { limit: 200, time_range: timeRange });
    const container = document.getElementById('alertsContainer');
    const critical = data.critical || [];
    const high = data.high || [];
    const warning = data.warning || [];

    document.getElementById('alertCount').textContent = data.total || 0;

    container.innerHTML = '';

    [['Critical', 'critical', critical], ['High', 'high', high], ['Warning', 'warning', warning]].forEach(([label, cls, items]) => {
      if (!items.length) return;
      const section = document.createElement('div');
      section.innerHTML = `<h3 class="alert-section-title ${cls}">${label} (${items.length})</h3>`;
      items.forEach(a => {
        const rule = a.rule || {};
        const agent = a.agent || {};
        const div = document.createElement('div');
        div.className = `alert-card ${cls}`;
        div.innerHTML = `<div class="alert-level">Lvl ${rule.level || '?'}</div>
          <div class="alert-body">
            <div class="alert-desc">${rule.description || 'Unknown rule'}</div>
            <div class="alert-meta">${agent.name || '—'} · ${formatDate(a.timestamp)}</div>
          </div>`;
        section.appendChild(div);
      });
      container.appendChild(section);
    });

    document.getElementById('alertTimeRange').addEventListener('change', loadAlerts);
  } catch (e) {
    document.getElementById('alertsContainer').innerHTML = `<div class="error">Error: ${e.message}</div>`;
  }
}

// --- Vulnerabilities ---

async function renderVulnerabilities() {
  try {
    const data = await api('/vulnerabilities', { limit: 100 });
    const items = data.data?.affected_items || [];
    const total = data.data?.total_affected_items || 0;

    document.getElementById('vulnTotal').textContent = total;
    const tbody = document.getElementById('vulnTableBody');

    if (items.length) {
      tbody.innerHTML = items.map(v => `<tr>
        <td>${v.cve || '—'}</td>
        <td>${v.package || '—'}</td>
        <td>${v.version || '—'}</td>
        <td>${sevBadgeHtml(v.severity)}</td>
        <td>${v.cvss ? (v.cvss.toFixed ? v.cvss.toFixed(1) : v.cvss) : '—'}</td>
        <td>${v.agentCount || 0}</td>
      </tr>`).join('');
    } else {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">No vulnerabilities found</td></tr>';
    }

    document.getElementById('vulnSearch').addEventListener('input', e => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('#vulnTableBody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  } catch (e) {
    document.getElementById('vulnTableBody').innerHTML = `<tr><td colspan="6" class="empty">Error: ${e.message}</td></tr>`;
  }
}

// --- Manager ---

async function renderManager() {
  try {
    const data = await api('/manager');
    const svcList = document.getElementById('svcList');
    if (data.manager && Object.keys(data.manager).length) {
      svcList.innerHTML = Object.entries(data.manager).map(([name, status]) => {
        const cls = status === 'running' ? 'status-ok' : 'status-err';
        return `<div class="svc-row"><span>${name}</span><span class="${cls}">${status}</span></div>`;
      }).join('');
    } else {
      svcList.innerHTML = '<div class="empty">Manager status unavailable</div>';
    }

    document.getElementById('workerCount').textContent = data.workers ? `${data.workers.active}/${data.workers.total}` : '—';
    document.getElementById('indexerInfo').textContent = data.indexer?.name ? `${data.indexer.name} v${data.indexer.version}` : '—';
    document.getElementById('apiLatency').textContent = data.apiLatencyP95Ms ? `${data.apiLatencyP95Ms} ms` : '—';
  } catch (e) {
    document.getElementById('svcList').innerHTML = `<div class="error">Error: ${e.message}</div>`;
  }
}

// --- Init ---

document.addEventListener('DOMContentLoaded', async () => {
  await initAuth();
  const path = window.location.pathname.replace(/\/+$/, '');
  navigate(path || '/');

  // SPA nav: intercept clicks on nav links
  document.getElementById('navLinks').addEventListener('click', e => {
    const link = e.target.closest('.nav-link');
    if (!link) return;
    e.preventDefault();
    const path = link.getAttribute('href');
    window.history.pushState(null, '', path);
    navigate(path);
  });

  // Handle browser back/forward
  window.addEventListener('popstate', () => {
    navigate(window.location.pathname);
  });
});
