import { createHubClient, HubError } from '/sdk/backend-hub-sdk-0.1.0.mjs';
import { resolveAppConfig } from '/portfolio-config.js';

const params = new URLSearchParams(window.location.search);
const envName = params.get('env') || 'local';
const cfg = resolveAppConfig({ appId: 'notes-demo', environment: envName });

const hub = createHubClient({
  ...cfg,
  storage: window.localStorage,
});

const $ = (id) => document.getElementById(id);

function notify(message, isError = false) {
  const el = $('toast');
  el.textContent = message;
  el.className = isError ? 'toast visible error' : 'toast visible';
  setTimeout(() => {
    el.className = 'toast';
  }, 4000);
}

async function runAction(fn) {
  try {
    await fn();
  } catch (err) {
    if (err instanceof HubError) {
      notify(`[${err.code}] ${err.message}`, true);
    } else {
      notify(err?.message || 'Unexpected error', true);
    }
  }
}

function renderAuthState() {
  const s = hub.auth.getSession();
  $('auth-state').textContent = s?.user ? `Signed in as ${s.user.email} (${s.user.id})` : 'Signed out';
}

async function refreshHubHealth() {
  try {
    const h = await hub.health();
    $('hub-health').textContent = `Hub ${h.db.toUpperCase()} (${h.environment}, ${h.migrationsApplied} migrations)`;
  } catch (err) {
    $('hub-health').textContent = `Hub error: ${err.message}`;
  }
}

async function probeAppHealth(appId) {
  const resp = await fetch(`${cfg.baseUrl}/functions/v1/health?appId=${encodeURIComponent(appId)}`);
  const data = await resp.json();
  $('probe-output').textContent = JSON.stringify(data, null, 2);
}

async function refreshPortfolio() {
  const session = hub.auth.getSession();
  const container = $('apps-container');
  if (!session?.accessToken) {
    container.innerHTML = '<p class="muted">Sign in above to inspect your portfolio apps.</p>';
    return;
  }

  const resp = await fetch(`${cfg.baseUrl}/functions/v1/portfolio-health`, {
    headers: { Authorization: `Bearer ${session.accessToken}` },
  });
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data?.error?.message || 'Failed to load portfolio');
  }

  container.innerHTML = '';
  if (data.apps.length === 0) {
    container.innerHTML = '<p class="muted">No active app memberships found for this user.</p>';
    return;
  }

  for (const app of data.apps) {
    const tile = document.createElement('div');
    tile.className = 'app-tile';

    const head = document.createElement('div');
    head.className = 'app-head';
    const title = document.createElement('strong');
    title.textContent = `${app.name} (${app.id})`;
    const badge = document.createElement('span');
    badge.className = app.health === 'healthy' ? 'badge' : 'badge warn';
    badge.textContent = `${app.health} · ${app.role}`;
    head.append(title, badge);
    tile.appendChild(head);

    const lines = [
      `Origins: ${app.allowedOrigins.join(', ') || 'none'}`,
      `Collections: ${app.allowedCollections.join(', ')}`,
      `Mode: selfEnroll=${app.allowSelfEnroll} · publicRead=${app.allowPublicRead}`,
      `Records: ${app.usage.recordCount} / ${app.limits.maxRecordsPerApp} app (${app.limits.maxRecordsPerUser}/user)`,
      `Storage: ${app.usage.activeStorageBytes} B used (${app.usage.activeObjectCount} files) / ${app.limits.maxStorageBytes} B`,
      `Rate limit: ${app.limits.rateLimitRpm} req/min`,
    ];
    if (app.recentDenied24h !== null) {
      lines.push(`Denied audit events (24h): ${app.recentDenied24h}`);
    }

    for (const line of lines) {
      const p = document.createElement('p');
      p.className = 'kv';
      p.textContent = line;
      tile.appendChild(p);
    }

    const actions = document.createElement('div');
    actions.className = 'actions';
    actions.style.marginTop = '0.6rem';

    if (app.allowedOrigins[0]) {
      const openLink = document.createElement('a');
      openLink.className = 'btn secondary';
      openLink.href = app.allowedOrigins[0];
      openLink.target = '_blank';
      openLink.rel = 'noopener noreferrer';
      openLink.textContent = 'Open App UI';
      actions.appendChild(openLink);
    }

    const probeBtn = document.createElement('button');
    probeBtn.className = 'secondary';
    probeBtn.textContent = 'Health Check';
    probeBtn.onclick = () => runAction(() => probeAppHealth(app.id));
    actions.appendChild(probeBtn);

    if (app.role === 'admin' || app.role === 'owner') {
      const recBtn = document.createElement('button');
      recBtn.textContent = 'Reconcile Usage';
      recBtn.onclick = () =>
        runAction(async () => {
          const r = await fetch(`${cfg.baseUrl}/functions/v1/quota-reconcile`, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${session.accessToken}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ appId: app.id }),
          });
          if (!r.ok) {
            const errBody = await r.json();
            throw new Error(errBody?.error?.message || 'Reconcile failed');
          }
          await refreshPortfolio();
          notify(`Reconciled ${app.id}`);
        });
      actions.appendChild(recBtn);
    }

    tile.appendChild(actions);
    container.appendChild(tile);
  }
}

$('btn-login').onclick = () =>
  runAction(async () => {
    await hub.auth.login($('auth-email').value, $('auth-password').value);
    renderAuthState();
    await refreshPortfolio();
    notify('Portfolio loaded');
  });

$('btn-refresh').onclick = () => runAction(refreshPortfolio);

$('btn-logout').onclick = () => {
  hub.auth.logout();
  renderAuthState();
  $('apps-container').innerHTML = '<p class="muted">Sign in above to inspect your portfolio apps.</p>';
  notify('Signed out');
};

$('btn-probe').onclick = () =>
  runAction(async () => {
    await probeAppHealth($('probe-app-id').value.trim());
  });

renderAuthState();
refreshHubHealth();
runAction(refreshPortfolio);
