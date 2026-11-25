import { createHubClient, HubError } from '/sdk/backend-hub-sdk-0.1.0.mjs';
import { resolveAppConfig } from '/portfolio-config.js';

const APP_ID = 'habits-demo';
const DEFAULT_BUCKET = 'habits-files';

const params = new URLSearchParams(window.location.search);
const envName = params.get('env') || 'local';

const cfg = resolveAppConfig({ appId: APP_ID, environment: envName });
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
  const session = hub.auth.getSession();
  $('auth-state').textContent = session?.user
    ? `Signed in as ${session.user.email} (${session.user.id})`
    : 'Signed out (habits-demo requires active membership)';
}

async function refreshHealth() {
  try {
    const resp = await fetch(`${cfg.baseUrl}/functions/v1/health?appId=${encodeURIComponent(APP_ID)}`);
    const data = await resp.json();
    $('health-status').textContent = data.ok
      ? `habits-demo: ${data.app.status.toUpperCase()} (DB ${data.db})`
      : `habits-demo: ${data.app?.status || 'DEGRADED'}`;
  } catch (err) {
    $('health-status').textContent = `Health error: ${err.message}`;
  }
}

async function refreshHabits() {
  if (!hub.auth.getSession()) {
    $('habits-list').innerHTML = '';
    return;
  }
  const [habits, checkins] = await Promise.all([hub.db('habits').list(), hub.db('checkins').list()]);
  const combined = [...habits, ...checkins].sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
  const list = $('habits-list');
  list.innerHTML = '';
  for (const item of combined) {
    const li = document.createElement('li');
    const info = document.createElement('span');
    info.textContent = `[${item.collection} | ${item.visibility}] ${item.title}: ${item.payload?.note ?? ''}`;
    li.appendChild(info);

    if (hub.auth.getSession()?.user?.id === item.owner_id) {
      const del = document.createElement('button');
      del.textContent = 'Delete';
      del.className = 'secondary';
      del.onclick = () =>
        runAction(async () => {
          await hub.db(item.collection).remove(item.id);
          await refreshHabits();
          notify('Entry deleted');
        });
      li.appendChild(del);
    }
    list.appendChild(li);
  }
}

async function refreshFiles() {
  if (!hub.auth.getSession()) {
    $('files-list').innerHTML = '';
    return;
  }
  const files = await hub.storage.list();
  const list = $('files-list');
  list.innerHTML = '';
  for (const f of files) {
    const li = document.createElement('li');
    const label = document.createElement('span');
    label.textContent = `${f.relative_path} (${f.size_bytes} B, ${f.mime_type})`;
    li.appendChild(label);

    const actions = document.createElement('div');
    actions.className = 'actions';
    const dl = document.createElement('button');
    dl.textContent = 'Signed Link';
    dl.onclick = () =>
      runAction(async () => {
        const { url } = await hub.storage.createSignedUrl(f.id, { expiresInSeconds: 60 });
        window.open(url, '_blank', 'noopener,noreferrer');
      });

    const del = document.createElement('button');
    del.textContent = 'Delete';
    del.className = 'secondary';
    del.onclick = () =>
      runAction(async () => {
        await hub.storage.remove(f.id);
        await refreshFiles();
        notify('File deleted');
      });

    actions.append(dl, del);
    li.appendChild(actions);
    list.appendChild(li);
  }
}

$('btn-login').onclick = () =>
  runAction(async () => {
    await hub.auth.login($('auth-email').value, $('auth-password').value);
    renderAuthState();
    await Promise.all([refreshHabits(), refreshFiles()]);
    notify('Signed in to habits-demo');
  });

$('btn-logout').onclick = () => {
  hub.auth.logout();
  renderAuthState();
  $('habits-list').innerHTML = '';
  $('files-list').innerHTML = '';
  $('profile-output').textContent = 'Signed out';
  $('caps-output').textContent = 'Signed out';
  notify('Signed out');
};

$('btn-save-profile').onclick = () =>
  runAction(async () => {
    const p = await hub.profile.upsert({
      displayName: $('profile-name').value,
      bio: $('profile-bio').value,
    });
    $('profile-output').textContent = JSON.stringify(p, null, 2);
    notify('habits-demo profile saved');
  });

$('btn-load-profile').onclick = () =>
  runAction(async () => {
    const p = await hub.profile.get();
    $('profile-output').textContent = p ? JSON.stringify(p, null, 2) : 'No profile yet in habits-demo';
  });

$('btn-create-habit').onclick = () =>
  runAction(async () => {
    const col = $('habit-collection').value;
    await hub.db(col).create({
      title: $('habit-title').value,
      visibility: $('habit-visibility').value,
      payload: { note: $('habit-cadence').value },
    });
    $('habit-title').value = '';
    $('habit-cadence').value = '';
    await refreshHabits();
    notify('Saved to habits-demo');
  });

$('btn-list-habits').onclick = () => runAction(refreshHabits);

$('btn-upload-file').onclick = () =>
  runAction(async () => {
    const file = $('file-input').files?.[0];
    if (!file) throw new Error('Select a file first');
    const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
    await hub.storage.upload(DEFAULT_BUCKET, `uploads/${safeName}`, file);
    await refreshFiles();
    notify('Private file uploaded to habits-files');
  });

$('btn-list-files').onclick = () => runAction(refreshFiles);

$('btn-capabilities').onclick = () =>
  runAction(async () => {
    const caps = await hub.app.getCapabilities();
    $('caps-output').textContent = JSON.stringify(caps, null, 2);
  });

renderAuthState();
refreshHealth();
runAction(async () => {
  if (hub.auth.getSession()) {
    await Promise.all([refreshHabits(), refreshFiles()]);
  }
});
