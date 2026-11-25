// Pin an explicit immutable SDK version artifact (never a mutable branch or `latest` URL).
import { createHubClient, HubError } from '/sdk/backend-hub-sdk-0.1.0.mjs';
import { resolveAppConfig } from '/portfolio-config.js';

const APP_ID = 'notes-demo';
const DEFAULT_BUCKET = 'notes-files';

const params = new URLSearchParams(window.location.search);
const envName = params.get('env') || 'local';

const hub = createHubClient({
  ...resolveAppConfig({ appId: APP_ID, environment: envName }),
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
    : 'Signed out (anonymous public-read mode)';
}

async function refreshHealth() {
  try {
    const h = await hub.health();
    $('health-status').textContent = `Backend ${h.db.toUpperCase()} (${h.environment})`;
  } catch (err) {
    $('health-status').textContent = `Backend error: ${err.message}`;
  }
}

async function refreshNotes() {
  const notes = await hub.db('notes').list();
  const list = $('notes-list');
  list.innerHTML = '';
  for (const note of notes) {
    const li = document.createElement('li');
    const info = document.createElement('span');
    info.textContent = `[${note.visibility}] ${note.title}: ${note.payload?.body ?? ''}`;
    li.appendChild(info);

    if (hub.auth.getSession()?.user?.id === note.owner_id) {
      const del = document.createElement('button');
      del.textContent = 'Delete';
      del.className = 'secondary';
      del.onclick = () =>
        runAction(async () => {
          await hub.db('notes').remove(note.id);
          await refreshNotes();
          notify('Note deleted');
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
        notify('File deleted and quota reconciled');
      });

    actions.append(dl, del);
    li.appendChild(actions);
    list.appendChild(li);
  }
}

$('btn-signup').onclick = () =>
  runAction(async () => {
    await hub.auth.signup($('auth-email').value, $('auth-password').value);
    await hub.app.enroll();
    renderAuthState();
    await Promise.all([refreshNotes(), refreshFiles()]);
    notify('Signed up and enrolled as member in notes-demo');
  });

$('btn-login').onclick = () =>
  runAction(async () => {
    await hub.auth.login($('auth-email').value, $('auth-password').value);
    renderAuthState();
    await Promise.all([refreshNotes(), refreshFiles()]);
    notify('Signed in');
  });

$('btn-enroll').onclick = () =>
  runAction(async () => {
    const m = await hub.app.enroll();
    notify(`Enrolled with role=${m.role}`);
  });

$('btn-logout').onclick = () => {
  hub.auth.logout();
  renderAuthState();
  $('profile-output').textContent = 'Signed out';
  $('files-list').innerHTML = '';
  runAction(refreshNotes);
  notify('Signed out');
};

$('btn-save-profile').onclick = () =>
  runAction(async () => {
    const p = await hub.profile.upsert({
      displayName: $('profile-name').value,
      bio: $('profile-bio').value,
    });
    $('profile-output').textContent = JSON.stringify(p, null, 2);
    notify('Profile saved');
  });

$('btn-load-profile').onclick = () =>
  runAction(async () => {
    const p = await hub.profile.get();
    $('profile-output').textContent = p ? JSON.stringify(p, null, 2) : 'No profile yet';
  });

$('btn-create-note').onclick = () =>
  runAction(async () => {
    await hub.db('notes').create({
      title: $('note-title').value,
      visibility: $('note-visibility').value,
      payload: { body: $('note-body').value },
    });
    $('note-title').value = '';
    $('note-body').value = '';
    await refreshNotes();
    notify('Note created');
  });

$('btn-list-notes').onclick = () => runAction(refreshNotes);

$('btn-upload-file').onclick = () =>
  runAction(async () => {
    const file = $('file-input').files?.[0];
    if (!file) throw new Error('Select a file first');
    const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
    await hub.storage.upload(DEFAULT_BUCKET, `uploads/${safeName}`, file);
    await refreshFiles();
    notify('Private file uploaded');
  });

$('btn-list-files').onclick = () => runAction(refreshFiles);

$('btn-capabilities').onclick = () =>
  runAction(async () => {
    const caps = await hub.app.getCapabilities();
    $('trusted-output').textContent = JSON.stringify(caps, null, 2);
  });

$('btn-summary').onclick = () =>
  runAction(async () => {
    const summary = await hub.functions.invoke('trusted-note-summary');
    $('trusted-output').textContent = JSON.stringify(summary, null, 2);
  });

renderAuthState();
refreshHealth();
runAction(refreshNotes);
