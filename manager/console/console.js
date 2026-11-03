// Synod Manager console: a small single-page app on the manager's API (the same API the
// synodmgr CLI uses). Everything the API returns is put on the page as text, never as HTML.
'use strict';

const app = document.getElementById('app');
const state = { me: null, timer: null, installations: null };

// ---- helpers

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function svg(markup) {
  // static, trusted markup only (the brand mark)
  const t = document.createElement('template');
  t.innerHTML = markup;
  return t.content.firstChild;
}

const MARK = '<svg class="mark" width="28" height="28" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="7" fill="#24346e"/><rect x="5" y="11" width="6" height="12" rx="1.5" fill="#9fb0f2"/><rect x="13" y="8" width="6" height="15" rx="1.5" fill="#ffffff"/><rect x="21" y="11" width="6" height="12" rx="1.5" fill="#9fb0f2"/></svg>';

async function api(method, path, body) {
  const headers = { 'accept': 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET') headers['x-synodmgr'] = '1';
  let r;
  try {
    r = await fetch(path, { method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) });
  } catch (e) {
    return { status: 0, data: { error: 'The manager did not answer. Check the network and try again.' } };
  }
  let data = null;
  try { data = await r.json(); } catch (e) { data = {}; }
  // a session that ended while the console was open (not a failed sign-in or a wrong current password)
  if (r.status === 401 && state.me && path !== '/api/v1/sign-in' && path !== '/api/v1/me/password') {
    state.me = null;
    showSignIn('Your session ended. Sign in again.');
  }
  return { status: r.status, data };
}

function errorText(res) {
  return (res.data && res.data.error) || `The manager answered ${res.status}.`;
}

function ago(seconds) {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return 'unknown';
  const s = Math.max(0, seconds);
  if (s < 1) return 'just now';
  if (s < 90) return `${Math.round(s)} s ago`;
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 172800) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

function since(iso) {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : (Date.now() - t) / 1000;
}

function when(iso) {
  const t = new Date(iso);
  return Number.isNaN(t.getTime()) ? String(iso) : t.toLocaleString();
}

function duration(s) {
  if (s === null || s === undefined) return '';
  if (s < 90) return `${Math.round(s)} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${(s / 3600).toFixed(1)} h`;
  return `${Math.round(s / 86400)} days`;
}

function bytes(n) {
  if (n < 1e6) return `${(n / 1e3).toFixed(0)} kB`;
  if (n < 1e9) return `${(n / 1e6).toFixed(1)} MB`;
  return `${(n / 1e9).toFixed(2)} GB`;
}

function stopTimer() {
  if (state.timer) clearInterval(state.timer);
  state.timer = null;
}

function every(ms, fn) {
  stopTimer();
  state.timer = setInterval(() => { if (!document.hidden) fn(); }, ms);
}

function field(label, input, hint) {
  return h('label', { class: 'field' }, label, hint ? h('span', { class: 'hint', text: hint }) : null, input);
}

function show(el, message) {
  el.textContent = message || '';
  el.hidden = !message;
}

// Two-step buttons instead of confirm() dialogs: the first click arms, the second acts.
function armed(label, confirmLabel, action, cls = 'danger small') {
  const b = h('button', { class: cls, type: 'button', text: label });
  let t = null;
  b.addEventListener('click', async () => {
    if (!b.classList.contains('armed')) {
      b.classList.add('armed');
      b.textContent = confirmLabel;
      t = setTimeout(() => { b.classList.remove('armed'); b.textContent = label; }, 4000);
      return;
    }
    clearTimeout(t);
    b.disabled = true;
    await action();
  });
  return b;
}

// ---- sign-in, and the password change a one-time password requires

function gate(title, lead, ...content) {
  stopTimer();
  const brand = svg(MARK);
  brand.style.color = 'var(--brand)';
  app.replaceChildren(h('div', { class: 'gate' },
    h('div', { class: 'gate-panel' }, brand, h('h1', { text: title }), h('p', { class: 'lead', text: lead }), ...content)));
}

function showSignIn(note) {
  const user = h('input', { type: 'text', name: 'username', autocomplete: 'username', required: true, autocapitalize: 'none', spellcheck: 'false' });
  const pass = h('input', { type: 'password', name: 'password', autocomplete: 'current-password', required: true });
  const err = h('div', { class: 'error', role: 'alert', hidden: true });
  const go = h('button', { class: 'primary', type: 'submit', text: 'Sign in' });
  const form = h('form', { class: 'stack' }, field('User ID', user), field('Password', pass), err, go);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    go.disabled = true;
    show(err, '');
    const res = await api('POST', '/api/v1/sign-in', { user_id: user.value.trim(), password: pass.value, client: 'web' });
    go.disabled = false;
    if (res.status !== 200) {
      show(err, errorText(res));
      pass.value = '';
      pass.focus();
      return;
    }
    await boot();
  });
  gate('Synod Manager', 'Sign in with your user ID and password.', note ? h('div', { class: 'notice', text: note }) : null, form);
  if (note) form.style.marginTop = '14px';
  user.focus();
}

function passwordForm(onDone, { forced }) {
  const cur = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const np = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: '15' });
  const again = h('input', { type: 'password', autocomplete: 'new-password', required: true });
  const err = h('div', { class: 'error', role: 'alert', hidden: true });
  const ok = h('div', { class: 'notice', role: 'status', hidden: true });
  const go = h('button', { class: 'primary', type: 'submit', text: 'Save password' });
  const form = h('form', { class: 'stack' },
    field(forced ? 'One-time password' : 'Current password', cur),
    field('New password', np, 'At least 15 characters. A few unrelated words are easy to remember and hard to guess.'),
    field('New password again', again),
    err, ok, go);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    show(err, ''); show(ok, '');
    if (np.value !== again.value) { show(err, 'The two new passwords are different.'); again.focus(); return; }
    go.disabled = true;
    const res = await api('POST', '/api/v1/me/password', { current_password: cur.value, new_password: np.value });
    go.disabled = false;
    if (res.status !== 200) { show(err, errorText(res)); return; }
    cur.value = np.value = again.value = '';
    onDone(ok);
  });
  return form;
}

function showForcedChange() {
  const form = passwordForm(async () => { await boot(); }, { forced: true });
  gate('Choose your password', `${state.me.user.name || state.me.user.user_id}, you signed in with a one-time password. Choose your own to continue.`, form);
  form.querySelector('input').focus();
}

// ---- the signed-in shell

const PAGES = [
  { id: 'fleet', title: 'Fleet', render: renderFleet },
  { id: 'sessions', title: 'Sessions', render: renderSessions },
  { id: 'events', title: 'Events', render: renderEvents },
  { id: 'users', title: 'Users', render: renderUsers, admin: true },
  { id: 'backups', title: 'Backups', render: renderBackups, admin: true },
  { id: 'account', title: 'Your account', render: renderAccount },
];

function isAdmin() { return state.me && state.me.user.role === 'admin'; }

function shell(page) {
  const brand = h('div', { class: 'brand' }, svg(MARK), 'Synod Manager');
  brand.firstChild.style.color = 'var(--brand)';
  const nav = h('nav', { 'aria-label': 'Pages' },
    PAGES.filter(p => !p.admin || isAdmin()).map(p =>
      h('a', { href: `#${p.id}`, 'aria-current': p.id === page.id ? 'page' : null, text: p.title })));
  const u = state.me.user;
  const who = h('div', { class: 'who' }, h('strong', { text: u.name || u.user_id }), `${u.user_id}, ${u.role === 'admin' ? 'Admin' : 'Viewer'}`);
  const main = h('main', { id: 'main' });
  app.replaceChildren(h('div', { class: 'shell' }, h('aside', { class: 'rail' }, brand, nav, who), main));
  document.title = `${page.title} · Synod Manager`;
  return main;
}

function route() {
  if (!state.me) return;
  // #page, or #page/a/b for a page's own parameters (Sessions: #sessions/installation/cluster/name)
  const [id, ...params] = (location.hash || '#fleet').slice(1).split('/').map(decodeURIComponent);
  const page = PAGES.find(p => p.id === id && (!p.admin || isAdmin())) || PAGES[0];
  stopTimer();
  closeDialog();
  const main = shell(page);
  page.render(main, params);
}

function head(title, sub, ...tools) {
  return h('div', { class: 'page-head' },
    h('div', {}, h('h1', { text: title }), sub ? h('p', { class: 'sub', text: sub }) : null),
    tools.length ? h('div', { class: 'toolbar' }, ...tools) : null);
}

// ---- Fleet: every installation, its clusters and their writers, its hosts

function seatClass(w) {
  if (!w) return 'bad';
  if (w.state === 'running') return '';
  if (['starting', 'restarting', 'moving', 'stopping'].includes(w.state)) return 'warn';
  return 'bad';
}

function restoreAge(s) {
  if (s === null || s === undefined) return h('span', { class: 'muted', text: 'none yet' });
  const cls = s < 180 ? 'ok' : s < 900 ? 'warn' : 'bad';
  return h('span', { class: `age ${cls}`, text: ago(s) });
}

function installationTrouble(inst) {
  const problems = [...(inst.errors || [])];
  for (const c of inst.clusters || []) {
    for (const s of c.slots || []) {
      if (s.held) continue;   // stopped by an operator: shown on its seat, not a problem
      if (!s.writer) problems.push(`${s.slot} has no writer`);
      else if (s.writer.state !== 'running') problems.push(`${s.slot} is ${s.writer.state}`);
    }
  }
  for (const d of inst.databases || []) {
    if (!d.held && !d.writer && !d.busy) problems.push(`database ${d.name} has no writer`);
  }
  for (const host of inst.hosts || []) {
    if (host.heartbeat_age_s > 15) problems.push(`host ${host.host_id} last heard from ${ago(host.heartbeat_age_s)}`);
  }
  return problems;
}

function sessionsLink(inst, kind, name) {
  return h('a', { href: `#sessions/${encodeURIComponent(inst)}/${kind}/${encodeURIComponent(name)}`, text: 'Sessions' });
}

function clusterTable(inst) {
  const admin = isAdmin();
  const rows = (inst.clusters || []).map(c => {
    const seats = h('div', { class: 'seats' }, (c.slots || []).map(s => {
      const w = s.writer;
      const letter = s.slot.slice(c.name.length + 1) || s.slot;
      const held = !!s.held;
      const cls = held ? 'held' : seatClass(w);
      const title = held ? `${s.slot}: stopped by an operator (${s.held})`
        : w ? `${s.slot}: ${w.compute_id} on ${w.host}, ${w.state}` : `${s.slot}: no writer`;
      const kids = [
        h('span', { class: 'slot', text: letter }),
        h('span', { class: 'host', text: w ? w.host : held ? 'stopped' : 'no writer' }),
        h('span', { class: 'state', text: held ? 'by an operator' : w ? w.state : '' })];
      // an Admin opens the writer's actions from its seat
      return admin
        ? h('button', { type: 'button', class: `seat ${cls}`, title: `${title}. Restart, stop or start it.`, 'aria-label': `Writer ${letter} of ${c.name}: ${held ? 'stopped' : w ? w.state : 'no writer'}. Actions`,
            onclick: () => writerDialog(inst, c, s, letter) }, ...kids)
        : h('div', { class: `seat ${cls}`, title }, ...kids);
    }));
    const mode = [c.membership, c.on_writer_failure ? `on failure: ${c.on_writer_failure}` : null].filter(Boolean).join(', ');
    const anyHeld = (c.slots || []).some(s => s.held);
    const anyRunning = (c.slots || []).some(s => !s.held && s.writer);
    const acts = h('td', { class: 'row-actions' }, sessionsLink(inst.installation, 'cluster', c.name));
    if (admin) {
      if (anyRunning) acts.append(h('button', { type: 'button', class: 'small', text: 'Rolling restart', onclick: () => clusterDialog(inst, c, 'restart') }));
      if (anyHeld || !anyRunning) acts.append(h('button', { type: 'button', class: 'small', text: 'Start', onclick: () => clusterDialog(inst, c, 'start') }));
      if (anyRunning) acts.append(h('button', { type: 'button', class: 'small danger', text: 'Stop', onclick: () => clusterDialog(inst, c, 'stop') }));
    }
    return h('tr', {},
      h('td', { class: 'name', text: c.name }),
      h('td', {}, seats),
      h('td', {}, restoreAge(c.restore_point_age_s)),
      h('td', { class: 'muted', text: mode }),
      acts);
  });
  if (!rows.length) return h('p', { class: 'muted', text: inst.errors && inst.errors.length ? 'No clusters shown: the control plane did not answer.' : 'No clusters in this installation yet.' });
  return h('div', { class: 'table-wrap' }, h('table', { class: 'clusters' },
    h('thead', {}, h('tr', {}, h('th', { text: 'Cluster' }), h('th', { text: 'Writers' }), h('th', { text: 'Last restore point' }), h('th', { text: 'Membership' }), h('th', { text: '' }))),
    h('tbody', {}, rows)));
}

function databaseTable(inst) {
  const dbs = inst.databases || [];
  if (!dbs.length) return null;
  const admin = isAdmin();
  return [h('h3', { text: `One-writer databases (${dbs.length})` }), h('div', { class: 'table-wrap' }, h('table', { class: 'clusters' },
    h('thead', {}, h('tr', {}, h('th', { text: 'Database' }), h('th', { text: 'Writer' }), h('th', { text: 'Replicas' }), h('th', { text: 'Home' }), h('th', { text: '' }))),
    h('tbody', {}, dbs.map(d => {
      const w = d.writer;
      const st = d.held ? h('span', { class: 'pill', title: d.held, text: 'Stopped by an operator' })
        : w ? h('span', {}, h('strong', { text: w.host }), h('span', { class: 'muted', text: ` ${w.address || ''}` }))
        : h('span', { class: 'pill bad', text: d.busy ? 'Starting' : 'No writer' });
      const acts = h('td', { class: 'row-actions' }, sessionsLink(inst.installation, 'database', d.name));
      if (admin) {
        if (w && !d.held) acts.append(h('button', { type: 'button', class: 'small', text: 'Restart', onclick: () => databaseDialog(inst, d, 'restart') }));
        if (d.held || !w) acts.append(h('button', { type: 'button', class: 'small', text: 'Start', onclick: () => databaseDialog(inst, d, 'start') }));
        // the manager's own repository: stopping it would stop the manager
        if (w && !d.held && !d.repository) acts.append(h('button', { type: 'button', class: 'small danger', text: 'Stop', onclick: () => databaseDialog(inst, d, 'stop') }));
      }
      return h('tr', {},
        h('td', { class: 'name' }, d.name, d.repository ? h('span', { class: 'muted repo', text: ' this manager\'s repository' }) : null),
        h('td', {}, st),
        h('td', { text: d.replicas === undefined ? '' : String(d.replicas) }),
        h('td', { class: 'muted', text: d.home_host || '' }),
        acts);
    }))))];
}

// ---- actions: one dialog says what will happen, asks for the confirmation the API needs,
// runs the action and shows how it went

function closeDialog() {
  const d = document.getElementById('action-dialog');
  if (d) { if (d.open) d.close(); d.remove(); }
}

const VERB = { stop: 'Stop', start: 'Start', restart: 'Restart' };
const DOING = { stop: 'Stopping', start: 'Starting', restart: 'Restarting' };

function actionDialog({ title, impact, confirmName, needsReason, verb, path, onDone, danger }) {
  closeDialog();
  const typed = confirmName ? h('input', { type: 'text', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', required: true }) : null;
  const reason = h('input', { type: 'text', maxlength: '200', required: needsReason || null, placeholder: needsReason ? 'Why, for the events and the audit log' : 'Optional' });
  const err = h('div', { class: 'error', role: 'alert', hidden: true });
  const status = h('div', { class: 'notice', role: 'status', hidden: true });
  const cancel = h('button', { type: 'button', text: 'Cancel', onclick: closeDialog });
  const go = h('button', { type: 'submit', class: danger ? 'primary danger-fill' : 'primary', text: title.split(' ')[0] === 'Rolling' ? 'Restart' : VERB[verb] });
  const form = h('form', { class: 'stack', method: 'dialog' },
    h('h2', { text: title }),
    h('div', { class: 'impact' }, ...impact.map(p => h('p', { text: p }))),
    typed ? field(`Type ${confirmName} to confirm`, typed) : null,
    field('Reason', reason, needsReason ? 'Required to stop.' : null),
    err, status,
    h('div', { class: 'dialog-buttons' }, cancel, go));
  const dlg = h('dialog', { id: 'action-dialog', class: 'action-dialog', 'aria-label': title }, form);
  // Escape doesn't close it while the action runs: its answer would be lost
  let running = false;
  dlg.addEventListener('cancel', (e) => { if (running) e.preventDefault(); });
  if (typed) {
    const check = () => { go.disabled = typed.value.trim() !== confirmName; };
    typed.addEventListener('input', check);
    check();
  }
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    show(err, '');
    if (needsReason && !reason.value.trim()) { show(err, 'Give a reason.'); reason.focus(); return; }
    go.disabled = true; cancel.disabled = true;
    if (typed) typed.disabled = true;
    reason.disabled = true;
    running = true;
    const t0 = Date.now();
    show(status, `${DOING[verb]}… this takes a few seconds, longer for a whole cluster.`);
    const tick = setInterval(() => show(status, `${DOING[verb]}… ${Math.round((Date.now() - t0) / 1000)} s`), 1000);
    const body = { reason: reason.value.trim() || undefined };
    if (confirmName) body.confirm = typed.value.trim();
    const res = await api('POST', path, body);
    clearInterval(tick);
    running = false;
    cancel.disabled = false;
    cancel.textContent = 'Close';
    if (res.status !== 200) { show(status, ''); show(err, errorText(res)); return; }
    show(status, outcome(verb, res.data, (Date.now() - t0) / 1000));
    go.hidden = true;
    if (onDone) onDone(res.data);
  });
  document.body.append(dlg);
  dlg.addEventListener('close', () => dlg.remove());
  dlg.showModal();
  (typed || reason).focus();
}

function outcome(verb, d, secs) {
  const took = `${(d.took_s || secs).toFixed(1)} s`;
  if (d.slots) {
    const done = d.slots.filter(s => !s.skipped && !s.error).map(s => s.slot);
    return `${VERB[verb]} done in ${took}: ${done.length ? `writers ${done.join(', ')}` : 'nothing to do'}.`;
  }
  if (d.already_running) return `Already running: ${d.writer} on ${d.host}.`;
  if (verb === 'stop') return `Stopped in ${took}${d.clean_shutdown === false ? ' (its host did not confirm the shutdown; its storage was fenced)' : ''}. It stays stopped until someone starts it.`;
  const w = d.writer ? ` ${d.writer} on ${d.host}` : '';
  const back = d.writable_after_s ? `, writable after ${d.writable_after_s.toFixed(1)} s` : '';
  return `${VERB[verb]} done in ${took}:${w}${back}.`;
}

function refreshSoon() {
  // the manager refreshes its copy right after an action; the page picks it up
  setTimeout(() => { if ((location.hash || '#fleet').startsWith('#fleet')) route(); }, 1500);
}

function writerDialog(inst, c, s, letter) {
  const peers = (c.slots || []).length;
  const name = s.slot;
  const base = `/api/v1/installations/${encodeURIComponent(inst.installation)}/clusters/${encodeURIComponent(c.name)}/slots/${encodeURIComponent(letter)}`;
  const choose = (verb) => {
    const impact = {
      restart: [`Writer ${letter} shuts down and a new one starts on the same host, then rejoins the other writers. Its clients are disconnected and can reconnect to the other writers at once.`,
        peers > 1 ? 'The other writers keep committing throughout.' : 'This cluster has one writer: it is closed for those seconds.'],
      stop: [`Writer ${letter} shuts down and stays down until someone starts it. The control plane won't restart it or fail it over.`,
        peers > 1 ? 'The other writers take over its blocks within about a second and keep committing; its clients reconnect to them. Restore points wait until every writer runs again.' : 'This cluster has one writer: it is closed until started.'],
      start: [`Starts writer ${letter} on its host and waits until it has rejoined the other writers.`],
    }[verb];
    actionDialog({ title: `${VERB[verb]} writer ${letter} of ${c.name}`, impact, verb, path: `${base}/${verb}`,
      confirmName: verb === 'start' ? null : name, needsReason: verb === 'stop', danger: verb === 'stop', onDone: refreshSoon });
  };
  if (s.held || !s.writer) return choose('start');
  // a running writer: restart (the usual) or stop
  closeDialog();
  const dlg = h('dialog', { id: 'action-dialog', class: 'action-dialog', 'aria-label': `Writer ${letter} of ${c.name}` },
    h('div', { class: 'stack' },
      h('h2', { text: `Writer ${letter} of ${c.name}` }),
      h('p', { class: 'muted', text: `${s.writer.compute_id} on ${s.writer.host}, ${s.writer.state}.` }),
      h('div', { class: 'dialog-buttons' },
        h('button', { type: 'button', text: 'Cancel', onclick: closeDialog }),
        h('a', { class: 'button-link', href: `#sessions/${encodeURIComponent(inst.installation)}/cluster/${encodeURIComponent(c.name)}`, text: 'Sessions', onclick: closeDialog }),
        h('button', { type: 'button', class: 'danger', text: 'Stop…', onclick: () => choose('stop') }),
        h('button', { type: 'button', class: 'primary', text: 'Restart…', onclick: () => choose('restart') }))));
  document.body.append(dlg);
  dlg.addEventListener('close', () => dlg.remove());
  dlg.showModal();
}

function clusterDialog(inst, c, verb) {
  const n = (c.slots || []).length;
  const impact = {
    restart: [`Each of the ${n} writers in turn shuts down, starts again on its host and rejoins the others before the next one goes.`,
      n > 1 ? 'The cluster keeps committing throughout; each writer\'s clients are disconnected once and can reconnect to the other writers.' : 'This cluster has one writer: it is closed for a few seconds.'],
    stop: ['Every writer shuts down at once and the cluster is closed until someone starts it. Clients can\'t connect meanwhile.',
      'The control plane won\'t restart the writers or fail them over.'],
    start: ['Starts every stopped writer at once, each on its host.'],
  }[verb];
  actionDialog({ title: verb === 'restart' ? `Rolling restart of ${c.name}` : `${VERB[verb]} cluster ${c.name}`, impact, verb,
    path: `/api/v1/installations/${encodeURIComponent(inst.installation)}/clusters/${encodeURIComponent(c.name)}/${verb}`,
    confirmName: verb === 'start' ? null : c.name, needsReason: verb === 'stop', danger: verb === 'stop', onDone: refreshSoon });
}

function databaseDialog(inst, d, verb) {
  const reps = d.replicas ? ` and its ${d.replicas === 1 ? 'replica' : `${d.replicas} replicas`}` : '';
  const impact = {
    restart: ['Its writer shuts down and a new one starts on the same host. Clients are disconnected and can reconnect within a few seconds. Nothing committed is lost.'],
    stop: [`Its writer${reps} shut down and stay down until someone starts it. Clients can't connect meanwhile.`, 'The control plane won\'t restart it or fail it over.'],
    start: [`Starts its writer${d.home_host ? ` on ${d.home_host}, its home host,` : ''} when that host is up.${d.replicas ? ' Replicas follow.' : ''}`],
  }[verb];
  actionDialog({ title: `${VERB[verb]} database ${d.name}`, impact, verb,
    path: `/api/v1/installations/${encodeURIComponent(inst.installation)}/databases/${encodeURIComponent(d.name)}/${verb}`,
    confirmName: verb === 'start' ? null : d.name, needsReason: verb === 'stop', danger: verb === 'stop', onDone: refreshSoon });
}

function hostList(inst) {
  const hosts = inst.hosts || [];
  if (!hosts.length) return null;
  return [h('h3', { text: `Hosts (${hosts.length})` }), h('ul', { class: 'hosts' }, hosts.map(host => {
    const age = host.heartbeat_age_s;
    const cls = age > 15 ? 'bad' : age > 5 ? 'warn' : '';
    const n = (host.computes || []).length;
    return h('li', { class: cls, title: `heartbeat ${ago(age)}` },
      h('strong', { text: host.host_id }), ` ${host.address}, ${n} ${n === 1 ? 'writer' : 'writers'}, heard from ${ago(age)}`);
  }))];
}

function installationPanel(inst) {
  const cp = inst.control_plane;
  const meta = [];
  if (cp) meta.push(`Control plane ${cp.instance || ''} leads${cp.leader_for_s ? ` (for ${duration(cp.leader_for_s)})` : ''}, version ${cp.version}`);
  if (inst.age_s !== undefined) meta.push(`read ${ago(inst.age_s)}`);
  const problems = installationTrouble(inst);
  return h('section', { class: 'panel', 'data-installation': inst.installation },
    h('div', { class: 'inst-head' }, h('h2', { text: inst.installation }), h('span', { class: 'meta', text: meta.join('; ') })),
    problems.length ? h('ul', { class: 'inst-problems' }, problems.slice(0, 6).map(p => h('li', { text: p })),
      problems.length > 6 ? h('li', { text: `and ${problems.length - 6} more` }) : null) : null,
    clusterTable(inst),
    databaseTable(inst),
    hostList(inst));
}

function renderFleet(main) {
  const filter = h('input', { type: 'text', placeholder: 'Find an installation or cluster', 'aria-label': 'Find an installation or cluster' });
  const fresh = h('span', { class: 'fresh' });
  const summary = h('p', { class: 'headline' });
  const list = h('div', {});
  main.append(head('Fleet', 'Every installation this manager watches, its clusters and their writers.', filter, fresh), summary, list);
  let data = [];

  function draw() {
    const q = filter.value.trim().toLowerCase();
    const shown = data.filter(i => !q || i.installation.toLowerCase().includes(q) || (i.clusters || []).some(c => c.name.toLowerCase().includes(q)));
    // installations that need attention first, then by name
    shown.sort((a, b) => (installationTrouble(b).length > 0) - (installationTrouble(a).length > 0) || a.installation.localeCompare(b.installation));
    list.replaceChildren(...(shown.length ? shown.map(installationPanel)
      : [h('div', { class: 'panel' }, h('p', { class: 'muted', text: data.length ? 'Nothing matches.' : 'No installations yet. An admin adds one with synod-install or POST /api/v1/installations.' }))]));
  }

  async function load() {
    const res = await api('GET', '/api/v1/fleet');
    if (res.status !== 200) { summary.replaceChildren(h('span', { class: 'bad', text: errorText(res) })); return; }
    data = res.data;
    let clusters = 0, writers = 0, running = 0, hosts = 0;
    const trouble = data.filter(i => installationTrouble(i).length).length;
    for (const i of data) {
      hosts += (i.hosts || []).length;
      for (const c of i.clusters || []) {
        clusters += 1;
        for (const s of c.slots || []) { writers += 1; if (s.writer && s.writer.state === 'running') running += 1; }
      }
    }
    const n = (k, one, many) => `${k} ${k === 1 ? one : many}`;
    summary.replaceChildren(
      `${n(data.length, 'installation', 'installations')}, ${n(clusters, 'cluster', 'clusters')}, ${running} of ${n(writers, 'writer', 'writers')} running, ${n(hosts, 'host', 'hosts')}. `,
      trouble ? h('span', { class: 'bad', text: `${n(trouble, 'installation needs', 'installations need')} attention.` }) : 'Nothing needs attention.');
    fresh.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    draw();
  }
  filter.addEventListener('input', draw);
  load();
  every(10000, load);
}

// ---- Sessions: every writer's sessions in one list (Oracle's GV$SESSION), live

function age(s) {
  if (s === null || s === undefined) return '';
  if (s < 1) return '<1 s';
  return duration(s);
}

function renderSessions(main, params) {
  const pick = h('select', { class: 'target', 'aria-label': 'Cluster or database' });
  const text = h('input', { type: 'text', placeholder: 'User, application, client or query', 'aria-label': 'Filter sessions' });
  const activeOnly = h('input', { type: 'checkbox' });
  const system = h('input', { type: 'checkbox' });
  const pause = h('button', { type: 'button', class: 'small', text: 'Pause' });
  const fresh = h('span', { class: 'fresh' });
  const out = h('div', {});
  const summary = h('p', { class: 'headline' });
  const writers = h('ul', { class: 'inst-problems' });
  const body = h('tbody', {});
  main.append(head('Sessions', 'Every writer\'s sessions in one list, refreshed every 5 s.', pick, text,
      h('label', { class: 'check' }, activeOnly, 'Active only'), h('label', { class: 'check' }, system, 'System sessions'), pause, fresh),
    out, summary, writers,
    h('div', { class: 'panel flush' }, h('div', { class: 'table-wrap' }, h('table', { class: 'list sessions' },
      h('thead', {}, h('tr', {}, ['Writer', 'PID', 'Application', 'Client', 'State', 'Transaction', 'Waiting on', 'Query', ''].map(t => h('th', { text: t })))),
      body))));
  let data = null;
  let paused = false;
  const target = () => { const [i, k, n] = (pick.value || '').split('/'); return i ? { inst: i, kind: k, name: n } : null; };

  async function fillTargets() {
    const res = await api('GET', '/api/v1/fleet');
    if (res.status !== 200) { out.replaceChildren(h('div', { class: 'error', text: errorText(res) })); return; }
    const opts = [];
    for (const i of res.data) {
      const g = h('optgroup', { label: i.installation });
      for (const c of i.clusters || []) g.append(h('option', { value: `${i.installation}/cluster/${c.name}`, text: `${c.name} (cluster, ${(c.slots || []).length} writers)` }));
      for (const d of i.databases || []) g.append(h('option', { value: `${i.installation}/database/${d.name}`, text: `${d.name} (database)` }));
      if (g.children.length) opts.push(g);
    }
    if (!opts.length) { pick.replaceChildren(h('option', { value: '', text: 'No clusters or databases' })); return; }
    pick.replaceChildren(...opts);
    const want = params && params.length === 3 ? params.join('/') : '';
    if (want && [...pick.options].some(o => o.value === want)) pick.value = want;
  }

  function draw() {
    if (!data) return;
    const q = text.value.trim().toLowerCase();
    const t = target();
    const rows = data.sessions.filter(x => (system.checked || !x.internal)
      && (!activeOnly.checked || (x.state && x.state !== 'idle'))
      && (!q || [x.user, x.application, x.client, x.query, x.database].some(v => v && String(v).toLowerCase().includes(q))));
    const all = data.sessions.filter(x => !x.internal);
    const active = all.filter(x => x.state === 'active').length;
    const waiting = all.filter(x => x.state === 'active' && x.wait_event_type && x.wait_event_type !== 'Activity').length;
    const longIdle = all.filter(x => x.state && x.state.startsWith('idle in transaction') && x.state_age_s > 60).length;
    const nw = data.writers.filter(w => !w.error).length;
    summary.replaceChildren(`${all.length} client sessions on ${nw} ${nw === 1 ? 'writer' : 'writers'}: ${active} active, ${waiting} waiting. `,
      longIdle ? h('span', { class: 'bad', text: `${longIdle} idle in a transaction for over a minute.` }) : '');
    writers.replaceChildren(...data.writers.filter(w => w.error).map(w => h('li', { text: `${w.slot ? `Writer ${w.slot}` : w.database}: ${w.error}` })));
    const admin = isAdmin();
    body.replaceChildren(...(rows.length ? rows.map(x => {
      const enc = encodeURIComponent;
      const base = t.kind === 'cluster'
        ? `/api/v1/installations/${enc(t.inst)}/clusters/${enc(t.name)}/sessions/${enc(x.slot)}/${x.pid}`
        : `/api/v1/installations/${enc(t.inst)}/databases/${enc(t.name)}/sessions/${x.pid}`;
      const acts = h('td', { class: 'actions' });
      if (admin && !x.internal) {
        const run = (what) => async () => {
          const res = await api('POST', `${base}/${what}`, {});
          out.replaceChildren(res.status === 200
            ? h('div', { class: 'notice', role: 'status', text: res.data.done ? `${what === 'cancel' ? 'Query cancelled' : 'Session ended'}: ${x.application || 'unnamed'} (user ${x.user}), PID ${x.pid} on ${x.slot ? `writer ${x.slot}` : 'the writer'}.` : `Asked; session ${x.pid} had not ended within 5 s.` })
            : h('div', { class: 'error', role: 'alert', text: errorText(res) }));
          load();
        };
        if (x.state === 'active') acts.append(armed('Cancel query', 'Confirm cancel', run('cancel'), 'small'));
        acts.append(armed('End session', 'Confirm end', run('terminate')));
      }
      const idleTx = x.state && x.state.startsWith('idle in transaction');
      const xcls = x.xact_age_s > 60 ? 'warn' : '';
      const inState = x.state === 'active' ? x.query_age_s : x.state_age_s;
      return h('tr', { class: x.internal ? 'internal' : null },
        h('td', { class: 'nowrap', text: x.slot || '' }),
        h('td', { class: 'id', text: String(x.pid) }),
        h('td', {}, h('span', { class: 'app', text: x.application || (x.internal ? x.backend_type : '') || 'unnamed' }), h('br'), h('span', { class: 'muted', text: x.user || '' })),
        h('td', { class: 'id', text: x.client || 'local' }),
        h('td', {}, h('span', { class: `pill ${x.state === 'active' ? 'ok' : idleTx ? 'warn' : ''}`, text: x.state || x.backend_type || '' }),
          inState !== null && inState !== undefined ? [h('br'), h('span', { class: 'muted', text: `for ${age(inState)}` })] : null),
        h('td', { class: `age ${xcls}`, text: age(x.xact_age_s) }),
        // what an active session waits on; an idle one always "waits" for its client
        h('td', { class: 'muted', text: x.state === 'active' && x.wait_event ? `${x.wait_event_type}: ${x.wait_event}` : '' }),
        h('td', { class: 'query', title: x.query || '', text: x.query || '' }),
        acts);
    }) : [h('tr', {}, h('td', { colspan: '9', class: 'muted', text: data.sessions.length ? 'No session matches.' : 'No sessions.' }))]));
  }

  async function load() {
    const t = target();
    if (!t || paused) return;
    const path = t.kind === 'cluster'
      ? `/api/v1/installations/${encodeURIComponent(t.inst)}/clusters/${encodeURIComponent(t.name)}/sessions?all=${system.checked}`
      : `/api/v1/installations/${encodeURIComponent(t.inst)}/databases/${encodeURIComponent(t.name)}/sessions?all=${system.checked}`;
    const res = await api('GET', path);
    if (res.status !== 200) { summary.replaceChildren(h('span', { class: 'bad', text: errorText(res) })); body.replaceChildren(); data = null; return; }
    data = res.data;
    fresh.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    draw();
  }

  pick.addEventListener('change', () => {
    history.replaceState(null, '', `#sessions/${pick.value.split('/').map(encodeURIComponent).join('/')}`);
    out.replaceChildren();
    load();
  });
  text.addEventListener('input', draw);
  activeOnly.addEventListener('change', draw);
  system.addEventListener('change', load);
  pause.addEventListener('click', () => { paused = !paused; pause.textContent = paused ? 'Resume' : 'Pause'; if (!paused) load(); });
  fillTargets().then(load);
  every(5000, load);
}

// ---- Events: one timeline across installations

async function installations() {
  if (state.installations) return state.installations;
  const res = await api('GET', '/api/v1/installations');
  state.installations = res.status === 200 ? res.data : [];
  return state.installations;
}

function renderEvents(main) {
  const inst = h('select', { 'aria-label': 'Installation' }, h('option', { value: '', text: 'All installations' }));
  const cluster = h('input', { type: 'text', placeholder: 'Cluster or database', 'aria-label': 'Cluster or database' });
  const fresh = h('span', { class: 'fresh' });
  const body = h('tbody', {});
  main.append(head('Events', 'Failovers, moves, restore points and setting changes, newest first. Copied from every control plane every 5 s.', inst, cluster, fresh),
    h('div', { class: 'panel flush' }, h('div', { class: 'table-wrap' }, h('table', { class: 'list' },
      h('thead', {}, h('tr', {}, h('th', { text: 'When' }), h('th', { text: 'Installation' }), h('th', { text: 'Database' }), h('th', { text: 'What' }), h('th', { text: 'Detail' }))),
      body))));
  installations().then(list => { for (const i of list) inst.append(h('option', { value: i.name, text: i.name })); });

  async function load() {
    const p = new URLSearchParams({ limit: '200' });
    if (inst.value) p.set('installation', inst.value);
    if (cluster.value.trim()) p.set('cluster', cluster.value.trim());
    const res = await api('GET', `/api/v1/events?${p}`);
    if (res.status !== 200) { body.replaceChildren(h('tr', {}, h('td', { colspan: '5', class: 'error', text: errorText(res) }))); return; }
    body.replaceChildren(...(res.data.length ? res.data.map(e => h('tr', {},
      h('td', { class: 'nowrap', title: when(e.at), text: ago(since(e.at)) }),
      h('td', { text: e.installation }),
      h('td', { class: 'id', text: e.database || '' }),
      h('td', { text: e.kind.replaceAll('_', ' ') }),
      h('td', { class: 'detail', text: e.detail }))) : [h('tr', {}, h('td', { colspan: '5', class: 'muted', text: 'No events match.' }))]));
    fresh.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  }
  inst.addEventListener('change', load);
  let t = null;
  cluster.addEventListener('input', () => { clearTimeout(t); t = setTimeout(load, 300); });
  load();
  every(5000, load);
}

// ---- Users (admins): add people, reset passwords, unlock, disable

function userState(u) {
  if (u.disabled) return h('span', { class: 'pill bad', text: 'Disabled' });
  if (u.locked_until && Date.parse(u.locked_until) > Date.now()) return h('span', { class: 'pill warn', text: `Paused until ${new Date(u.locked_until).toLocaleTimeString()}` });
  if (u.must_change) return h('span', { class: 'pill warn', text: 'Must choose a password' });
  return h('span', { class: 'pill ok', text: 'Active' });
}

function secretNotice(title, who, pw, note) {
  const copy = h('button', { class: 'small', type: 'button', text: 'Copy' });
  copy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(pw); copy.textContent = 'Copied'; } catch (e) { copy.textContent = 'Select and copy it'; }
  });
  return h('div', { class: 'notice', role: 'status' },
    h('strong', { text: title }), h('br'), `One-time password for ${who}: `, h('span', { class: 'secret', text: pw }), ' ', copy, h('br'),
    h('span', { class: 'muted', text: note }));
}

function renderUsers(main) {
  const out = h('div', {});
  const body = h('tbody', {});
  const uid = h('input', { type: 'text', required: true, autocapitalize: 'none', spellcheck: 'false' });
  const name = h('input', { type: 'text' });
  const role = h('select', {}, h('option', { value: 'viewer', text: 'Viewer: sees every page' }), h('option', { value: 'admin', text: 'Admin: also manages users and installations' }));
  const err = h('div', { class: 'error', role: 'alert', hidden: true });
  const add = h('button', { class: 'primary', type: 'submit', text: 'Add user' });
  const form = h('form', { class: 'stack' }, field('User ID', uid, 'Letters, digits, dots, dashes or underscores.'), field('Name', name), field('Role', role), err, add);
  main.append(head('Users', 'People who can sign in. Admins run every action; Viewers see every page and nothing else.'), out,
    h('div', { class: 'cols list-and-form' },
      h('div', { class: 'panel flush' }, h('div', { class: 'table-wrap' }, h('table', { class: 'list' },
        h('thead', {}, h('tr', {}, h('th', { text: 'User' }), h('th', { text: 'Role' }), h('th', { text: 'State' }), h('th', { text: 'Password set' }), h('th', { text: '' }))),
        body))),
      h('div', { class: 'panel' }, h('h2', { text: 'Add a user' }), h('p', { class: 'muted', text: 'They get a one-time password to give them; they choose their own at first sign-in.' }), form)));

  async function act(method, path, payload, done) {
    const res = await api(method, path, payload);
    if (res.status !== 200) out.replaceChildren(h('div', { class: 'error', role: 'alert', text: errorText(res) }));
    else if (done) done(res.data);
    load();
  }

  async function load() {
    const res = await api('GET', '/api/v1/users');
    if (res.status !== 200) { body.replaceChildren(h('tr', {}, h('td', { colspan: '5', class: 'error', text: errorText(res) }))); return; }
    body.replaceChildren(...res.data.map(u => {
      const me = u.user_id === state.me.user.user_id;
      const enc = encodeURIComponent(u.user_id);
      const actions = h('td', { class: 'actions' });
      if (!me) {
        actions.append(armed('Reset password', 'Confirm reset', () => act('POST', `/api/v1/users/${enc}/reset-password`, undefined,
          d => out.replaceChildren(secretNotice('Password reset.', u.user_id, d.temporary_password, d.note)))));
        if (u.locked_until && Date.parse(u.locked_until) > Date.now()) {
          actions.append(h('button', { class: 'small', type: 'button', text: 'Unlock', onclick: () => act('POST', `/api/v1/users/${enc}/unlock`) }));
        }
        actions.append(u.disabled
          ? h('button', { class: 'small', type: 'button', text: 'Enable', onclick: () => act('PATCH', `/api/v1/users/${enc}`, { disabled: false }) })
          : armed('Disable', 'Confirm disable', () => act('PATCH', `/api/v1/users/${enc}`, { disabled: true })));
      } else {
        actions.append(h('span', { class: 'muted', text: 'You' }));
      }
      return h('tr', {},
        h('td', {}, h('strong', { text: u.name || u.user_id }), h('br'), h('span', { class: 'muted id', text: u.user_id })),
        h('td', { text: u.role === 'admin' ? 'Admin' : 'Viewer' }),
        h('td', {}, userState(u)),
        h('td', { title: when(u.password_set_at), text: ago(since(u.password_set_at)) }),
        actions);
    }));
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    show(err, '');
    add.disabled = true;
    const res = await api('POST', '/api/v1/users', { user_id: uid.value.trim(), name: name.value.trim(), role: role.value });
    add.disabled = false;
    if (res.status !== 200) { show(err, errorText(res)); return; }
    out.replaceChildren(secretNotice('User added.', res.data.user_id, res.data.temporary_password, res.data.note));
    uid.value = name.value = '';
    load();
  });
  load();
}

// ---- Backups (admins)

function renderBackups(main) {
  const out = h('div', {});
  const facts = h('dl', { class: 'facts' });
  const body = h('tbody', {});
  const now = h('button', { class: 'primary', type: 'button', text: 'Back up now' });
  main.append(head('Backups', 'Each manager machine backs itself up every night: its repository, its metrics and its key file, in one encrypted file.', now), out,
    h('div', { class: 'cols' },
      h('div', { class: 'panel' }, h('h2', { text: 'On this machine' }), facts),
      h('div', { class: 'panel flush' }, h('div', { class: 'table-wrap' }, h('table', { class: 'list' },
        h('thead', {}, h('tr', {}, h('th', { text: 'Made' }), h('th', { text: 'Size' }), h('th', { text: 'File' }))), body)))));

  async function load() {
    const res = await api('GET', '/api/v1/backups');
    if (res.status !== 200) { out.replaceChildren(h('div', { class: 'error', text: errorText(res) })); return null; }
    const b = res.data;
    facts.replaceChildren(
      h('dt', { text: 'Directory' }), h('dd', { class: 'id', text: b.dir || 'not set: no nightly backups' }),
      h('dt', { text: 'Every night at' }), h('dd', { text: `${b.at} (this machine's time)` }),
      h('dt', { text: 'Kept' }), h('dd', { text: `${b.keep_days} days` }),
      h('dt', { text: 'Metrics included' }), h('dd', { text: b.metrics ? 'Yes' : 'No' }),
      h('dt', { text: 'Backup key' }), h('dd', {}, b.key_set ? h('span', { class: 'pill ok', text: 'Set' }) : h('span', { class: 'pill bad', text: 'Missing: backups fail' })));
    body.replaceChildren(...(b.backups.length ? b.backups.map(x => h('tr', {},
      h('td', { class: 'nowrap', title: when(x.at), text: ago(since(x.at)) }), h('td', { class: 'nowrap', text: bytes(x.bytes) }), h('td', { class: 'id', text: x.name })))
      : [h('tr', {}, h('td', { colspan: '3', class: 'muted', text: 'No backups yet.' }))]));
    now.disabled = !b.dir;
    return b.backups.length;
  }

  now.addEventListener('click', async () => {
    now.disabled = true;
    out.replaceChildren(h('div', { class: 'notice', text: 'Backing up. Large metrics stores take a few minutes.' }));
    const before = await load();
    const res = await api('POST', '/api/v1/backups');
    if (res.status !== 200) { out.replaceChildren(h('div', { class: 'error', text: errorText(res) })); now.disabled = false; return; }
    const t0 = Date.now();
    every(2000, async () => {
      const n = await load();
      if (n !== null && n > before) { stopTimer(); out.replaceChildren(h('div', { class: 'notice', text: 'Backup made.' })); now.disabled = false; }
      else if (Date.now() - t0 > 600000) { stopTimer(); out.replaceChildren(h('div', { class: 'error', text: 'No new backup after 10 minutes; the audit log has the reason.' })); now.disabled = false; }
    });
  });
  load();
}

// ---- Your account

function renderAccount(main) {
  const u = state.me.user;
  const form = passwordForm(ok => show(ok, 'Password changed. Your other sessions were signed out.'), { forced: false });
  const out = h('button', { type: 'button', text: 'Sign out' });
  out.addEventListener('click', async () => {
    await api('POST', '/api/v1/sign-out');
    state.me = null;
    history.replaceState(null, '', '#fleet');
    showSignIn('Signed out.');
  });
  main.append(head('Your account', null, out),
    h('div', { class: 'cols' },
      h('div', { class: 'panel' }, h('h2', { text: u.name || u.user_id }), h('dl', { class: 'facts' },
        h('dt', { text: 'User ID' }), h('dd', { class: 'id', text: u.user_id }),
        h('dt', { text: 'Role' }), h('dd', { text: u.role === 'admin' ? 'Admin' : 'Viewer' }),
        h('dt', { text: 'Password set' }), h('dd', { title: when(u.password_set_at), text: ago(since(u.password_set_at)) }),
        h('dt', { text: 'Account made' }), h('dd', { text: when(u.created_at) }))),
      h('div', { class: 'panel' }, h('h2', { text: 'Change your password' }), h('p', { class: 'muted', text: 'Changing it signs you out everywhere else.' }), form)));
}

// ---- start

async function boot() {
  const res = await api('GET', '/api/v1/me');
  if (res.status !== 200) { if (res.status !== 401) showSignIn(errorText(res)); else showSignIn(); return; }
  state.me = res.data;
  if (state.me.must_change_password) { showForcedChange(); return; }
  route();
}

window.addEventListener('hashchange', route);
boot();
