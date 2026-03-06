const apiBase = '/v1';
const DEMO_USER_KEY = 'aegis_demo_user';

let sessionId = null;
let userSessions = [];

function getApiKey() {
  return localStorage.getItem('aegis_api_key') || '';
}

function getDemoUser() {
  return (localStorage.getItem(DEMO_USER_KEY) || '').trim().toLowerCase();
}

function sessionStorageKeyForUser() {
  const user = getDemoUser();
  return `aegis_chat_session_${user || 'anonymous'}`;
}

function setStatus(ok, msg) {
  const el = document.getElementById('chatStatus');
  el.textContent = msg || (ok ? 'Connected' : 'Disconnected');
  el.style.color = ok ? '#065f46' : '#991b1b';
  el.style.background = ok ? '#d1fae5' : '#fee2e2';
  el.style.borderColor = ok ? '#86efac' : '#fca5a5';
}

async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  const demoUser = getDemoUser();
  if (demoUser) headers['x-demo-user'] = demoUser;
  const res = await fetch(apiBase + path, { ...options, headers });
  if (!res.ok) {
    let detail = `API ${res.status}`;
    try {
      const body = await res.json();
      if (body && typeof body.detail === 'string') detail = body.detail;
    } catch {}
    throw new Error(detail);
  }
  return res.json();
}

async function ensureSession() {
  if (sessionId) return sessionId;
  await loadUserSessions();
  if (sessionId) return sessionId;
  return createNewSession();
}

function extractConversation(events) {
  const ordered = [...(events || [])].sort((a, b) => Number(a.ts || 0) - Number(b.ts || 0));
  const groups = {};
  const sequence = [];

  const policyBlockFallback = (reason) => {
    const base = "I can't answer that request because it goes against policy. I can help with a safer alternative, like high-level guidance, defensive best practices, or a compliant version of your question.";
    const detail = String(reason || '').trim();
    return detail ? `${base} Reason: ${detail}` : base;
  };

  const policyWarnFallback = (reason) => {
    const base = "Policy warning: this request may violate policy, so the response is limited. If you want, rephrase toward safe intent and I can provide a compliant alternative.";
    const detail = String(reason || '').trim();
    return detail ? `${base} Reason: ${detail}` : base;
  };

  const outcomeOfDecision = (decision) => {
    const d = decision || {};
    if (d.blocked) return 'block';
    if (d.require_approval) return 'approval';
    if (d.warn) return 'warn';
    return 'allow';
  };

  const inferOutcome = (evs) => {
    let out = 'allow';
    for (const ev of evs || []) {
      if (!ev.decision) continue;
      const x = outcomeOfDecision(ev.decision);
      if (x === 'block') return 'block';
      if (x === 'approval') out = out === 'block' ? out : 'approval';
      else if (x === 'warn' && out === 'allow') out = 'warn';
    }
    return out;
  };

  for (let i = 0; i < ordered.length; i += 1) {
    const e = ordered[i];
    const id = e.request_id || `legacy-${i}`;
    if (!groups[id]) {
      groups[id] = { id, user: '', assistant: '', assistantDraft: '', events: [] };
      sequence.push(groups[id]);
    }
    groups[id].events.push(e);
    if (!groups[id].user && e.stage === 'prellm' && e.content) {
      groups[id].user = String(e.content);
    }
    if (e.stage === 'model' && e.output) {
      groups[id].assistantDraft = String(e.output);
    }
    if ((e.stage === 'output_firewall.transform' || e.stage === 'postllm.transform') && e.output_transformed) {
      groups[id].assistant = String(e.output_transformed);
    }
    if ((e.stage === 'postllm.response' || e.stage === 'guardrail.response') && e.output && !groups[id].assistant) {
      groups[id].assistant = String(e.output);
      groups[id].assistantDraft = String(e.output);
    }
  }
  return sequence
    .map(x => {
      const outcome = inferOutcome(x.events || []);
      const decisionEvent = (x.events || []).find(ev => {
        const d = ev.decision || {};
        return Boolean(d.blocked || d.require_approval || d.warn);
      }) || null;
      const decisionMessage = String((decisionEvent?.decision || {}).message || decisionEvent?.message || '').trim();

      let assistant = x.assistant || x.assistantDraft;
      if (!assistant && outcome === 'block') {
        assistant = policyBlockFallback(decisionMessage);
      } else if (!assistant && outcome === 'approval') {
        assistant = policyBlockFallback(decisionMessage || 'This request requires policy approval.');
      } else if (!assistant && outcome === 'warn') {
        assistant = policyWarnFallback(decisionMessage);
      }

      return {
        user: x.user,
        assistant,
      };
    })
    .filter(x => x.user || x.assistant);
}

function renderConversation(events) {
  const output = document.getElementById('chatResponse');
  const turns = extractConversation(events);
  output.innerHTML = '';
  if (!turns.length) {
    const empty = document.createElement('div');
    empty.className = 'tiny';
    empty.textContent = 'No messages yet.';
    output.appendChild(empty);
    return;
  }
  turns.forEach((turn) => {
    if (turn.user) {
      const userBox = document.createElement('div');
      userBox.className = 'chat-item user';
      userBox.innerHTML = '<div class="chat-role">User</div>';
      const userText = document.createElement('div');
      userText.className = 'chat-text';
      userText.textContent = turn.user;
      userBox.appendChild(userText);
      output.appendChild(userBox);
    }
    if (turn.assistant) {
      const aiBox = document.createElement('div');
      aiBox.className = 'chat-item assistant';
      aiBox.innerHTML = '<div class="chat-role">Assistant</div>';
      const aiText = document.createElement('div');
      aiText.className = 'chat-text';
      aiText.textContent = turn.assistant;
      aiBox.appendChild(aiText);
      output.appendChild(aiBox);
    }
  });
}

async function loadSessionTranscript(targetSessionId) {
  const sid = String(targetSessionId || '').trim();
  if (!sid) {
    renderConversation([]);
    return;
  }
  const payload = await api(`/sessions/${sid}`);
  renderConversation(payload.events || []);
}

function renderSessionOptions() {
  const select = document.getElementById('chatSessionSelect');
  if (!select) return;
  select.innerHTML = '';
  if (!userSessions.length) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'No sessions yet';
    select.appendChild(opt);
    return;
  }
  userSessions.forEach(s => {
    const opt = document.createElement('option');
    opt.value = s.id;
    const title = String(s.title || 'New Chat');
    const count = Number(s.events || 0);
    const tsReadable = String(s.timestamp_readable || '-');
    opt.textContent = `${title} • ${tsReadable} (${count} events)`;
    if (s.id === sessionId) opt.selected = true;
    select.appendChild(opt);
  });
}

async function loadUserSessions() {
  const data = await api('/sessions');
  const list = Array.isArray(data.sessions) ? data.sessions : [];
  userSessions = list.slice().sort((a, b) => {
    const tsDelta = Number(b.timestamp || 0) - Number(a.timestamp || 0);
    if (tsDelta !== 0) return tsDelta;
    return Number(b.events || 0) - Number(a.events || 0);
  });

  const stored = localStorage.getItem(sessionStorageKeyForUser());
  if (stored && userSessions.find(s => s.id === stored)) {
    sessionId = stored;
  } else if (!sessionId && userSessions.length) {
    sessionId = userSessions[0].id;
    localStorage.setItem(sessionStorageKeyForUser(), sessionId);
  }
  renderSessionOptions();
  await loadSessionTranscript(sessionId);
}

async function switchSession(nextSessionId) {
  const chosen = String(nextSessionId || '').trim();
  if (!chosen) return;
  sessionId = chosen;
  localStorage.setItem(sessionStorageKeyForUser(), sessionId);
  const state = document.getElementById('chatState');
  if (state) state.textContent = `active session: ${chosen.slice(0, 12)}…`;
  try {
    await loadSessionTranscript(chosen);
  } catch (e) {
    const output = document.getElementById('chatResponse');
    output.innerHTML = `<div class="tiny">Failed to load session transcript: ${e?.message || String(e)}</div>`;
  }
}

async function createNewSession() {
  const created = await api('/sessions', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({}),
  });
  sessionId = created.session_id;
  localStorage.setItem(sessionStorageKeyForUser(), sessionId);
  await loadUserSessions();
  renderConversation([]);
  return sessionId;
}

async function sendChatPrompt() {
  const btn = document.getElementById('chatSendBtn');
  const state = document.getElementById('chatState');
  const output = document.getElementById('chatResponse');
  const content = (document.getElementById('chatPrompt').value || '').trim();

  if (!content) {
    state.textContent = 'prompt required';
    return;
  }

  btn.disabled = true;
  state.textContent = 'sending...';
  try {
    const sid = await ensureSession();
    const res = await api(`/sessions/${sid}/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content, metadata: { source: 'chat' }, environment: 'dev' }),
    });
    state.textContent = 'done';
    setStatus(true);
    await loadUserSessions();
    await loadSessionTranscript(sid);
  } catch (e) {
    output.innerHTML = `<div class="tiny">Request failed: ${e?.message || String(e)}</div>`;
    state.textContent = 'failed';
    setStatus(false, 'Error');
  } finally {
    btn.disabled = false;
  }
}

function logoutDemoUser() {
  localStorage.removeItem(DEMO_USER_KEY);
  window.location.href = '/v1/dashboard';
}

async function boot() {
  const user = getDemoUser();
  if (!user) {
    window.location.href = '/v1/dashboard';
    return;
  }
  const userEl = document.getElementById('chatUser');
  userEl.textContent = `User: ${user}`;
  try {
    const users = await api('/demo/users');
    const role = (users.users || []).find(u => String(u.username || '').toLowerCase() === user)?.role || 'employee';
    if (String(role).toLowerCase() === 'admin') {
      window.location.href = '/v1/dashboard';
      return;
    }
    await loadUserSessions();
    setStatus(true, 'Connected');
  } catch (e) {
    setStatus(false, e?.message || 'Invalid key');
  }
}

window.sendChatPrompt = sendChatPrompt;
window.logoutDemoUser = logoutDemoUser;
window.switchSession = switchSession;
window.createNewSession = createNewSession;
boot();
