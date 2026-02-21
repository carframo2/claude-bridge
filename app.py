from flask import Flask, request, jsonify, Response, render_template_string
import os, json, time
import requests
from collections import defaultdict, deque

app = Flask(__name__)

# -----------------------
# CORS (IMPORTANTE para fetch desde navegador / Claude Artifacts)
# -----------------------
@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-BRIDGE-TOKEN"
    resp.headers["Access-Control-Max-Age"] = "86400"
    return resp

# -----------------------
# Config general
# -----------------------
DEFAULT_PROVIDER = os.environ.get("DEFAULT_PROVIDER", "groq")
DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "llama-3.3-70b-versatile")
DEFAULT_TEMPERATURE = float(os.environ.get("DEFAULT_TEMPERATURE", "0.2"))
DEFAULT_MAX_TOKENS = int(os.environ.get("DEFAULT_MAX_TOKENS", "600"))

BRIDGE_TOKEN = os.environ.get("BRIDGE_TOKEN", "").strip()

RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "60"))
_ip_hits = defaultdict(lambda: deque())

MAX_CONTEXT_CHARS = int(os.environ.get("MAX_CONTEXT_CHARS", "20000"))

ALLOWED_MODELS_GROQ = set(filter(None, os.environ.get("ALLOWED_MODELS_GROQ", "").split(",")))
ALLOWED_MODELS_OPENAI = set(filter(None, os.environ.get("ALLOWED_MODELS_OPENAI", "").split(",")))

# -----------------------
# Helpers
# -----------------------
def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def _rate_limit_ok() -> bool:
    ip = _client_ip()
    now = time.time()
    q = _ip_hits[ip]
    while q and (now - q[0]) > 60:
        q.popleft()
    if len(q) >= RATE_LIMIT_PER_MIN:
        return False
    q.append(now)
    return True

def _require_token():
    if not BRIDGE_TOKEN:
        return
    provided = (
        request.headers.get("X-BRIDGE-TOKEN")
        or request.args.get("token")
        or (request.is_json and (request.get_json(silent=True) or {}).get("token"))
        or request.form.get("token")
    )
    if not provided or provided != BRIDGE_TOKEN:
        return jsonify({"content": "(unauthorized) token inválido"}), 401

def _coerce_float(v, default):
    try:
        return float(v)
    except Exception:
        return default

def _coerce_int(v, default):
    try:
        return int(v)
    except Exception:
        return default

def _read_text_from_request():
    if request.method == "GET":
        text = request.args.get("text", "") or ""
        context = request.args.get("context", "") or ""
        return text, context

    if request.is_json:
        data = request.get_json(silent=True) or {}
        text = data.get("text", "") or ""
        context = data.get("context", "") or ""
        return text, context

    text = request.form.get("text", "") or ""
    context = request.form.get("context", "") or ""
    file = request.files.get("file")
    if file:
        content = file.read().decode("utf-8", errors="replace")
        context = (context + "\n" + content) if context else content
    return text, context

def _build_prompt(text: str, context: str) -> str:
    text = (text or "").strip()
    context = (context or "").strip()
    if len(context) > MAX_CONTEXT_CHARS:
        context = context[:MAX_CONTEXT_CHARS]
    if context:
        return f"{text}\n\nCONTEXTO:\n{context}"
    return text

def _get_params():
    if request.method == "GET":
        provider = (request.args.get("provider") or DEFAULT_PROVIDER).strip().lower()
        model = (request.args.get("model") or DEFAULT_MODEL).strip()
        temperature = _coerce_float(request.args.get("temperature"), DEFAULT_TEMPERATURE)
        max_tokens = _coerce_int(request.args.get("max_tokens"), DEFAULT_MAX_TOKENS)
        stream = (request.args.get("stream") or "0") in ("1", "true", "True", "yes")
        return provider, model, temperature, max_tokens, stream

    if request.is_json:
        data = request.get_json(silent=True) or {}
        provider = (data.get("provider") or DEFAULT_PROVIDER).strip().lower()
        model = (data.get("model") or DEFAULT_MODEL).strip()
        temperature = _coerce_float(data.get("temperature"), DEFAULT_TEMPERATURE)
        max_tokens = _coerce_int(data.get("max_tokens"), DEFAULT_MAX_TOKENS)
        stream = bool(data.get("stream", False))
        return provider, model, temperature, max_tokens, stream

    provider = (request.form.get("provider") or DEFAULT_PROVIDER).strip().lower()
    model = (request.form.get("model") or DEFAULT_MODEL).strip()
    temperature = _coerce_float(request.form.get("temperature"), DEFAULT_TEMPERATURE)
    max_tokens = _coerce_int(request.form.get("max_tokens"), DEFAULT_MAX_TOKENS)
    stream = (request.form.get("stream") or "0") in ("1", "true", "True", "yes")
    return provider, model, temperature, max_tokens, stream

# -----------------------
# Providers
# -----------------------
def call_groq(prompt, model, temperature, max_tokens, stream):
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        return None, "(sin GROQ_API_KEY)", 500
    url = "https://api.groq.com/openai/v1/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": stream,
    }
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "User-Agent": "super-bridge/1.0"},
        data=json.dumps(payload),
        stream=stream,
        timeout=90,
    )
    return resp, None, None

def call_openai(prompt, model, temperature, max_tokens, stream):
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None, "(sin OPENAI_API_KEY)", 500
    url = "https://api.openai.com/v1/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": stream,
    }
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "User-Agent": "super-bridge/1.0"},
        data=json.dumps(payload),
        stream=stream,
        timeout=90,
    )
    return resp, None, None

def dispatch(provider, prompt, model, temperature, max_tokens, stream):
    if provider == "groq":
        return call_groq(prompt, model, temperature, max_tokens, stream)
    if provider == "openai":
        return call_openai(prompt, model, temperature, max_tokens, stream)
    return None, f"(provider no soportado: {provider})", 400

# -----------------------
# Streaming (SSE)
# -----------------------
def sse_from_openai_compatible(resp):
    try:
        for raw in resp.iter_lines(decode_unicode=True):
            if not raw:
                continue
            line = raw.strip()
            if line.startswith("data:"):
                data = line[len("data:"):].strip()
                if data == "[DONE]":
                    break
                try:
                    obj = json.loads(data)
                    delta = obj["choices"][0].get("delta", {}).get("content")
                    if delta:
                        yield delta
                except Exception:
                    continue
    finally:
        try:
            resp.close()
        except Exception:
            pass

# -----------------------
# UI (nueva ruta)
# -----------------------
UI_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bridge UI</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #f5f2eb;
    --surface: #edeade;
    --border: #c8c3b5;
    --ink: #1a1814;
    --muted: #6b6558;
    --accent: #c0392b;
    --accent2: #2980b9;
    --success: #27ae60;
    --error: #c0392b;
    --get-color: #d35400;
    --post-color: #2980b9;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--ink);
    font-family: 'IBM Plex Mono', monospace;
    min-height: 100vh;
    padding: 0;
  }
  header {
    background: var(--ink);
    color: var(--bg);
    padding: 1rem 2rem;
    display: flex;
    align-items: baseline;
    gap: 1rem;
    border-bottom: 3px solid var(--accent);
  }
  header h1 {
    font-family: 'Syne', sans-serif;
    font-size: 1.4rem;
    font-weight: 800;
    letter-spacing: -0.02em;
  }
  header h1 span { color: #e74c3c; }
  header .sub { font-size: 0.7rem; color: #888; }

  .layout {
    display: grid;
    grid-template-columns: 360px 1fr;
    min-height: calc(100vh - 58px);
  }
  @media(max-width: 700px) {
    .layout { grid-template-columns: 1fr; }
  }

  .sidebar {
    background: var(--surface);
    border-right: 2px solid var(--border);
    padding: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .section-title {
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--muted);
    margin-bottom: 0.3rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.3rem;
  }

  label { display: block; font-size: 0.7rem; color: var(--muted); margin-bottom: 0.3rem; margin-top: 0.7rem; }
  label:first-of-type { margin-top: 0; }

  input[type=text], input[type=number], select, textarea {
    width: 100%;
    background: var(--bg);
    border: 1.5px solid var(--border);
    border-radius: 4px;
    color: var(--ink);
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.75rem;
    padding: 0.5rem 0.6rem;
    outline: none;
    transition: border-color 0.15s;
  }
  input:focus, select:focus, textarea:focus { border-color: var(--ink); }
  textarea { resize: vertical; min-height: 90px; }

  .method-row {
    display: flex;
    gap: 0.4rem;
  }
  .method-btn {
    flex: 1; padding: 0.45rem;
    border: 1.5px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
    font-family: 'IBM Plex Mono', monospace;
    font-weight: 600; font-size: 0.75rem;
    background: var(--bg); color: var(--muted);
    transition: all 0.15s;
  }
  .method-btn.get-active { background: var(--get-color); color: #fff; border-color: var(--get-color); }
  .method-btn.post-active { background: var(--post-color); color: #fff; border-color: var(--post-color); }

  .file-zone {
    border: 2px dashed var(--border);
    border-radius: 4px;
    padding: 1rem;
    text-align: center;
    font-size: 0.72rem;
    color: var(--muted);
    cursor: pointer;
    transition: all 0.15s;
    background: var(--bg);
  }
  .file-zone:hover, .file-zone.drag { border-color: var(--ink); color: var(--ink); background: #ede8de; }
  .file-zone input { display: none; }
  .file-name { margin-top: 0.4rem; color: var(--accent2); font-size: 0.7rem; word-break: break-all; }

  .send-btn {
    width: 100%;
    padding: 0.75rem;
    border: none; border-radius: 4px;
    background: var(--ink); color: var(--bg);
    font-family: 'Syne', sans-serif; font-weight: 700;
    font-size: 0.9rem; cursor: pointer;
    letter-spacing: 0.02em;
    transition: background 0.15s, transform 0.1s;
    margin-top: 0.5rem;
  }
  .send-btn:hover { background: #333; }
  .send-btn:active { transform: scale(0.98); }
  .send-btn:disabled { background: #999; cursor: not-allowed; }

  /* Main area */
  .main {
    display: flex;
    flex-direction: column;
    padding: 1.5rem;
    gap: 1rem;
  }

  .url-bar {
    background: var(--surface);
    border: 1.5px solid var(--border);
    border-radius: 4px;
    padding: 0.5rem 0.8rem;
    font-size: 0.68rem;
    color: var(--muted);
    word-break: break-all;
    min-height: 2.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .method-pill {
    padding: 0.15rem 0.5rem;
    border-radius: 3px;
    font-weight: 600; font-size: 0.65rem;
    flex-shrink: 0;
  }
  .pill-get { background: rgba(211,84,0,0.12); color: var(--get-color); }
  .pill-post { background: rgba(41,128,185,0.12); color: var(--post-color); }

  .response-box {
    flex: 1;
    background: var(--surface);
    border: 1.5px solid var(--border);
    border-radius: 4px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .response-top {
    display: flex; align-items: center; justify-content: space-between;
    padding: 0.6rem 1rem;
    border-bottom: 1px solid var(--border);
    background: var(--bg);
  }
  .response-top .title { font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); }
  .status-badge {
    font-size: 0.68rem; font-weight: 600;
    padding: 0.15rem 0.5rem; border-radius: 3px;
  }
  .ok { background: rgba(39,174,96,0.12); color: var(--success); }
  .err { background: rgba(192,57,43,0.12); color: var(--error); }
  .timing { font-size: 0.65rem; color: var(--muted); }

  .tab-bar {
    display: flex; border-bottom: 1px solid var(--border);
    background: var(--bg);
  }
  .tab {
    padding: 0.4rem 1rem; font-size: 0.68rem; cursor: pointer;
    border: none; background: transparent; color: var(--muted);
    font-family: 'IBM Plex Mono', monospace;
    border-bottom: 2px solid transparent;
    transition: all 0.15s;
  }
  .tab.active { color: var(--ink); border-bottom-color: var(--ink); }

  .response-body {
    flex: 1; padding: 1rem;
    font-size: 0.75rem; line-height: 1.7;
    white-space: pre-wrap; word-break: break-word;
    overflow-y: auto;
    min-height: 200px;
    max-height: 500px;
  }
  .response-body.empty { color: var(--muted); font-style: italic; }

  .chat-log {
    display: flex; flex-direction: column; gap: 1rem;
  }
  .msg {
    border-left: 3px solid var(--border);
    padding: 0.5rem 0.8rem;
  }
  .msg.user { border-color: var(--ink); }
  .msg.assistant { border-color: var(--accent2); }
  .msg .who { font-size: 0.62rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-bottom: 0.3rem; }
  .msg.user .who { color: var(--ink); }
  .msg.assistant .who { color: var(--accent2); }
  .msg .body { font-size: 0.78rem; line-height: 1.6; }

  .loader-dots span {
    animation: blink 1.2s infinite;
    opacity: 0;
  }
  .loader-dots span:nth-child(2) { animation-delay: 0.2s; }
  .loader-dots span:nth-child(3) { animation-delay: 0.4s; }
  @keyframes blink { 0%,80%,100%{opacity:0} 40%{opacity:1} }
</style>
</head>
<body>

<header>
  <h1>Super Bridge <span>UI</span></h1>
  <span class="sub">claude-bridge-i43j.onrender.com</span>
</header>

<div class="layout">
  <!-- SIDEBAR -->
  <div class="sidebar">

    <div>
      <div class="section-title">Método</div>
      <div class="method-row">
        <button class="method-btn get-active" id="btnGet" onclick="setMethod('GET')">GET</button>
        <button class="method-btn" id="btnPost" onclick="setMethod('POST')">POST</button>
      </div>
    </div>

    <div>
      <div class="section-title">Configuración</div>
      <label>Token</label>
      <input type="text" id="token" value="kienzan">
      <label>Provider</label>
      <select id="provider" onchange="updateModel()">
        <option value="groq">groq</option>
        <option value="openai">openai</option>
      </select>
      <label>Modelo</label>
      <input type="text" id="model" value="openai/gpt-oss-120b">
      <label>Temperature</label>
      <input type="number" id="temperature" value="0.2" min="0" max="2" step="0.1">
      <label>Max tokens</label>
      <input type="number" id="max_tokens" value="600" min="1" max="8000">
    </div>

    <div>
      <div class="section-title">Mensaje</div>
      <textarea id="text" rows="4" placeholder="Escribe tu mensaje aquí...">Hola, ¿qué modelo eres?</textarea>
    </div>

    <div id="fileSection">
      <div class="section-title">Fichero (POST multipart)</div>
      <div class="file-zone" id="fileZone" onclick="document.getElementById('fileInput').click()"
           ondragover="event.preventDefault();this.classList.add('drag')"
           ondragleave="this.classList.remove('drag')"
           ondrop="handleDrop(event)">
        📎 Haz clic o arrastra un fichero .txt
        <input type="file" id="fileInput" accept=".txt,.md,.csv,.json,.log" onchange="handleFile(this)">
        <div class="file-name" id="fileName"></div>
      </div>
    </div>

    <button class="send-btn" id="sendBtn" onclick="sendRequest()">▶ Enviar</button>
  </div>

  <!-- MAIN -->
  <div class="main">
    <div class="url-bar" id="urlBar">
      <span class="method-pill pill-get" id="methodPill">GET</span>
      <span id="urlText" style="color:var(--muted)">—</span>
    </div>

    <div class="response-box">
      <div class="response-top">
        <span class="title">Respuesta</span>
        <div style="display:flex;gap:0.8rem;align-items:center">
          <span class="timing" id="timing"></span>
          <span id="statusBadge" class="status-badge" style="display:none"></span>
        </div>
      </div>
      <div class="tab-bar">
        <button class="tab active" onclick="showTab('chat')">Chat</button>
        <button class="tab" onclick="showTab('raw')">Raw JSON</button>
      </div>
      <div class="response-body empty" id="chatTab">Envía un mensaje para ver la respuesta aquí.</div>
      <div class="response-body" id="rawTab" style="display:none;color:var(--muted)">—</div>
    </div>
  </div>
</div>

<script>
  let method = 'GET';
  let selectedFile = null;
  let chatHistory = [];

  function setMethod(m) {
    method = m;
    document.getElementById('btnGet').className = 'method-btn' + (m==='GET' ? ' get-active' : '');
    document.getElementById('btnPost').className = 'method-btn' + (m==='POST' ? ' post-active' : '');
    document.getElementById('fileSection').style.display = m==='POST' ? 'block' : 'none';
    document.getElementById('methodPill').className = 'method-pill ' + (m==='GET' ? 'pill-get' : 'pill-post');
    document.getElementById('methodPill').textContent = m;
    updateUrl();
  }

  function updateModel() {
    const p = document.getElementById('provider').value;
    const modelInput = document.getElementById('model');
    if (p === 'groq') modelInput.value = 'llama-3.3-70b-versatile';
    else modelInput.value = 'gpt-4o';
  }

  function getParams() {
    return {
      text: document.getElementById('text').value,
      model: document.getElementById('model').value,
      provider: document.getElementById('provider').value,
      token: document.getElementById('token').value,
      temperature: document.getElementById('temperature').value,
      max_tokens: document.getElementById('max_tokens').value,
    };
  }

  function updateUrl() {
    const base = '/api/message';
    const p = getParams();
    if (method === 'GET') {
      const q = new URLSearchParams(p).toString();
      document.getElementById('urlText').textContent = `${base}?${q}`;
    } else {
      document.getElementById('urlText').textContent = `${base}  [POST JSON${selectedFile ? ' + file' : ''}]`;
    }
  }

  ['text','model','token','temperature','max_tokens'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', updateUrl);
  });
  document.getElementById('provider').addEventListener('change', updateUrl);

  function handleFile(input) {
    selectedFile = input.files[0] || null;
    document.getElementById('fileName').textContent = selectedFile ? selectedFile.name : '';
    updateUrl();
  }

  function handleDrop(e) {
    e.preventDefault();
    document.getElementById('fileZone').classList.remove('drag');
    const f = e.dataTransfer.files[0];
    if (f) {
      selectedFile = f;
      document.getElementById('fileName').textContent = f.name;
      updateUrl();
    }
  }

  function showTab(tab) {
    document.querySelectorAll('.tab').forEach((t,i) => t.classList.toggle('active', (i===0&&tab==='chat')||(i===1&&tab==='raw')));
    document.getElementById('chatTab').style.display = tab==='chat' ? 'block' : 'none';
    document.getElementById('rawTab').style.display = tab==='raw' ? 'block' : 'none';
  }

  function renderChat() {
    const el = document.getElementById('chatTab');
    if (!chatHistory.length) {
      el.className = 'response-body empty';
      el.textContent = 'Envía un mensaje para ver la respuesta aquí.';
      return;
    }
    el.className = 'response-body';
    el.innerHTML = '<div class="chat-log">' + chatHistory.map(m => `
      <div class="msg ${m.role}">
        <div class="who">${m.role === 'user' ? '👤 Tú' : '🤖 ' + (m.model || 'Asistente')}</div>
        <div class="body">${m.content.replace(/</g,'&lt;').replace(/\n/g,'<br>')}</div>
      </div>
    `).join('') + '</div>';
    el.scrollTop = el.scrollHeight;
  }

  async function sendRequest() {
    const btn = document.getElementById('sendBtn');
    const badge = document.getElementById('statusBadge');
    const timing = document.getElementById('timing');
    const rawTab = document.getElementById('rawTab');
    const p = getParams();

    if (!p.text.trim()) { alert('Escribe un mensaje'); return; }

    btn.disabled = true;
    btn.textContent = '⏳ Enviando...';
    badge.style.display = 'none';
    timing.textContent = '';

    // Añadir mensaje de usuario al chat
    chatHistory.push({ role: 'user', content: p.text });
    // Placeholder de carga
    chatHistory.push({ role: 'assistant', content: '...', model: p.model });
    renderChat();
    // Añadir loader al último mensaje
    const chatEl = document.getElementById('chatTab');
    const lastMsg = chatEl.querySelector('.chat-log .msg.assistant:last-child .body');
    if (lastMsg) lastMsg.innerHTML = '<span class="loader-dots"><span>.</span><span>.</span><span>.</span></span>';

    const t0 = Date.now();

    try {
      let res;
      if (method === 'GET') {
        const q = new URLSearchParams(p).toString();
        res = await fetch(`/api/message?${q}`, { method: 'GET', cache: 'no-store' });
      } else if (selectedFile) {
        const fd = new FormData();
        Object.entries(p).forEach(([k,v]) => fd.append(k, v));
        fd.append('file', selectedFile);
        res = await fetch('/api/message', { method: 'POST', body: fd });
      } else {
        res = await fetch('/api/message', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(p)
        });
      }

      const elapsed = Date.now() - t0;
      const text = await res.text();
      timing.textContent = `${elapsed}ms`;
      rawTab.textContent = text;

      badge.style.display = 'inline-block';
      badge.className = 'status-badge ' + (res.ok ? 'ok' : 'err');
      badge.textContent = res.ok ? `✓ ${res.status}` : `✗ ${res.status}`;

      let content = text;
      let modelName = p.model;
      try {
        const json = JSON.parse(text);
        content = json.content || text;
        modelName = json.model || p.model;
      } catch {}

      // Reemplazar placeholder
      chatHistory[chatHistory.length - 1] = { role: 'assistant', content, model: modelName };

    } catch (err) {
      const elapsed = Date.now() - t0;
      timing.textContent = `${elapsed}ms`;
      badge.style.display = 'inline-block';
      badge.className = 'status-badge err';
      badge.textContent = '✗ Error';
      rawTab.textContent = String(err);
      chatHistory[chatHistory.length - 1] = { role: 'assistant', content: `❌ Error: ${err.message}`, model: p.model };
    }

    renderChat();
    btn.disabled = false;
    btn.textContent = '▶ Enviar';
    document.getElementById('text').value = '';
    updateUrl();
  }

  // Init
  setMethod('GET');
  updateUrl();
</script>
</body>
</html>
"""

@app.get("/ui")
def ui():
    return render_template_string(UI_HTML)

# -----------------------
# Routes
# -----------------------
@app.get("/")
def home():
    return "SUPER BRIDGE ONLINE 🔥"

@app.route("/api/message", methods=["GET", "POST", "OPTIONS"])
def api_message():
    if request.method == "OPTIONS":
        return ("", 204)

    tok = _require_token()
    if tok is not None:
        return tok

    if not _rate_limit_ok():
        return jsonify({"content": "(rate limit) demasiadas peticiones, espera 60s"}), 429

    provider, model, temperature, max_tokens, stream = _get_params()
    text, context = _read_text_from_request()

    if not (text or context):
        return jsonify({"content": "Falta text (GET ?text=... o POST body)"}), 400

    prompt = _build_prompt(text, context)

    try:
        resp, err, status = dispatch(provider, prompt, model, temperature, max_tokens, stream)
    except requests.RequestException as e:
        return jsonify({"content": f"(upstream error) {str(e)}"}), 502
    except Exception as e:
        return jsonify({"content": f"(internal error dispatch) {str(e)}"}), 500

    if err:
        return jsonify({"content": err}), status or 500

    if not stream:
        if resp.status_code >= 400:
            return jsonify({"content": f"({provider} HTTP {resp.status_code}) {resp.text}"}), 500
        try:
            data = resp.json()
            out = data["choices"][0]["message"]["content"].strip()
        except Exception:
            return jsonify({"content": f"({provider}) respuesta no válida: {resp.text}"}), 500
        return jsonify({"content": out, "provider": provider, "model": model})

    if resp.status_code >= 400:
        return jsonify({"content": f"({provider} HTTP {resp.status_code}) {resp.text}"}), 500

    return Response(
        sse_from_openai_compatible(resp),
        mimetype="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-cache"},
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
