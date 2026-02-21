from flask import Flask, request, jsonify, Response
import os, json, time
import requests
from collections import defaultdict, deque

app = Flask(__name__)

# -----------------------
# CORS (IMPORTANTE para fetch desde navegador / Claude Artifacts)
# -----------------------
@app.after_request
def add_cors_headers(resp):
    # Para pruebas: permite cualquier origen (incluye file:// => Origin: null y claude.ai)
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

# Seguridad (ponlo en Render). Si está vacío, NO se exige token.
BRIDGE_TOKEN = os.environ.get("BRIDGE_TOKEN", "").strip()

# Rate limit básico (por IP, en memoria)
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "60"))
_ip_hits = defaultdict(lambda: deque())  # ip -> timestamps

# Límite de tamaño de contexto (evita subir megas y fundirte)
MAX_CONTEXT_CHARS = int(os.environ.get("MAX_CONTEXT_CHARS", "20000"))

# Opcional: lista blanca de modelos por proveedor (recomendado)
ALLOWED_MODELS_GROQ = set(filter(None, os.environ.get("ALLOWED_MODELS_GROQ", "").split(",")))
ALLOWED_MODELS_OPENAI = set(filter(None, os.environ.get("ALLOWED_MODELS_OPENAI", "").split(",")))

# -----------------------
# Helpers
# -----------------------
def _client_ip() -> str:
    # Render suele poner X-Forwarded-For
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def _rate_limit_ok() -> bool:
    ip = _client_ip()
    now = time.time()
    q = _ip_hits[ip]
    # limpia entradas de > 60s
    while q and (now - q[0]) > 60:
        q.popleft()
    if len(q) >= RATE_LIMIT_PER_MIN:
        return False
    q.append(now)
    return True

def _require_token():
    if not BRIDGE_TOKEN:
        return  # token desactivado
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
    """
    Soporta:
      - GET ?text=...
      - POST JSON {"text": "...", "context": "..."}
      - POST multipart form-data: text + file(.txt)
    """
    if request.method == "GET":
        text = request.args.get("text", "") or ""
        context = request.args.get("context", "") or ""
        return text, context

    if request.is_json:
        data = request.get_json(silent=True) or {}
        text = data.get("text", "") or ""
        context = data.get("context", "") or ""
        return text, context

    # multipart / form
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
    # provider/model/temp/max_tokens/stream desde GET o POST
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
def call_groq(prompt: str, model: str, temperature: float, max_tokens: int, stream: bool):
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        return None, "(sin GROQ_API_KEY)", 500

    # De momento permitimos todos los modelos
    # if ALLOWED_MODELS_GROQ and model not in ALLOWED_MODELS_GROQ:
    #     return None, f"(modelo Groq no permitido: {model})", 400

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
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "super-bridge/1.0",
        },
        data=json.dumps(payload),
        stream=stream,
        timeout=90,
    )
    return resp, None, None

def call_openai(prompt: str, model: str, temperature: float, max_tokens: int, stream: bool):
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None, "(sin OPENAI_API_KEY)", 500

    # De momento permitimos todos los modelos
    # if ALLOWED_MODELS_OPENAI and model not in ALLOWED_MODELS_OPENAI:
    #     return None, f"(modelo OpenAI no permitido: {model})", 400

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
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "super-bridge/1.0",
        },
        data=json.dumps(payload),
        stream=stream,
        timeout=90,
    )
    return resp, None, None

def dispatch(provider: str, prompt: str, model: str, temperature: float, max_tokens: int, stream: bool):
    if provider == "groq":
        return call_groq(prompt, model, temperature, max_tokens, stream)
    if provider == "openai":
        return call_openai(prompt, model, temperature, max_tokens, stream)
    return None, f"(provider no soportado: {provider})", 400

# -----------------------
# Streaming (SSE)
# -----------------------
def sse_from_openai_compatible(resp: requests.Response):
    """
    Convierte el stream SSE OpenAI-compatible en un stream "text/plain" (solo texto).
    Los proveedores suelen mandar líneas "data: {...}" y terminar con "data: [DONE]".
    """
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
                    # ignora fragmentos raros
                    continue
    finally:
        try:
            resp.close()
        except Exception:
            pass

# -----------------------
# Routes
# -----------------------
@app.get("/")
def home():
    return "SUPER BRIDGE ONLINE 🔥"

@app.route("/api/message", methods=["GET", "POST", "OPTIONS"])
def api_message():
    # Preflight CORS (IMPORTANTE para fetch POST/JSON y algunos entornos)
    if request.method == "OPTIONS":
        return ("", 204)

    # Seguridad y rate limit
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

    # Si no stream: devolver JSON normal
    if not stream:
        if resp.status_code >= 400:
            return jsonify({"content": f"({provider} HTTP {resp.status_code}) {resp.text}"}), 500

        try:
            data = resp.json()
            out = data["choices"][0]["message"]["content"].strip()
        except Exception:
            return jsonify({"content": f"({provider}) respuesta no válida: {resp.text}"}), 500

        return jsonify({"content": out, "provider": provider, "model": model})

    # Stream: devolver texto plano (chunked)
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
