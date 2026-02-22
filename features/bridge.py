from flask import Blueprint, request, jsonify, Response, current_app, render_template_string
import requests
from core.auth import require_token
from services.llm_providers import dispatch
from services.streaming import sse_from_openai_compatible

bp = Blueprint("bridge", __name__)

UI_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Bridge UI</title></head>
<body>
<h1>Super Bridge UI</h1>
<p>claude-bridge-i43j.onrender.com</p>
<p>Usa /api/message (GET/POST)</p>
</body></html>
"""

def _coerce_float(v, default):
    try: return float(v)
    except Exception: return default

def _coerce_int(v, default):
    try: return int(v)
    except Exception: return default

def _read_text_from_request():
    if request.method == "GET":
        return (request.args.get("text", "") or ""), (request.args.get("context", "") or "")

    if request.is_json:
        data = request.get_json(silent=True) or {}
        return (data.get("text", "") or ""), (data.get("context", "") or "")

    text = request.form.get("text", "") or ""
    context = request.form.get("context", "") or ""

    file = request.files.get("file")
    if file:
        content = file.read().decode("utf-8", errors="replace")
        context = (context + "\n" + content) if context else content

    return text, context

def _build_prompt(text: str, context: str) -> str:
    s = current_app.config["SETTINGS"]
    text = (text or "").strip()
    context = (context or "").strip()
    if len(context) > s.MAX_CONTEXT_CHARS:
        context = context[: s.MAX_CONTEXT_CHARS]
    if context:
        return f"{text}\n\nCONTEXTO:\n{context}"
    return text

def _get_params():
    s = current_app.config["SETTINGS"]

    if request.method == "GET":
        provider = (request.args.get("provider") or s.DEFAULT_PROVIDER).strip().lower()
        model = (request.args.get("model") or s.DEFAULT_MODEL).strip()
        temperature = _coerce_float(request.args.get("temperature"), s.DEFAULT_TEMPERATURE)
        max_tokens = _coerce_int(request.args.get("max_tokens"), s.DEFAULT_MAX_TOKENS)
        stream = (request.args.get("stream") or "0") in ("1","true","True","yes")
        return provider, model, temperature, max_tokens, stream

    if request.is_json:
        data = request.get_json(silent=True) or {}
        provider = (data.get("provider") or s.DEFAULT_PROVIDER).strip().lower()
        model = (data.get("model") or s.DEFAULT_MODEL).strip()
        temperature = _coerce_float(data.get("temperature"), s.DEFAULT_TEMPERATURE)
        max_tokens = _coerce_int(data.get("max_tokens"), s.DEFAULT_MAX_TOKENS)
        stream = bool(data.get("stream", False))
        return provider, model, temperature, max_tokens, stream

    provider = (request.form.get("provider") or s.DEFAULT_PROVIDER).strip().lower()
    model = (request.form.get("model") or s.DEFAULT_MODEL).strip()
    temperature = _coerce_float(request.form.get("temperature"), s.DEFAULT_TEMPERATURE)
    max_tokens = _coerce_int(request.form.get("max_tokens"), s.DEFAULT_MAX_TOKENS)
    stream = (request.form.get("stream") or "0") in ("1","true","True","yes")
    return provider, model, temperature, max_tokens, stream

@bp.get("/")
def home():
    return "SUPER BRIDGE ONLINE "

@bp.get("/ui")
def ui():
    return render_template_string(UI_HTML)

@bp.route("/api/message", methods=["GET", "POST", "OPTIONS"])
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def api_message():
    if request.method == "OPTIONS":
        return ("", 204)

    limiter = current_app.config["RATE_LIMITER"]
    if not limiter.ok():
        return jsonify({"content": "(rate limit) demasiadas peticiones, espera 60s"}), 429

    provider, model, temperature, max_tokens, stream = _get_params()

    # (opcional) enforce allow-lists si están definidas
    s = current_app.config["SETTINGS"]
    # De momento permitimos cualquier modelo
    #if provider == "groq" and s.ALLOWED_MODELS_GROQ and model not in s.ALLOWED_MODELS_GROQ:
    #    return jsonify({"content": f"(model no permitido groq): {model}"}), 400
    #if provider == "openai" and s.ALLOWED_MODELS_OPENAI and model not in s.ALLOWED_MODELS_OPENAI:
    #    return jsonify({"content": f"(model no permitido openai): {model}"}), 400

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

    # igual que tu app: streaming "texto plano"
    return Response(
        sse_from_openai_compatible(resp),
        mimetype="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-cache"},
    )
