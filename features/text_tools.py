from flask import Blueprint, request, jsonify, current_app
from core.auth import require_token
import hashlib

bp = Blueprint("text_tools", __name__, url_prefix="/tools")


def _coerce_int(v, default):
    try:
        return int(v)
    except Exception:
        return default


def _read_text_from_request():
    """
    Igual filosofía que features/bridge.py:
    - GET: ?text=...&context=...
    - POST JSON: {"text":"...", "context":"..."}
    - POST form-data: text/context + file
    """
    if request.method == "GET":
        return (request.args.get("text", "") or ""), (request.args.get("context", "") or "")

    if request.is_json:
        data = request.get_json(silent=True) or {}
        return (data.get("text", "") or ""), (data.get("context", "") or "")

    text = request.form.get("text", "") or ""
    context = request.form.get("context", "") or ""

    f = request.files.get("file")
    if f:
        content = f.read().decode("utf-8", errors="replace")
        context = (context + "\n" + content) if context else content

    return text, context


def _stats(s: str):
    lines = s.splitlines()
    words = s.split()
    return {
        "chars": len(s),
        "lines": len(lines),
        "words": len(words),
        "sha256": hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest(),
    }


def _make_chunks(s: str, chunk_size: int, overlap: int):
    """
    Chunking por caracteres, simple y determinista.
    """
    if chunk_size <= 0:
        return []

    overlap = max(0, min(overlap, chunk_size - 1)) if chunk_size > 1 else 0
    step = max(1, chunk_size - overlap)

    out = []
    i = 0
    idx = 0
    n = len(s)
    while i < n:
        j = min(i + chunk_size, n)
        out.append({
            "index": idx,
            "start": i,
            "end": j,
            "len": j - i,
            "preview": s[i:j][:120]
        })
        if j >= n:
            break
        i += step
        idx += 1
    return out


@bp.route("/text_stats", methods=["GET", "POST", "OPTIONS"])
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def text_stats():
    if request.method == "OPTIONS":
        return ("", 204)

    # Reutiliza vuestro rate limiter global
    limiter = current_app.config["RATE_LIMITER"]
    if not limiter.ok():
        return jsonify({"error": "rate limit"}), 429

    text, context = _read_text_from_request()

    if not (text or context):
        return jsonify({"error": "Falta text o context (o file en form-data)"}), 400

    joined = text.strip()
    context = context.strip()

    if joined and context:
        payload = f"{joined}\n\nCONTEXTO:\n{context}"
    else:
        payload = joined or context

    preview_len = _coerce_int(
        request.args.get("preview_len") if request.method == "GET"
        else (request.form.get("preview_len") if not request.is_json else (request.get_json(silent=True) or {}).get("preview_len")),
        300
    )
    chunk_size = _coerce_int(
        request.args.get("chunk_size") if request.method == "GET"
        else (request.form.get("chunk_size") if not request.is_json else (request.get_json(silent=True) or {}).get("chunk_size")),
        0
    )
    overlap = _coerce_int(
        request.args.get("overlap") if request.method == "GET"
        else (request.form.get("overlap") if not request.is_json else (request.get_json(silent=True) or {}).get("overlap")),
        0
    )

    res = {
        "ok": True,
        "input": {
            "has_text": bool(text.strip()),
            "has_context": bool(context),
            "combined_preview": payload[:max(0, preview_len)],
        },
        "stats": _stats(payload),
    }

    if chunk_size > 0:
        res["chunks"] = _make_chunks(payload, chunk_size=chunk_size, overlap=overlap)
        res["chunking"] = {
            "chunk_size": chunk_size,
            "overlap": overlap,
            "count": len(res["chunks"])
        }

    return jsonify(res)
