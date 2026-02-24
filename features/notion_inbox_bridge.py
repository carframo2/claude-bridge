from __future__ import annotations

"""
Feature: notion_inbox_bridge (minimal, plug-and-play)

Objetivo:
- Endpoints "A" en Bridge: cuando se llama, mira la página Notion "test_bridge" (inbox).
- Si encuentra una URL (B/C/D...), la envía al Daemon/Bounce (/bounce) para que la ejecute.
- Recibe la respuesta del Daemon/Bounce.
- Borra el contenido de "test_bridge" y escribe la respuesta en "test_bridge_response".

Diseño:
- Daemon NO sabe nada de Notion. Solo rebota URLs.
- Esta feature SÍ sabe leer/escribir Notion.

Variables de entorno (mantiene compatibilidad):
- NOTION_TOKEN (obligatoria)
- NOTION_API_VERSION (opcional, default 2022-06-28)
- NOTION_INBOX_PAGE_ID (opcional)  -> page_id de test_bridge
- NOTION_INBOX_PAGE_TITLE (opcional, default "test_bridge") -> si no hay ID, busca por título
- NOTION_RESPONSE_PAGE_ID (obligatoria) -> page_id donde se escribe la respuesta (test_bridge_response)
- DAEMON_BOUNCE_URL (obligatoria) -> URL base del daemon /bounce (puede incluir token del daemon en query)

Seguridad:
- Respeta vuestro auth de Bridge (X-BRIDGE-TOKEN / token) vía require_token
- Respeta rate limiter global (RATE_LIMITER)

Endpoints:
- GET /notion/inbox_tick
- GET /notion/inbox_test_bridge  (alias)

Query params:
- debug=1               -> devuelve JSON con detalles (por defecto, minimal)
- max_blocks=...         -> límite de bloques a escanear (default 200)
- timeout=...            -> timeout HTTP (default 20)
- keep_inbox_on_error=1  -> si 1, NO borra inbox cuando falla bounce (default 1)
"""

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlsplit

import requests
from flask import Blueprint, current_app, jsonify, request

from core.auth import require_token

bp = Blueprint("notion_inbox_bridge", __name__, url_prefix="/notion")

URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)

RESPUESTA_LEER_NOTION = "RESPUESTA_LEER_NOTION"


# ---------------------------------------------------------------------------
# helpers env / args
# ---------------------------------------------------------------------------

def _env(name: str, default: Optional[str] = None) -> str:
    v = os.environ.get(name)
    if v is None:
        return "" if default is None else str(default)
    return str(v)


def _bool_q(name: str, default: bool = False) -> bool:
    v = request.args.get(name)
    if v is None:
        return default
    return v in ("1", "true", "True", "yes", "on")


def _int_q(name: str, default: int, min_v: Optional[int] = None, max_v: Optional[int] = None) -> int:
    raw = request.args.get(name)
    if raw is None or raw == "":
        n = default
    else:
        try:
            n = int(raw)
        except Exception:
            raise ValueError(f"{name} inválido")
    if min_v is not None and n < min_v:
        raise ValueError(f"{name} debe ser >= {min_v}")
    if max_v is not None and n > max_v:
        raise ValueError(f"{name} debe ser <= {max_v}")
    return n


def _float_q(name: str, default: float, min_v: Optional[float] = None, max_v: Optional[float] = None) -> float:
    raw = request.args.get(name)
    if raw is None or raw == "":
        x = default
    else:
        try:
            x = float(raw)
        except Exception:
            raise ValueError(f"{name} inválido")
    if min_v is not None and x < min_v:
        raise ValueError(f"{name} debe ser >= {min_v}")
    if max_v is not None and x > max_v:
        raise ValueError(f"{name} debe ser <= {max_v}")
    return x


def _json_error(msg: str, status: int = 400, **extra):
    payload = {"ok": False, "error": msg}
    payload.update(extra)
    return jsonify(payload), status


# ---------------------------------------------------------------------------
# Notion client (minimal)
# ---------------------------------------------------------------------------

def _notion_token() -> str:
    return (_env("NOTION_TOKEN", "") or "").strip()


def _notion_version() -> str:
    return (_env("NOTION_API_VERSION", "2022-06-28") or "2022-06-28").strip()


def _notion_headers() -> Dict[str, str]:
    tok = _notion_token()
    if not tok:
        raise RuntimeError("Falta NOTION_TOKEN")
    return {
        "Authorization": f"Bearer {tok}",
        "Notion-Version": _notion_version(),
        "Content-Type": "application/json",
    }


def _normalize_page_id(pid: str) -> str:
    pid = (pid or "").strip()
    pid = pid.replace("-", "")
    if len(pid) != 32:
        return pid
    return f"{pid[0:8]}-{pid[8:12]}-{pid[12:16]}-{pid[16:20]}-{pid[20:32]}"


def _search_page_by_title(title: str, *, timeout: float) -> Optional[Dict[str, Any]]:
    # Notion search endpoint
    url = "https://api.notion.com/v1/search"
    payload = {
        "query": title,
        "filter": {"property": "object", "value": "page"},
        "sort": {"direction": "descending", "timestamp": "last_edited_time"},
        "page_size": 20,
    }
    r = requests.post(url, headers=_notion_headers(), json=payload, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    results = data.get("results") or []
    # prefer exact title match
    exact = None
    contains = None
    for p in results:
        t = _page_title(p) or ""
        if t == title and exact is None:
            exact = p
        if title.lower() in t.lower() and contains is None:
            contains = p
    return exact or contains or (results[0] if results else None)


def _page_title(page_obj: Dict[str, Any]) -> str:
    props = page_obj.get("properties") or {}
    # Most common: title property named "title" or any property of type "title"
    for k, v in props.items():
        if (v or {}).get("type") == "title":
            arr = (v or {}).get("title") or []
            return "".join((x.get("plain_text") or "") for x in arr).strip()
    # sometimes the API returns a "title" field under "properties" named "Name"
    name = props.get("Name")
    if isinstance(name, dict) and name.get("type") == "title":
        arr = name.get("title") or []
        return "".join((x.get("plain_text") or "") for x in arr).strip()
    return ""


def _get_blocks_children(block_id: str, *, timeout: float, page_size: int = 100) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    cursor = None
    while True:
        qs = {"page_size": page_size}
        if cursor:
            qs["start_cursor"] = cursor
        url = f"https://api.notion.com/v1/blocks/{block_id}/children?{urlencode(qs)}"
        r = requests.get(url, headers=_notion_headers(), timeout=timeout)
        r.raise_for_status()
        data = r.json()
        out.extend(data.get("results") or [])
        if not data.get("has_more"):
            break
        cursor = data.get("next_cursor")
        if not cursor:
            break
    return out


def _archive_block(block_id: str, *, timeout: float) -> None:
    url = f"https://api.notion.com/v1/blocks/{block_id}"
    r = requests.patch(url, headers=_notion_headers(), json={"archived": True}, timeout=timeout)
    r.raise_for_status()


def _append_blocks(page_id: str, blocks: List[Dict[str, Any]], *, timeout: float) -> None:
    url = f"https://api.notion.com/v1/blocks/{page_id}/children"
    r = requests.patch(url, headers=_notion_headers(), json={"children": blocks}, timeout=timeout)
    r.raise_for_status()


def _clear_page_children(page_id: str, *, timeout: float, max_blocks: int) -> int:
    blocks = _get_blocks_children(page_id, timeout=timeout)
    count = 0
    for b in blocks[:max_blocks]:
        bid = b.get("id")
        if not bid:
            continue
        try:
            _archive_block(bid, timeout=timeout)
            count += 1
        except Exception:
            # best-effort
            continue
    return count


def _extract_urls_from_blocks(blocks: List[Dict[str, Any]], *, max_blocks: int) -> Tuple[List[str], int]:
    urls: List[str] = []
    scanned = 0

    def add_text(s: str):
        for m in URL_RE.findall(s or ""):
            u = m.strip().rstrip(").,;")
            urls.append(u)

    for b in blocks[:max_blocks]:
        scanned += 1
        # search in rich_text arrays or href/text links
        for k, v in (b or {}).items():
            # common leafs:
            if isinstance(v, str):
                add_text(v)
            elif isinstance(v, dict):
                # look for rich_text
                rt = v.get("rich_text")
                if isinstance(rt, list):
                    for t in rt:
                        add_text(t.get("plain_text") or "")
                        href = t.get("href")
                        if href:
                            urls.append(str(href))
                        link = ((t.get("text") or {}).get("link") or {}).get("url")
                        if link:
                            urls.append(str(link))
                # captions
                cap = v.get("caption")
                if isinstance(cap, list):
                    for t in cap:
                        add_text(t.get("plain_text") or "")
        # also in plain_text inside block type
        typ = b.get("type")
        if typ and isinstance(b.get(typ), dict):
            rt = b[typ].get("rich_text")
            if isinstance(rt, list):
                for t in rt:
                    add_text(t.get("plain_text") or "")
                    href = t.get("href")
                    if href:
                        urls.append(str(href))

    # dedupe keep order
    seen = set()
    uniq: List[str] = []
    for u in urls:
        if not isinstance(u, str):
            continue
        u = u.strip()
        if not u.startswith(("http://", "https://")):
            continue
        if u in seen:
            continue
        seen.add(u)
        uniq.append(u)
    return uniq, scanned


def _resolve_inbox_page(*, timeout: float) -> Dict[str, Any]:
    pid = (_env("NOTION_INBOX_PAGE_ID", "") or "").strip()
    title = (_env("NOTION_INBOX_PAGE_TITLE", "test_bridge") or "test_bridge").strip()
    if pid:
        return {"page_id": _normalize_page_id(pid), "page_title": None}
    page = _search_page_by_title(title, timeout=timeout)
    if not page:
        raise RuntimeError(f"No se encontró página Notion por título: {title}")
    return {"page_id": _normalize_page_id(page.get("id") or ""), "page_title": title}


def _response_page_id() -> str:
    pid = (_env("NOTION_RESPONSE_PAGE_ID", "") or "").strip()
    if not pid:
        raise RuntimeError("Falta NOTION_RESPONSE_PAGE_ID")
    return _normalize_page_id(pid)


# ---------------------------------------------------------------------------
# Daemon call
# ---------------------------------------------------------------------------

def _daemon_bounce_url() -> str:
    u = (_env("DAEMON_BOUNCE_URL", "") or "").strip()
    if not u:
        raise RuntimeError("Falta DAEMON_BOUNCE_URL (ej: https://daemon-bounce.../bounce?token=XYZ)")
    return u


def _call_daemon_bounce(found_url: str, *, timeout: float, debug: bool) -> Tuple[int, str]:
    base = _daemon_bounce_url()
    sep = "&" if ("?" in base) else "?"
    full = f"{base}{sep}{urlencode({'url': found_url, 'debug': '1' if debug else '0'})}"
    r = requests.get(full, timeout=timeout)
    # In modo minimal, daemon devuelve raw body. Con debug=1 puede devolver JSON.
    if debug:
        # intentamos devolver JSON legible
        try:
            data = r.json()
            return r.status_code, str(data)
        except Exception:
            return r.status_code, r.text
    return r.status_code, r.text


# ---------------------------------------------------------------------------
# Notion writing helpers
# ---------------------------------------------------------------------------

def _text_to_notion_blocks(text: str, *, title: Optional[str] = None) -> List[Dict[str, Any]]:
    # Notion rich_text limit ≈ 2000 chars per segment; dividimos en párrafos de 1800
    text = text or ""
    chunks: List[str] = []
    step = 1800
    for i in range(0, len(text), step):
        chunks.append(text[i : i + step])

    blocks: List[Dict[str, Any]] = []
    if title:
        blocks.append({
            "object": "block",
            "type": "heading_2",
            "heading_2": {"rich_text": [{"type": "text", "text": {"content": title[:200]}}]},
        })
    if not chunks:
        chunks = [""]

    for c in chunks:
        blocks.append({
            "object": "block",
            "type": "paragraph",
            "paragraph": {"rich_text": [{"type": "text", "text": {"content": c}}]},
        })
    return blocks


# ---------------------------------------------------------------------------
# Core workflow
# ---------------------------------------------------------------------------

def _run_inbox_once(*, debug: bool, timeout: float, max_blocks: int, keep_inbox_on_error: bool) -> Dict[str, Any]:
    inbox_ref = _resolve_inbox_page(timeout=timeout)
    inbox_id = inbox_ref["page_id"]
    resp_id = _response_page_id()

    # 1) leer blocks inbox
    blocks = _get_blocks_children(inbox_id, timeout=timeout)
    urls, scanned = _extract_urls_from_blocks(blocks, max_blocks=max_blocks)

    first_url = urls[0] if urls else None
    if not first_url:
        return {
            "ok": True,
            "status": "no_url",
            "inbox_page_id": inbox_id,
            "blocks_scanned": scanned,
        }

    # 2) bounce -> ejecutar URL real
    t0 = time.perf_counter()
    code, body = _call_daemon_bounce(first_url, timeout=timeout, debug=False)  # debug del daemon no hace falta aquí
    latency_ms = int((time.perf_counter() - t0) * 1000)

    # 3) si error HTTP -> escribir error en response (opcional), NO borrar inbox por defecto
    if code >= 400:
        err_text = f"[daemon bounce] HTTP {code}\n\n{body}"
        # escribimos error para visibilidad
        try:
            _clear_page_children(resp_id, timeout=timeout, max_blocks=max_blocks)
            _append_blocks(resp_id, _text_to_notion_blocks(err_text, title="ERROR"), timeout=timeout)
        except Exception:
            pass

        if not keep_inbox_on_error:
            try:
                _clear_page_children(inbox_id, timeout=timeout, max_blocks=max_blocks)
            except Exception:
                pass

        return {
            "ok": False,
            "status": "bounce_error",
            "url": first_url,
            "http_status": code,
            "latency_ms": latency_ms,
        }

    # 4) éxito -> borrar inbox y escribir response
    cleared_inbox = 0
    cleared_resp = 0
    try:
        cleared_inbox = _clear_page_children(inbox_id, timeout=timeout, max_blocks=max_blocks)
    except Exception:
        cleared_inbox = 0

    try:
        cleared_resp = _clear_page_children(resp_id, timeout=timeout, max_blocks=max_blocks)
    except Exception:
        cleared_resp = 0

    try:
        _append_blocks(resp_id, _text_to_notion_blocks(body, title=None), timeout=timeout)
    except Exception as e:
        return {
            "ok": False,
            "status": "write_response_failed",
            "url": first_url,
            "http_status": code,
            "latency_ms": latency_ms,
            "error": str(e),
        }

    out = {
        "ok": True,
        "status": "done",
        "url": first_url,
        "http_status": code,
        "latency_ms": latency_ms,
    }
    if debug:
        out.update({
            "inbox_page_id": inbox_id,
            "response_page_id": resp_id,
            "urls_found": len(urls),
            "blocks_scanned": scanned,
            "cleared_inbox_blocks": cleared_inbox,
            "cleared_response_blocks": cleared_resp,
        })
    return out


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@bp.route("/inbox_tick", methods=["GET", "OPTIONS"])
@bp.route("/inbox_test_bridge", methods=["GET", "OPTIONS"])
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def inbox_tick():
    if request.method == "OPTIONS":
        return ("", 204)

    # rate limiter global
    limiter = current_app.config["RATE_LIMITER"]
    if not limiter.ok():
        return _json_error("rate limit", 429)

    debug = _bool_q("debug", False)

    try:
        timeout = _float_q("timeout", float(_env("NOTION_TIMEOUT_SEC", "20")), min_v=0.5, max_v=120.0)
        max_blocks = _int_q("max_blocks", int(_env("NOTION_MAX_BLOCKS", "200")), min_v=1, max_v=5000)
        keep_inbox_on_error = _bool_q("keep_inbox_on_error", True)
    except ValueError as e:
        return _json_error(str(e), 400)

    try:
        result = _run_inbox_once(
            debug=debug,
            timeout=timeout,
            max_blocks=max_blocks,
            keep_inbox_on_error=keep_inbox_on_error,
        )
    except Exception as e:
        return _json_error(f"notion_inbox_bridge error: {e}", 502)

    # Respuesta ultra-minimal por defecto
    if not debug:
        if result.get("ok") and result.get("status") == "done":
            return RESPUESTA_LEER_NOTION, 200, {"Content-Type": "text/plain; charset=utf-8"}
        if result.get("status") == "no_url":
            return "NO_URL", 200, {"Content-Type": "text/plain; charset=utf-8"}
        return "ERROR", 502, {"Content-Type": "text/plain; charset=utf-8"}

    return jsonify(result)

