from __future__ import annotations

"""
Feature: notion_relay (v4)
Lee una página de Notion (por título o page_id), extrae URLs y las relanza por GET.

NUEVO:
- Si response_in_notion=true:
  - escribe el resultado del relay en una página de Notion "respuesta"
  - devuelve un mensaje fijo desde env RESPUESTA_LEER_NOTION
  - pensado para esquivar caché agresiva por URL exacta del cliente

Endpoints (GET):
- /notion/relay_urls
- /notion/relay_test_bridge   (atajo: page_title=test_bridge)

Auth:
- Usa el mismo @require_token del bridge (X-BRIDGE-TOKEN / token según vuestro core.auth)

ENV esperadas:
- NOTION_TOKEN                      (obligatoria)
- NOTION_API_VERSION                (opcional, default: 2025-09-03)
- NOTION_DEFAULT_PAGE_TITLE         (opcional, default: test_bridge)

ENV opcionales para evitar self-call (rewrite de host):
- RELAY_ORIGEN                      (ej: claude-bridge-i43j.onrender.com)
- RELAY_DESTINO                     (ej: claude-bridge2.onrender.com)

ENV opcionales para respuesta en Notion:
- NOTION_RESPONSE_PAGE_TITLE        (opcional, default: test_bridge_respuesta)
- RESPUESTA_LEER_NOTION             (opcional, texto que se devuelve a Claude)

Params útiles:
- run=1|0
- response_in_notion=1|0
- response_page_title=...
- response_page_id=...
- response_mode=replace|append
- response_include_full_json=1|0
- response_max_json_chars=...
"""

import hashlib
import json
import os
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib import error as urlerror
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from flask import Blueprint, current_app, jsonify, request

from core.auth import require_token

bp = Blueprint("notion_relay", __name__, url_prefix="/notion")

NOTION_API_BASE = "https://api.notion.com/v1"
DEFAULT_NOTION_API_VERSION = "2025-09-03"

# Regex simple y práctico para URLs en texto
URL_RE = re.compile(r"https?://[^\s<>\"]+")

# Tipos de block que suelen tener rich_text
RICH_TEXT_BLOCK_TYPES = {
    "paragraph",
    "heading_1",
    "heading_2",
    "heading_3",
    "bulleted_list_item",
    "numbered_list_item",
    "to_do",
    "toggle",
    "quote",
    "callout",
    "code",
    "template",
    "synced_block",
    "table_of_contents",
}

# Límites prácticos para Notion
NOTION_MAX_CHILDREN_PER_APPEND = 100
NOTION_TEXT_CHUNK = 1800  # conservador (rich_text text content suele tener límite por segmento)
DEFAULT_RESPONSE_JSON_MAX_CHARS = 20000
MAX_RESPONSE_JSON_MAX_CHARS = 200000


# ---------------------------------------------------------------------------
# Helpers genéricos
# ---------------------------------------------------------------------------

def _json_error(msg: str, status: int = 400, **extra):
    payload = {"ok": False, "error": msg}
    payload.update(extra)
    resp = jsonify(payload)
    # Anti-caché también en errores (útil para depurar desde Claude)
    resp.headers["Cache-Control"] = "no-store, no-cache, max-age=0, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp, status


def _bool_arg(name: str, default: bool = False) -> bool:
    v = request.args.get(name)
    if v is None:
        return default
    return v in ("1", "true", "True", "yes", "on")


def _int_arg(name: str, default: int, min_value: Optional[int] = None, max_value: Optional[int] = None) -> int:
    raw = request.args.get(name, str(default))
    try:
        n = int(raw)
    except Exception:
        raise ValueError(f"{name} inválido")
    if min_value is not None and n < min_value:
        raise ValueError(f"{name} debe ser >= {min_value}")
    if max_value is not None and n > max_value:
        raise ValueError(f"{name} debe ser <= {max_value}")
    return n


def _str_arg(name: str, default: str = "") -> str:
    return (request.args.get(name) or default).strip()


def _get_settings_attr(name: str, default=None):
    s = current_app.config.get("SETTINGS")
    return getattr(s, name, default) if s else default


def _rate_limit_ok():
    limiter = current_app.config.get("RATE_LIMITER")
    if limiter is None:
        return True
    try:
        return limiter.ok()
    except Exception:
        # No romper por cambios internos del limiter
        return True


def _dedupe_keep_order(items: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _truncate_text(s: str, n: int) -> str:
    if n <= 0:
        return ""
    if len(s) <= n:
        return s
    return s[: max(0, n - 1)] + "…"


def _chunks(s: str, size: int) -> List[str]:
    if size <= 0:
        return [s]
    if not s:
        return [""]
    return [s[i:i + size] for i in range(0, len(s), size)]


# ---------------------------------------------------------------------------
# Notion API helpers
# ---------------------------------------------------------------------------

def _notion_token() -> str:
    return (
        _get_settings_attr("NOTION_TOKEN", None)
        or os.environ.get("NOTION_TOKEN", "")
    ).strip()


def _notion_version() -> str:
    return (
        _get_settings_attr("NOTION_API_VERSION", None)
        or os.environ.get("NOTION_API_VERSION", "")
        or DEFAULT_NOTION_API_VERSION
    ).strip()


def _notion_headers(json_body: bool = False) -> Dict[str, str]:
    h = {
        "Authorization": f"Bearer {_notion_token()}",
        "Notion-Version": _notion_version(),
        "Accept": "application/json",
    }
    if json_body:
        h["Content-Type"] = "application/json"
    return h


def _http_json(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[dict] = None,
    timeout: int = 20,
) -> Tuple[int, Dict[str, Any]]:
    data = None
    req_headers = headers or {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    req = Request(url=url, method=method.upper(), headers=req_headers, data=data)

    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = getattr(resp, "status", 200)
            if not raw:
                return status, {}
            try:
                return status, json.loads(raw.decode("utf-8", errors="replace"))
            except Exception:
                return status, {"_raw": raw.decode("utf-8", errors="replace")}
    except urlerror.HTTPError as e:
        raw = e.read() if hasattr(e, "read") else b""
        try:
            payload = json.loads(raw.decode("utf-8", errors="replace")) if raw else {}
        except Exception:
            payload = {"_raw": raw.decode("utf-8", errors="replace")}
        return e.code, payload
    except Exception as e:
        return 599, {"error": str(e)}


def _notion_search_pages(query: str, *, timeout: int = 20, page_size: int = 25, max_pages: int = 5) -> List[Dict[str, Any]]:
    """
    Busca páginas en Notion (solo pages) usando /v1/search.
    """
    results: List[Dict[str, Any]] = []
    next_cursor = None
    pages_fetched = 0

    while True:
        body: Dict[str, Any] = {"page_size": page_size}
        if query:
            body["query"] = query
        if next_cursor:
            body["start_cursor"] = next_cursor

        status, payload = _http_json(
            "POST",
            f"{NOTION_API_BASE}/search",
            headers=_notion_headers(json_body=True),
            body=body,
            timeout=timeout,
        )
        if status != 200:
            raise RuntimeError(f"Notion search error ({status}): {payload}")

        for item in payload.get("results", []) or []:
            if item.get("object") == "page":
                results.append(item)

        pages_fetched += 1
        if not payload.get("has_more"):
            break
        next_cursor = payload.get("next_cursor")
        if not next_cursor:
            break
        if pages_fetched >= max_pages:
            break

    return results


def _extract_page_title(page_obj: Dict[str, Any]) -> str:
    props = page_obj.get("properties") or {}
    for _prop_name, prop in props.items():
        if isinstance(prop, dict) and prop.get("type") == "title":
            parts = prop.get("title") or []
            txt = "".join((p.get("plain_text") or "") for p in parts if isinstance(p, dict))
            if txt.strip():
                return txt.strip()
    if page_obj.get("title"):
        t = page_obj.get("title")
        if isinstance(t, list):
            txt = "".join((p.get("plain_text") or "") for p in t if isinstance(p, dict))
            return txt.strip()
    return ""


def _find_page_by_title(title: str, *, timeout: int = 20) -> Optional[Dict[str, Any]]:
    title_norm = title.strip().lower()
    if not title_norm:
        return None

    pages = _notion_search_pages(title, timeout=timeout)
    if not pages:
        return None

    # 1) exact match
    for p in pages:
        if _extract_page_title(p).strip().lower() == title_norm:
            return p

    # 2) contains
    for p in pages:
        t = _extract_page_title(p).strip().lower()
        if title_norm in t:
            return p

    return pages[0]


def _notion_get_block_children(block_id: str, *, timeout: int = 20, page_size: int = 100) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    next_cursor = None

    while True:
        url = f"{NOTION_API_BASE}/blocks/{block_id}/children?page_size={page_size}"
        if next_cursor:
            url += f"&start_cursor={next_cursor}"

        status, payload = _http_json(
            "GET",
            url,
            headers=_notion_headers(json_body=False),
            timeout=timeout,
        )
        if status != 200:
            raise RuntimeError(f"Notion block children error ({status}): {payload}")

        out.extend(payload.get("results", []) or [])
        if not payload.get("has_more"):
            break
        next_cursor = payload.get("next_cursor")
        if not next_cursor:
            break

    return out


def _notion_append_block_children(block_id: str, children: List[Dict[str, Any]], *, timeout: int = 20) -> Dict[str, Any]:
    status, payload = _http_json(
        "PATCH",
        f"{NOTION_API_BASE}/blocks/{block_id}/children",
        headers=_notion_headers(json_body=True),
        body={"children": children},
        timeout=timeout,
    )
    if status != 200:
        raise RuntimeError(f"Notion append children error ({status}): {payload}")
    return payload


def _notion_delete_block(block_id: str, *, timeout: int = 20) -> Dict[str, Any]:
    status, payload = _http_json(
        "DELETE",
        f"{NOTION_API_BASE}/blocks/{block_id}",
        headers=_notion_headers(json_body=False),
        timeout=timeout,
    )
    if status != 200:
        raise RuntimeError(f"Notion delete block error ({status}): {payload}")
    return payload


def _notion_clear_page_top_level_children(page_id: str, *, timeout: int = 20, max_delete: int = 500) -> Dict[str, Any]:
    children = _notion_get_block_children(page_id, timeout=timeout)
    deleted = 0
    errors: List[str] = []

    for b in children[:max_delete]:
        bid = b.get("id")
        if not bid:
            continue
        try:
            _notion_delete_block(bid, timeout=timeout)
            deleted += 1
        except Exception as e:
            errors.append(str(e))

    return {
        "found": len(children),
        "deleted": deleted,
        "errors_count": len(errors),
        "errors": errors[:10],
        "truncated_by_max_delete": len(children) > max_delete,
    }


def _walk_blocks_recursive(root_block_id: str, *, timeout: int = 20, max_blocks: int = 2000) -> List[Dict[str, Any]]:
    """
    DFS simple. Guardamos todos los bloques (incluidos anidados) hasta max_blocks.
    """
    all_blocks: List[Dict[str, Any]] = []
    stack: List[str] = [root_block_id]

    while stack:
        parent_id = stack.pop()
        children = _notion_get_block_children(parent_id, timeout=timeout)

        for b in children:
            all_blocks.append(b)
            if len(all_blocks) >= max_blocks:
                return all_blocks
            if b.get("has_children") is True and b.get("id"):
                stack.append(b["id"])

    return all_blocks


# ---------------------------------------------------------------------------
# Builders de bloques Notion (para escribir respuestas)
# ---------------------------------------------------------------------------

def _rt(text: str) -> List[Dict[str, Any]]:
    # Un único segmento de rich_text
    return [{"type": "text", "text": {"content": text}}]


def _block_paragraph(text: str) -> Dict[str, Any]:
    return {
        "object": "block",
        "type": "paragraph",
        "paragraph": {"rich_text": _rt(text)},
    }


def _block_heading_2(text: str) -> Dict[str, Any]:
    return {
        "object": "block",
        "type": "heading_2",
        "heading_2": {"rich_text": _rt(text)},
    }


def _block_heading_3(text: str) -> Dict[str, Any]:
    return {
        "object": "block",
        "type": "heading_3",
        "heading_3": {"rich_text": _rt(text)},
    }


def _block_bullet(text: str) -> Dict[str, Any]:
    return {
        "object": "block",
        "type": "bulleted_list_item",
        "bulleted_list_item": {"rich_text": _rt(text)},
    }


def _block_code(text: str, language: str = "plain text") -> Dict[str, Any]:
    return {
        "object": "block",
        "type": "code",
        "code": {"rich_text": _rt(text), "language": language},
    }


def _text_to_paragraph_blocks(text: str, *, max_chunk: int = NOTION_TEXT_CHUNK) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for part in _chunks(text, max_chunk):
        out.append(_block_paragraph(part if part else ""))
    return out


def _text_to_code_blocks(text: str, *, max_chunk: int = NOTION_TEXT_CHUNK, language: str = "plain text") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for part in _chunks(text, max_chunk):
        out.append(_block_code(part if part else "", language=language))
    return out


def _append_blocks_batched(parent_id: str, blocks: List[Dict[str, Any]], *, timeout: int = 20) -> Dict[str, Any]:
    batches = 0
    created_total = 0

    for i in range(0, len(blocks), NOTION_MAX_CHILDREN_PER_APPEND):
        chunk = blocks[i:i + NOTION_MAX_CHILDREN_PER_APPEND]
        payload = _notion_append_block_children(parent_id, chunk, timeout=timeout)
        created_total += len(payload.get("results", []) or [])
        batches += 1

    return {
        "batches": batches,
        "blocks_requested": len(blocks),
        "blocks_created_returned": created_total,
    }


def _compose_notion_report_blocks(
    *,
    source_page_info: Dict[str, Any],
    relay_results: List[Dict[str, Any]],
    response_notice: str,
    served_at_ms: int,
    relay_request_id: str,
    relay_version: str,
    rewrite_info: Dict[str, Any],
    response_in_notion_params: Dict[str, Any],
    include_full_json: bool,
    response_json_max_chars: int,
) -> List[Dict[str, Any]]:
    blocks: List[Dict[str, Any]] = []

    ts_iso = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(served_at_ms / 1000))

    blocks.append(_block_heading_2("Claude Bridge Relay Response"))
    blocks.append(_block_paragraph(f"request_id={relay_request_id}"))
    blocks.append(_block_paragraph(f"served_at_ms={served_at_ms} ({ts_iso})"))
    blocks.append(_block_paragraph(f"relay_version={relay_version}"))

    src_title = source_page_info.get("title") or ""
    src_id = source_page_info.get("page_id") or ""
    src_mode = source_page_info.get("mode") or ""
    blocks.append(_block_heading_3("Fuente"))
    blocks.append(_block_bullet(f"mode={src_mode}"))
    if src_title:
        blocks.append(_block_bullet(f"title={src_title}"))
    if src_id:
        blocks.append(_block_bullet(f"page_id={src_id}"))

    blocks.append(_block_heading_3("Relay"))
    blocks.append(_block_bullet(f"rewrite_enabled={rewrite_info.get('enabled')}"))
    blocks.append(_block_bullet(f"origin_host={rewrite_info.get('origin_host') or ''}"))
    blocks.append(_block_bullet(f"dest_host={rewrite_info.get('dest_host') or ''}"))
    blocks.append(_block_bullet(f"applied_count={rewrite_info.get('applied_count', 0)}"))
    blocks.append(_block_bullet(f"results={len(relay_results)}"))

    if response_notice:
        blocks.append(_block_heading_3("Mensaje para Claude"))
        for b in _text_to_paragraph_blocks(response_notice, max_chunk=NOTION_TEXT_CHUNK):
            blocks.append(b)

    blocks.append(_block_heading_3("Resumen de resultados"))
    if not relay_results:
        blocks.append(_block_bullet("Sin resultados"))
    else:
        for idx, r in enumerate(relay_results, start=1):
            status = r.get("status")
            ok = r.get("ok")
            elapsed = r.get("elapsed_ms")
            src = _truncate_text(r.get("source_url", ""), 180)
            relayed = _truncate_text(r.get("relayed_url", ""), 180)
            err = _truncate_text(r.get("error", ""), 180) if r.get("error") else ""
            blocks.append(_block_bullet(f"#{idx} ok={ok} status={status} elapsed_ms={elapsed}"))
            blocks.append(_block_bullet(f"#{idx} source_url={src}"))
            blocks.append(_block_bullet(f"#{idx} relayed_url={relayed}"))
            if err:
                blocks.append(_block_bullet(f"#{idx} error={err}"))

    # JSON completo/sanitizado opcional
    if include_full_json:
        blocks.append(_block_heading_3("JSON Relay (sanitizado)"))
        payload_for_json = {
            "relay_request_id": relay_request_id,
            "served_at_ms": served_at_ms,
            "relay_version": relay_version,
            "source_page_info": source_page_info,
            "rewrite": rewrite_info,
            "response_in_notion": response_in_notion_params,
            "relay_results": relay_results,
        }
        js = json.dumps(payload_for_json, ensure_ascii=False, indent=2)
        js = _truncate_text(js, response_json_max_chars)
        blocks.extend(_text_to_code_blocks(js, max_chunk=NOTION_TEXT_CHUNK, language="json"))

    return blocks


def _resolve_response_page(
    *,
    response_page_id: str,
    response_page_title: str,
    timeout: int,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Devuelve (page_info, error_msg)
    page_info: {"page_id","title","mode"}
    """
    if response_page_id:
        return {
            "page_id": response_page_id,
            "title": "",
            "mode": "page_id",
        }, None

    if not response_page_title:
        return None, "Falta response_page_title y response_page_id"

    p = _find_page_by_title(response_page_title, timeout=timeout)
    if not p:
        return None, f"Página de respuesta no encontrada: {response_page_title}"

    return {
        "page_id": p.get("id"),
        "title": _extract_page_title(p) or response_page_title,
        "mode": "search_title",
    }, None


# ---------------------------------------------------------------------------
# Extracción de URLs desde bloques de Notion
# ---------------------------------------------------------------------------

def _collect_urls_from_rich_text(rich_text_items: List[Dict[str, Any]]) -> List[str]:
    urls: List[str] = []
    for rt in rich_text_items or []:
        if not isinstance(rt, dict):
            continue

        href = rt.get("href")
        if isinstance(href, str) and href.startswith(("http://", "https://")):
            urls.append(href)

        plain = rt.get("plain_text") or ""
        if plain:
            urls.extend(URL_RE.findall(plain))

        text_obj = rt.get("text") or {}
        link_obj = text_obj.get("link") or {}
        link_url = link_obj.get("url")
        if isinstance(link_url, str) and link_url.startswith(("http://", "https://")):
            urls.append(link_url)

    return urls


def _extract_urls_from_block(block: Dict[str, Any]) -> List[str]:
    urls: List[str] = []

    btype = block.get("type")
    if not btype:
        return urls

    data = block.get(btype) or {}

    if btype in RICH_TEXT_BLOCK_TYPES:
        urls.extend(_collect_urls_from_rich_text(data.get("rich_text") or []))

    v = data.get("url")
    if isinstance(v, str) and v.startswith(("http://", "https://")):
        urls.append(v)

    if btype in ("image", "file", "pdf", "video", "audio"):
        file_obj = data.get("external") or {}
        ext_url = file_obj.get("url")
        if isinstance(ext_url, str) and ext_url.startswith(("http://", "https://")):
            urls.append(ext_url)

        file_obj2 = data.get("file") or {}
        file_url = file_obj2.get("url")
        if isinstance(file_url, str) and file_url.startswith(("http://", "https://")):
            urls.append(file_url)

        caption = data.get("caption") or []
        if isinstance(caption, list):
            urls.extend(_collect_urls_from_rich_text(caption))

    return urls


def _extract_urls_from_blocks(blocks: List[Dict[str, Any]]) -> List[str]:
    found: List[str] = []
    for b in blocks:
        found.extend(_extract_urls_from_block(b))
    return _dedupe_keep_order(found)


# ---------------------------------------------------------------------------
# Relay URLs helpers (HTTP + rewrite de host + anti-caché interno)
# ---------------------------------------------------------------------------

def _normalize_host_for_compare(host: Optional[str]) -> str:
    if not host:
        return ""
    h = host.strip().lower()
    if h.startswith("http://") or h.startswith("https://"):
        try:
            h = urlparse(h).netloc.lower()
        except Exception:
            pass
    return h.strip("/")


def _relay_rewrite_config() -> Dict[str, Any]:
    origin = (
        _get_settings_attr("RELAY_ORIGEN", None)
        or os.environ.get("RELAY_ORIGEN", "")
    )
    dest = (
        _get_settings_attr("RELAY_DESTINO", None)
        or os.environ.get("RELAY_DESTINO", "")
    )

    origin_h = _normalize_host_for_compare(origin)
    dest_h = _normalize_host_for_compare(dest)
    req_h = _normalize_host_for_compare(request.host)

    enabled = bool(origin_h and dest_h and origin_h != dest_h)

    return {
        "enabled": enabled,
        "origin_host": origin_h,
        "dest_host": dest_h,
        "request_host": req_h,
    }


def _rewrite_url_for_relay(url: str) -> Tuple[str, Dict[str, Any]]:
    cfg = _relay_rewrite_config()
    info = {
        "rewritten": False,
        "reason": None,
        "from_host": None,
        "to_host": None,
    }

    if not cfg["enabled"]:
        info["reason"] = "disabled_or_invalid_env"
        return url, info

    # Evita rebotes: solo reescribir si la request entró por el host origen
    if cfg["request_host"] != cfg["origin_host"]:
        info["reason"] = "request_not_on_origin_host"
        return url, info

    try:
        sp = urlsplit(url)
    except Exception:
        info["reason"] = "invalid_url"
        return url, info

    if not sp.scheme or not sp.netloc:
        info["reason"] = "missing_scheme_or_host"
        return url, info

    current_host = _normalize_host_for_compare(sp.netloc)
    if current_host != cfg["origin_host"]:
        info["reason"] = "url_host_not_origin"
        return url, info

    rewritten = urlunsplit((sp.scheme, cfg["dest_host"], sp.path, sp.query, sp.fragment))
    info.update({
        "rewritten": True,
        "reason": "ok",
        "from_host": cfg["origin_host"],
        "to_host": cfg["dest_host"],
    })
    return rewritten, info


def _append_query_param(url: str, key: str, value: str) -> str:
    try:
        sp = urlsplit(url)
        q = parse_qsl(sp.query, keep_blank_values=True)
        q.append((key, value))
        new_query = urlencode(q, doseq=True)
        return urlunsplit((sp.scheme, sp.netloc, sp.path, new_query, sp.fragment))
    except Exception:
        return url


def _relay_version_seed(urls_filtered: List[str]) -> str:
    joined = "\n".join(urls_filtered)
    return hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()[:16]


def _relay_get_url(url: str, *, timeout: int = 20, body_preview_bytes: int = 1200) -> Dict[str, Any]:
    started = time.time()
    req = Request(
        url=url,
        method="GET",
        headers={
            "User-Agent": "claude-bridge-notion-relay/1.0",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-cache, no-store, max-age=0",
            "Pragma": "no-cache",
        },
    )

    try:
        with urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            raw = resp.read(body_preview_bytes)
            elapsed_ms = round((time.time() - started) * 1000, 1)
            headers = dict(resp.headers.items())
            return {
                "ok": True,
                "url": url,
                "status": status,
                "final_url": getattr(resp, "geturl", lambda: url)(),
                "elapsed_ms": elapsed_ms,
                "content_type": headers.get("Content-Type"),
                "content_length": headers.get("Content-Length"),
                "body_preview": raw.decode("utf-8", errors="replace"),
            }
    except urlerror.HTTPError as e:
        raw = e.read(body_preview_bytes) if hasattr(e, "read") else b""
        elapsed_ms = round((time.time() - started) * 1000, 1)
        return {
            "ok": False,
            "url": url,
            "status": e.code,
            "elapsed_ms": elapsed_ms,
            "error": f"HTTPError {e.code}",
            "body_preview": raw.decode("utf-8", errors="replace"),
        }
    except Exception as e:
        elapsed_ms = round((time.time() - started) * 1000, 1)
        return {
            "ok": False,
            "url": url,
            "status": None,
            "elapsed_ms": elapsed_ms,
            "error": str(e),
        }


def _filter_urls(
    urls: List[str],
    *,
    url_prefix: Optional[str],
    only_contains: Optional[str],
    host_equals: Optional[str],
) -> List[str]:
    out = []
    for u in urls:
        if url_prefix and not u.startswith(url_prefix):
            continue
        if only_contains and only_contains not in u:
            continue
        if host_equals:
            try:
                if urlparse(u).netloc != host_equals:
                    continue
            except Exception:
                continue
        out.append(u)
    return out


# ---------------------------------------------------------------------------
# Sanitizado relay para guardar/devolver
# ---------------------------------------------------------------------------

def _sanitize_relay_result_for_storage(r: Dict[str, Any], *, max_preview_chars: int = 4000) -> Dict[str, Any]:
    out = {
        "ok": r.get("ok"),
        "status": r.get("status"),
        "elapsed_ms": r.get("elapsed_ms"),
        "content_type": r.get("content_type"),
        "content_length": r.get("content_length"),
        "error": r.get("error"),
        "source_url": r.get("source_url") or r.get("url"),
        "relayed_url": r.get("relayed_url") or r.get("final_url") or r.get("url"),
        "host_rewrite": r.get("host_rewrite"),
    }
    if "body_preview" in r:
        out["body_preview"] = _truncate_text(r.get("body_preview") or "", max_preview_chars)
    return out


def _sanitize_relay_results_for_storage(results: List[Dict[str, Any]], *, max_preview_chars: int = 4000) -> List[Dict[str, Any]]:
    return [_sanitize_relay_result_for_storage(r, max_preview_chars=max_preview_chars) for r in results]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def _relay_urls_impl(default_page_title: Optional[str] = None):
    if request.method == "OPTIONS":
        return ("", 204)

    if not _rate_limit_ok():
        return _json_error("rate limit", 429)

    notion_token = _notion_token()
    if not notion_token:
        return _json_error("Falta NOTION_TOKEN en entorno", 500)

    try:
        timeout = _int_arg("timeout", 20, min_value=1, max_value=120)
        max_urls = _int_arg("max_urls", 20, min_value=1, max_value=200)
        max_blocks = _int_arg("max_blocks", 2000, min_value=1, max_value=20000)
        body_preview_bytes = _int_arg("body_preview_bytes", 1200, min_value=100, max_value=20000)
        response_json_max_chars = _int_arg(
            "response_max_json_chars",
            DEFAULT_RESPONSE_JSON_MAX_CHARS,
            min_value=1000,
            max_value=MAX_RESPONSE_JSON_MAX_CHARS,
        )
    except ValueError as e:
        return _json_error(str(e), 400)

    run = _bool_arg("run", True)
    include_blocks_debug = _bool_arg("include_blocks_debug", False)
    include_rewrite_debug = _bool_arg("include_rewrite_debug", False)
    include_freshness_debug = _bool_arg("include_freshness_debug", True)

    # Cache-busting interno (no depende del cliente)
    relay_cache_bust = _bool_arg("relay_cache_bust", True)
    relay_cache_bust_mode = _str_arg("relay_cache_bust_mode", "version").lower()
    if relay_cache_bust_mode not in ("version", "timestamp"):
        relay_cache_bust_mode = "version"

    # Nuevo: guardar respuesta en Notion para esquivar caché cliente
    response_in_notion = _bool_arg("response_in_notion", False)
    response_mode = _str_arg("response_mode", "replace").lower()
    if response_mode not in ("replace", "append"):
        response_mode = "replace"

    response_page_id = _str_arg("response_page_id", "")
    response_page_title = _str_arg(
        "response_page_title",
        _get_settings_attr("NOTION_RESPONSE_PAGE_TITLE", None)
        or os.environ.get("NOTION_RESPONSE_PAGE_TITLE")
        or "test_bridge_respuesta",
    )

    response_include_full_json = _bool_arg("response_include_full_json", True)

    response_notice = (
        _get_settings_attr("RESPUESTA_LEER_NOTION", None)
        or os.environ.get("RESPUESTA_LEER_NOTION", "")
        or "Claude, la respuesta debes leerla en Notion porque aquí puede estar cacheada."
    )

    page_id = _str_arg("page_id", "")
    page_title = _str_arg("page_title", "")

    if not page_id:
        page_title = page_title or default_page_title or (
            _get_settings_attr("NOTION_DEFAULT_PAGE_TITLE", None)
            or os.environ.get("NOTION_DEFAULT_PAGE_TITLE")
            or "test_bridge"
        )

    url_prefix = _str_arg("url_prefix", "") or None
    only_contains = _str_arg("only_contains", "") or None

    host_equals = _str_arg("host_equals", "") or None
    only_current_host = _bool_arg("only_current_host", False)
    if only_current_host and not host_equals:
        host_equals = request.host

    served_at_ms = int(time.time() * 1000)
    relay_request_id = f"nr-{served_at_ms}-{os.getpid()}"

    # 1) Resolver página origen
    notion_page_obj = None
    page_lookup = {"mode": None, "page_id": None, "page_title": None}

    try:
        if page_id:
            page_lookup["mode"] = "page_id"
            page_lookup["page_id"] = page_id
        else:
            notion_page_obj = _find_page_by_title(page_title, timeout=timeout)
            if not notion_page_obj:
                return _json_error("Página de Notion no encontrada", 404, page_title=page_title)
            page_id = notion_page_obj.get("id")
            page_lookup["mode"] = "search_title"
            page_lookup["page_id"] = page_id
            page_lookup["page_title"] = _extract_page_title(notion_page_obj) or page_title
    except Exception as e:
        return _json_error(f"Error resolviendo página Notion: {e}", 502)

    if not page_id:
        return _json_error("No se pudo resolver page_id de Notion", 500)

    # 2) Leer bloques recursivamente
    try:
        blocks = _walk_blocks_recursive(page_id, timeout=timeout, max_blocks=max_blocks)
    except Exception as e:
        return _json_error(f"Error leyendo bloques de Notion: {e}", 502, page_id=page_id)

    # 3) Extraer URLs + filtros
    urls_all = _extract_urls_from_blocks(blocks)
    urls_filtered = _filter_urls(
        urls_all,
        url_prefix=url_prefix,
        only_contains=only_contains,
        host_equals=host_equals,
    )
    urls_filtered = urls_filtered[:max_urls]

    relay_version = _relay_version_seed(urls_filtered)

    # 4) Relay (opcional) con rewrite de host + cache-busting interno
    relay_results: List[Dict[str, Any]] = []
    rewrite_applied = 0
    rewrite_debug: List[Dict[str, Any]] = []

    if run:
        for u in urls_filtered:
            relay_url, rw = _rewrite_url_for_relay(u)
            if rw.get("rewritten"):
                rewrite_applied += 1

            if relay_cache_bust:
                if relay_cache_bust_mode == "timestamp":
                    relay_url = _append_query_param(relay_url, "_relay_cb", str(served_at_ms))
                else:
                    relay_url = _append_query_param(relay_url, "_relay_v", relay_version)

            res = _relay_get_url(relay_url, timeout=timeout, body_preview_bytes=body_preview_bytes)
            res["source_url"] = u
            res["relayed_url"] = relay_url
            res["host_rewrite"] = rw
            relay_results.append(res)

            rewrite_debug.append({
                "source_url": u,
                "relayed_url": relay_url,
                "rewritten": rw.get("rewritten", False),
                "reason": rw.get("reason"),
            })

    rewrite_cfg = _relay_rewrite_config()
    rewrite_info = {
        "enabled": rewrite_cfg["enabled"],
        "origin_host": rewrite_cfg["origin_host"],
        "dest_host": rewrite_cfg["dest_host"],
        "request_host": rewrite_cfg["request_host"],
        "applied_count": rewrite_applied if run else 0,
    }

    # 5) Opcional: escribir respuesta en Notion
    notion_response_write: Dict[str, Any] = {
        "enabled": response_in_notion,
        "ok": None,
        "page": None,
        "mode": response_mode,
        "cleared": None,
        "append": None,
        "error": None,
    }

    relay_results_sanitized = _sanitize_relay_results_for_storage(relay_results, max_preview_chars=4000)

    if response_in_notion and run:
        try:
            page_info, page_err = _resolve_response_page(
                response_page_id=response_page_id,
                response_page_title=response_page_title,
                timeout=timeout,
            )
            if page_err or not page_info:
                raise RuntimeError(page_err or "No se pudo resolver página de respuesta")

            source_page_info = {
                "mode": page_lookup.get("mode"),
                "page_id": page_lookup.get("page_id"),
                "title": page_lookup.get("page_title") or page_title or "",
            }

            blocks_to_write = _compose_notion_report_blocks(
                source_page_info=source_page_info,
                relay_results=relay_results_sanitized,
                response_notice=response_notice,
                served_at_ms=served_at_ms,
                relay_request_id=relay_request_id,
                relay_version=relay_version,
                rewrite_info=rewrite_info,
                response_in_notion_params={
                    "enabled": True,
                    "response_mode": response_mode,
                    "response_include_full_json": response_include_full_json,
                },
                include_full_json=response_include_full_json,
                response_json_max_chars=response_json_max_chars,
            )

            cleared = None
            if response_mode == "replace":
                cleared = _notion_clear_page_top_level_children(page_info["page_id"], timeout=timeout)

            appended = _append_blocks_batched(page_info["page_id"], blocks_to_write, timeout=timeout)

            notion_response_write.update({
                "ok": True,
                "page": page_info,
                "cleared": cleared,
                "append": appended,
            })
        except Exception as e:
            notion_response_write.update({
                "ok": False,
                "error": str(e),
            })

    # 6) Respuesta final
    # Si response_in_notion=true, devolvemos el mensaje fijo para Claude y resumimos la carga,
    # para no depender de leer aquí el body (que puede venir cacheado en cliente).
    relay_public_results: List[Dict[str, Any]]
    if response_in_notion:
        relay_public_results = [
            {
                "ok": r.get("ok"),
                "status": r.get("status"),
                "elapsed_ms": r.get("elapsed_ms"),
                "source_url": r.get("source_url"),
                "relayed_url": r.get("relayed_url"),
                "error": r.get("error"),
            }
            for r in relay_results
        ]
    else:
        relay_public_results = relay_results

    resp: Dict[str, Any] = {
        "ok": True,
        "feature": "notion_relay",
        "notion": {
            "api_version": _notion_version(),
            "page_lookup": page_lookup,
            "blocks_read": len(blocks),
            "max_blocks": max_blocks,
        },
        "filters": {
            "url_prefix": url_prefix,
            "only_contains": only_contains,
            "host_equals": host_equals,
            "only_current_host": only_current_host,
            "max_urls": max_urls,
        },
        "rewrite": rewrite_info,
        "freshness": {
            "relay_cache_bust": relay_cache_bust,
            "relay_cache_bust_mode": relay_cache_bust_mode,
            "relay_version": relay_version,
        },
        "urls": {
            "found_total": len(urls_all),
            "after_filters": len(urls_filtered),
            "items": urls_filtered,
        },
        "relay": {
            "run": run,
            "count": len(relay_public_results),
            "results": relay_public_results,
        },
        "response_in_notion": {
            "enabled": response_in_notion,
            "notice": response_notice if response_in_notion else None,
            "write": notion_response_write,
        },
    }

    # Mensaje top-level para que Claude lo tenga muy a mano
    if response_in_notion:
        resp["message"] = response_notice

    if include_blocks_debug:
        resp["blocks_debug"] = [
            {"id": b.get("id"), "type": b.get("type"), "has_children": b.get("has_children", False)}
            for b in blocks[:500]
        ]

    if include_rewrite_debug:
        resp["rewrite_debug"] = rewrite_debug

    if include_freshness_debug:
        resp["debug_freshness"] = {
            "served_at_ms": served_at_ms,
            "relay_request_id": relay_request_id,
        }

    response = jsonify(resp)
    # Anti-caché en la respuesta del relay (importante para capas intermedias/cliente)
    response.headers["Cache-Control"] = "no-store, no-cache, max-age=0, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Relay-Request-Id"] = relay_request_id
    response.headers["X-Relay-Served-At-Ms"] = str(served_at_ms)
    return response


@bp.route("/relay_urls", methods=["GET", "OPTIONS"])
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def relay_urls():
    return _relay_urls_impl(default_page_title=None)


@bp.route("/relay_test_bridge", methods=["GET", "OPTIONS"])
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def relay_test_bridge():
    return _relay_urls_impl(default_page_title="test_bridge")
