from __future__ import annotations

"""
Feature: notion_relay
Lee una página de Notion (por título o page_id), extrae URLs y las relanza por GET.

Endpoints (GET):
- /notion/relay_urls
- /notion/relay_test_bridge   (atajo: page_title=test_bridge)

Auth:
- Usa el mismo @require_token del bridge (X-BRIDGE-TOKEN / token según vuestro core.auth)

ENV esperadas:
- NOTION_TOKEN                  (obligatoria)
- NOTION_API_VERSION            (opcional, default: 2025-09-03)
- NOTION_DEFAULT_PAGE_TITLE     (opcional, default: test_bridge)

Ejemplos:
- /notion/relay_test_bridge?run=0
- /notion/relay_test_bridge?max_urls=3&timeout=20
- /notion/relay_urls?page_title=test_bridge&url_prefix=https://claude-bridge-i43j.onrender.com/&run=1
- /notion/relay_urls?page_id=<uuid>&only_contains=/api/message
"""

import json
import os
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib import error as urlerror
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from flask import Blueprint, current_app, jsonify, request

from core.auth import require_token

bp = Blueprint("notion_relay", __name__, url_prefix="/notion")

NOTION_API_BASE = "https://api.notion.com/v1"
DEFAULT_NOTION_API_VERSION = "2025-09-03"

# regex simple y práctico para URLs en texto
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


# ---------------------------------------------------------------------------
# Helpers genéricos
# ---------------------------------------------------------------------------

def _json_error(msg: str, status: int = 400, **extra):
    payload = {"ok": False, "error": msg}
    payload.update(extra)
    return jsonify(payload), status


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


# ---------------------------------------------------------------------------
# Notion API helpers
# ---------------------------------------------------------------------------

def _notion_token() -> str:
    # Preferimos SETTINGS si existe, pero también permitimos env directo
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
    Filtramos por object=page en cliente para reducir dependencia de cambios de schema del filter.
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
    # Search devuelve page object con properties; buscamos la property tipo title
    props = page_obj.get("properties") or {}
    for _prop_name, prop in props.items():
        if isinstance(prop, dict) and prop.get("type") == "title":
            parts = prop.get("title") or []
            txt = "".join((p.get("plain_text") or "") for p in parts if isinstance(p, dict))
            if txt.strip():
                return txt.strip()
    # Fallbacks
    if page_obj.get("title"):
        # Algunos payloads pueden incluir title directamente
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

    # 1) exact match por título
    for p in pages:
        if _extract_page_title(p).strip().lower() == title_norm:
            return p

    # 2) fallback: primero que contenga
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
# Extracción de URLs desde bloques de Notion
# ---------------------------------------------------------------------------

def _collect_urls_from_rich_text(rich_text_items: List[Dict[str, Any]]) -> List[str]:
    urls: List[str] = []
    for rt in rich_text_items or []:
        if not isinstance(rt, dict):
            continue

        # href explícito (ej. texto enlazado)
        href = rt.get("href")
        if isinstance(href, str) and href.startswith(("http://", "https://")):
            urls.append(href)

        # plain_text con URL escrita
        plain = rt.get("plain_text") or ""
        if plain:
            urls.extend(URL_RE.findall(plain))

        # text.link.url (cuando el rich_text es de tipo text con enlace)
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

    # Bloques con rich_text
    if btype in RICH_TEXT_BLOCK_TYPES:
        urls.extend(_collect_urls_from_rich_text(data.get("rich_text") or []))

    # Bloques con campo URL directo
    for field in ("url",):
        v = data.get(field)
        if isinstance(v, str) and v.startswith(("http://", "https://")):
            urls.append(v)

    # Algunos bloques embed/bookmark/link_preview llevan url directo
    # (ya cubierto por data["url"], pero mantenemos por claridad)

    # Archivos externos en image/file/pdf/video/audio
    if btype in ("image", "file", "pdf", "video", "audio"):
        file_obj = data.get("external") or {}
        ext_url = file_obj.get("url")
        if isinstance(ext_url, str) and ext_url.startswith(("http://", "https://")):
            urls.append(ext_url)

        file_obj2 = data.get("file") or {}
        file_url = file_obj2.get("url")
        if isinstance(file_url, str) and file_url.startswith(("http://", "https://")):
            urls.append(file_url)

        # caption también puede contener links
        caption = data.get("caption") or []
        if isinstance(caption, list):
            urls.extend(_collect_urls_from_rich_text(caption))

    # equation / callout icon etc. no necesarios aquí

    return urls


def _extract_urls_from_blocks(blocks: List[Dict[str, Any]]) -> List[str]:
    found: List[str] = []
    for b in blocks:
        found.extend(_extract_urls_from_block(b))
    return _dedupe_keep_order(found)


# ---------------------------------------------------------------------------
# Replay URLs helpers
# ---------------------------------------------------------------------------

def _relay_get_url(url: str, *, timeout: int = 20, body_preview_bytes: int = 1200) -> Dict[str, Any]:
    """
    Relanza una URL con GET y devuelve resumen de respuesta.
    """
    started = time.time()
    req = Request(
        url=url,
        method="GET",
        headers={
            "User-Agent": "claude-bridge-notion-relay/1.0",
            "Accept": "*/*",
            "Accept-Encoding": "identity",  # simplifica preview
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
    except ValueError as e:
        return _json_error(str(e), 400)

    run = _bool_arg("run", True)
    include_blocks_debug = _bool_arg("include_blocks_debug", False)

    page_id = (request.args.get("page_id") or "").strip()
    page_title = (request.args.get("page_title") or "").strip()

    if not page_id:
        page_title = page_title or default_page_title or (
            _get_settings_attr("NOTION_DEFAULT_PAGE_TITLE", None)
            or os.environ.get("NOTION_DEFAULT_PAGE_TITLE")
            or "test_bridge"
        )

    url_prefix = (request.args.get("url_prefix") or "").strip() or None
    only_contains = (request.args.get("only_contains") or "").strip() or None

    # Filtro práctico para evitar relanzar URLs externas si queréis:
    # host_equals toma precedencia si viene
    host_equals = (request.args.get("host_equals") or "").strip() or None
    only_current_host = _bool_arg("only_current_host", False)
    if only_current_host and not host_equals:
        host_equals = request.host  # ej. claude-bridge-i43j.onrender.com

    # 1) Resolver página
    notion_page_obj = None
    page_lookup = {"mode": None, "page_id": None, "page_title": None}

    try:
        if page_id:
            # No hace falta "retrieve page" para leer contenido; page_id sirve como block_id.
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

    # 4) Relay (opcional)
    relay_results: List[Dict[str, Any]] = []
    if run:
        for u in urls_filtered:
            relay_results.append(_relay_get_url(u, timeout=timeout, body_preview_bytes=body_preview_bytes))

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
        "urls": {
            "found_total": len(urls_all),
            "after_filters": len(urls_filtered),
            "items": urls_filtered,
        },
        "relay": {
            "run": run,
            "count": len(relay_results),
            "results": relay_results,
        },
    }

    if include_blocks_debug:
        resp["blocks_debug"] = [
            {"id": b.get("id"), "type": b.get("type"), "has_children": b.get("has_children", False)}
            for b in blocks[:500]
        ]

    return jsonify(resp)


@bp.route("/relay_urls", methods=["GET", "OPTIONS"])
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def relay_urls():
    return _relay_urls_impl(default_page_title=None)


@bp.route("/relay_test_bridge", methods=["GET", "OPTIONS"])
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def relay_test_bridge():
    return _relay_urls_impl(default_page_title="test_bridge")
