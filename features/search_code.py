from __future__ import annotations

"""
Feature: search_code (zoom progresivo sobre repos GitHub)

Qué hace:
- Busca texto en múltiples ficheros de un proyecto GitHub configurado.
- Devuelve hits con contexto de líneas (before/after) para "zoom" progresivo.
- Permite hacer zoom directo sobre un hit (path + line) sin releer todo el repo.

Endpoints (GET):
- /github/search_code
- /github/search_code_zoom

Auth:
- Igual que /github/* actual: X-BRIDGE-TOKEN (admin) o X-USER + X-PASS (o ?user= ?pass=)

Ejemplos:
- /github/search_code?project=mi_repo&q=require_token&before=2&after=4
- /github/search_code?project=mi_repo&q=dispatch&path=services/llm_providers.py&before=10&after=20
- /github/search_code_zoom?project=mi_repo&path=core/auth.py&line=12&before=30&after=60
"""

import fnmatch
import re
from typing import Any, Dict, List, Optional, Tuple

from flask import Blueprint, current_app, jsonify, request

from services.github_access import (
    parse_projects_full,
    resolve_project_token,
    user_allowed_for_project,
    verify_user_password,
)
from services.github_reader import get_file_bytes, list_paths_recursive

bp = Blueprint("search_code", __name__, url_prefix="/github")

# Límites (locales a la feature)
MAX_FILE_BYTES_FOR_SCAN = 8 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES_SCAN = 5 * 1024 * 1024
MAX_TOTAL_BYTES_SCAN = 25 * 1024 * 1024
DEFAULT_MAX_FILES_SCANNED = 300
MAX_FILES_SCANNED = 5000
DEFAULT_MAX_HITS = 20
MAX_HITS = 200
DEFAULT_MAX_HITS_PER_FILE = 10
MAX_HITS_PER_FILE = 100
MAX_CONTEXT_LINES = 200
MAX_QUERY_CHARS = 400


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


def _safe_path(p: str) -> str:
    p = (p or "").strip().lstrip("/")
    if not p:
        raise ValueError("path vacío")
    parts = p.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("path inválido")
    return p


def _safe_project_alias(project: str) -> str:
    project = (project or "").strip()
    if not project:
        raise ValueError("Falta project")
    return project


def _decode_text(data: bytes) -> Tuple[Optional[str], Optional[str]]:
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("utf-8-sig"), "utf-8-sig"
    except UnicodeDecodeError:
        return None, None


def _split_lines(text: str) -> List[str]:
    return text.splitlines()


def _parse_paths_multi() -> List[str]:
    out: List[str] = []

    for p in request.args.getlist("path"):
        if p and p.strip():
            out.append(p.strip())

    paths_csv = (request.args.get("paths") or "").strip()
    if paths_csv:
        out.extend([p.strip() for p in paths_csv.split(",") if p.strip()])

    seen = set()
    uniq: List[str] = []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


# ---------------------------------------------------------------------------
# Auth / ACL (autocontenido, mismo comportamiento que github_reader)
# ---------------------------------------------------------------------------

def _provided_bridge_token() -> str:
    return (request.headers.get("X-BRIDGE-TOKEN") or request.args.get("token") or "").strip()


def _expected_bridge_token() -> str:
    s = current_app.config["SETTINGS"]
    return (getattr(s, "BRIDGE_TOKEN", "") or "").strip()


def _is_master_bridge_auth() -> bool:
    expected = _expected_bridge_token()
    if not expected:
        return False
    provided = _provided_bridge_token()
    return bool(provided and provided == expected)


def _provided_user() -> str:
    return (request.headers.get("X-USER") or request.args.get("user") or "").strip()


def _provided_pass() -> str:
    return (
        request.headers.get("X-PASS")
        or request.args.get("pass")
        or request.args.get("password")
        or ""
    )


def _auth_identity():
    if _is_master_bridge_auth():
        return {"mode": "bridge", "user": None}

    username = _provided_user()
    password = _provided_pass()

    if not username or not password:
        return None

    ok, reason = verify_user_password(username, password)
    if not ok:
        return {"mode": "invalid", "reason": reason}

    return {"mode": "user", "user": username}


def _resolve_project_access(project_alias: str):
    identity = _auth_identity()
    if identity is None:
        return None, _json_error(
            "Unauthorized: usa X-BRIDGE-TOKEN (admin) o user/pass (+project). Recomendado: X-USER y X-PASS en headers.",
            401,
        )
    if identity.get("mode") == "invalid":
        return None, _json_error(f"Unauthorized: {identity.get('reason')}", 401)

    try:
        projects_full = parse_projects_full()
    except Exception as e:
        return None, _json_error(f"GITHUB_PROJECTS inválido: {e}", 500)

    if project_alias not in projects_full:
        return None, _json_error(f"Proyecto no configurado: {project_alias}", 404)

    if identity["mode"] == "user":
        username = identity["user"]
        if not user_allowed_for_project(username, project_alias):
            return None, _json_error("NO_PERMITIDO", 403, user=username, project=project_alias)

    try:
        gh_token = resolve_project_token(project_alias)
    except Exception as e:
        return None, _json_error(f"Token de proyecto no disponible: {e}", 500)

    return {
        "identity": identity,
        "project_cfg": projects_full[project_alias],
        "github_token": gh_token,
    }, None


# ---------------------------------------------------------------------------
# Búsqueda y formato de hits
# ---------------------------------------------------------------------------

def _extract_query_args() -> Dict[str, Any]:
    q = (request.args.get("q") or "").strip()
    if not q:
        raise ValueError("Falta q (texto a buscar)")
    if len(q) > MAX_QUERY_CHARS:
        raise ValueError(f"q demasiado largo (máx {MAX_QUERY_CHARS})")

    before = _int_arg("before", 2, min_value=0, max_value=MAX_CONTEXT_LINES)
    after = _int_arg("after", 4, min_value=0, max_value=MAX_CONTEXT_LINES)
    max_hits = _int_arg("max_hits", DEFAULT_MAX_HITS, min_value=1, max_value=MAX_HITS)
    max_hits_per_file = _int_arg(
        "max_hits_per_file", DEFAULT_MAX_HITS_PER_FILE, min_value=1, max_value=MAX_HITS_PER_FILE
    )
    max_files = _int_arg(
        "max_files", DEFAULT_MAX_FILES_SCANNED, min_value=1, max_value=MAX_FILES_SCANNED
    )
    max_total_bytes = _int_arg(
        "max_total_bytes",
        DEFAULT_MAX_TOTAL_BYTES_SCAN,
        min_value=1,
        max_value=MAX_TOTAL_BYTES_SCAN,
    )

    regex = _bool_arg("regex", False)
    whole_word = _bool_arg("whole_word", False)
    ignore_case = _bool_arg("ignore_case", True)
    numbered = _bool_arg("numbered", True)
    include_match_line = _bool_arg("include_match_line", True)
    path_q = (request.args.get("path_q") or "").strip().lower()
    prefix = (request.args.get("prefix") or "").strip().strip("/")
    name = (request.args.get("name") or "").strip()
    ext = (request.args.get("ext") or "").strip()
    glob_pat = (request.args.get("glob") or "").strip()

    if ext and not ext.startswith("."):
        ext = "." + ext

    return {
        "q": q,
        "before": before,
        "after": after,
        "max_hits": max_hits,
        "max_hits_per_file": max_hits_per_file,
        "max_files": max_files,
        "max_total_bytes": max_total_bytes,
        "regex": regex,
        "whole_word": whole_word,
        "ignore_case": ignore_case,
        "numbered": numbered,
        "include_match_line": include_match_line,
        "path_q": path_q,
        "prefix": prefix,
        "name": name,
        "ext": ext,
        "glob": glob_pat,
    }


def _compile_matcher(q: str, *, regex: bool, whole_word: bool, ignore_case: bool):
    if regex:
        flags = re.IGNORECASE if ignore_case else 0
        return re.compile(q, flags)

    literal = re.escape(q)
    if whole_word:
        literal = rf"\b{literal}\b"
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile(literal, flags)


def _filter_tree_entries(entries: List[Dict[str, Any]], args: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for e in entries:
        if e.get("type") != "blob":
            continue
        path = e.get("path", "")
        if not path:
            continue
        if args["prefix"] and not (path == args["prefix"] or path.startswith(args["prefix"] + "/")):
            continue
        if args["path_q"] and args["path_q"] not in path.lower():
            continue
        if args["name"] and path.split("/")[-1] != args["name"]:
            continue
        if args["ext"] and not path.endswith(args["ext"]):
            continue
        if args["glob"] and not fnmatch.fnmatch(path, args["glob"]):
            continue
        out.append(e)
    return out


def _make_block(lines: List[str], line_no: int, before: int, after: int, numbered: bool) -> Dict[str, Any]:
    total = len(lines)
    start = max(1, line_no - before)
    end = min(total, line_no + after)
    block = lines[start - 1 : end]

    if numbered:
        content = "\n".join(f"{i}: {ln}" for i, ln in enumerate(block, start=start))
    else:
        content = "\n".join(block)

    return {
        "range": {"start": start, "end": end},
        "has_more_before": start > 1,
        "has_more_after": end < total,
        "content": content,
    }


def _scan_file_for_hits(
    *,
    project: str,
    path: str,
    token: str,
    ref: Optional[str],
    pattern: re.Pattern,
    q_args: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Devuelve (hits, file_stats)."""
    try:
        data = get_file_bytes(project=project, path=path, token=token, ref=ref)
    except KeyError:
        return [], {"ok": False, "reason": "not_found"}
    except Exception as e:
        return [], {"ok": False, "reason": f"github error: {e}"}

    if len(data) > MAX_FILE_BYTES_FOR_SCAN:
        return [], {"ok": False, "reason": "too_large", "size": len(data)}

    text, encoding = _decode_text(data)
    if text is None:
        return [], {"ok": False, "reason": "binary_or_non_utf8", "size": len(data)}

    lines = _split_lines(text)
    total_lines = len(lines)
    hits: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines, start=1):
        m = pattern.search(line)
        if not m:
            continue

        block = _make_block(lines, idx, q_args["before"], q_args["after"], q_args["numbered"])
        hit = {
            "path": path,
            "line": idx,
            "range": block["range"],
            "has_more_before": block["has_more_before"],
            "has_more_after": block["has_more_after"],
            "content": block["content"],
            "zoom": {
                "path": path,
                "line": idx,
                "suggested_before": min(MAX_CONTEXT_LINES, max(10, q_args["before"] * 2 if q_args["before"] else 10)),
                "suggested_after": min(MAX_CONTEXT_LINES, max(20, q_args["after"] * 2 if q_args["after"] else 20)),
            },
        }
        if q_args["include_match_line"]:
            hit["match_line"] = line
        # columnas 1-based (aprox con primer match encontrado)
        hit["match_col"] = {"start": m.start() + 1, "end": m.end()} if m else None
        hits.append(hit)

        if len(hits) >= q_args["max_hits_per_file"]:
            break

    return hits, {
        "ok": True,
        "size": len(data),
        "encoding": encoding,
        "total_lines": total_lines,
        "hits": len(hits),
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@bp.get("/search_code")
def github_search_code():
    try:
        project = _safe_project_alias(request.args.get("project", ""))
        q_args = _extract_query_args()
    except ValueError as e:
        return _json_error(str(e), 400)

    token_ctx, err = _resolve_project_access(project)
    if err:
        return err

    gh_token = token_ctx["github_token"]
    ref = (request.args.get("ref") or "").strip() or None

    # Compilar patrón (regex o literal)
    try:
        pattern = _compile_matcher(
            q_args["q"],
            regex=q_args["regex"],
            whole_word=q_args["whole_word"],
            ignore_case=q_args["ignore_case"],
        )
    except re.error as e:
        return _json_error(f"regex inválida: {e}", 400)

    # Selección de paths: exact path(s) si se pasan; si no, árbol recursivo + filtros
    explicit_paths_raw = _parse_paths_multi()
    if explicit_paths_raw:
        try:
            candidate_paths = [_safe_path(p) for p in explicit_paths_raw]
        except ValueError as e:
            return _json_error(str(e), 400)
        truncated_tree = False
    else:
        try:
            entries, truncated_tree = list_paths_recursive(project=project, token=gh_token, ref=ref)
        except KeyError as e:
            return _json_error(str(e), 404)
        except Exception as e:
            return _json_error(f"github error: {e}", 502)
        entries = _filter_tree_entries(entries, q_args)
        candidate_paths = [e.get("path") for e in entries if e.get("path")]

    total_candidates = len(candidate_paths)
    candidate_paths = candidate_paths[: q_args["max_files"]]
    limited_by_max_files = total_candidates > len(candidate_paths)

    hits: List[Dict[str, Any]] = []
    files_stats: List[Dict[str, Any]] = []
    scanned_bytes = 0
    stop_reason = None

    for path in candidate_paths:
        if len(hits) >= q_args["max_hits"]:
            stop_reason = "max_hits"
            break

        file_hits, fstat = _scan_file_for_hits(
            project=project,
            path=path,
            token=gh_token,
            ref=ref,
            pattern=pattern,
            q_args=q_args,
        )

        if fstat.get("ok"):
            size = int(fstat.get("size") or 0)
            scanned_bytes += size
            files_stats.append({
                "path": path,
                "ok": True,
                "size": size,
                "total_lines": fstat.get("total_lines"),
                "hits": fstat.get("hits", 0),
            })
        else:
            files_stats.append({
                "path": path,
                "ok": False,
                "reason": fstat.get("reason"),
                "size": fstat.get("size"),
            })

        # cortar si excede bytes totales (después de procesar este fichero)
        if scanned_bytes > q_args["max_total_bytes"]:
            stop_reason = "max_total_bytes"
            break

        if not file_hits:
            continue

        for h in file_hits:
            h["id"] = len(hits) + 1
            h["zoom"]["search_code_zoom_url"] = (
                f"/github/search_code_zoom?project={project}&path={h['path']}&line={h['line']}"
                f"&before={h['zoom']['suggested_before']}&after={h['zoom']['suggested_after']}"
            )
            hits.append(h)
            if len(hits) >= q_args["max_hits"]:
                stop_reason = "max_hits"
                break

        if stop_reason == "max_hits":
            break

    files_scanned = len(files_stats)
    files_with_hits = sum(1 for f in files_stats if f.get("ok") and (f.get("hits") or 0) > 0)
    files_skipped_large = sum(1 for f in files_stats if f.get("reason") == "too_large")
    files_skipped_binary = sum(1 for f in files_stats if f.get("reason") == "binary_or_non_utf8")
    files_errors = sum(1 for f in files_stats if (not f.get("ok")) and f.get("reason") not in ("too_large", "binary_or_non_utf8"))

    return jsonify(
        ok=True,
        project=project,
        ref=ref,
        auth_mode=token_ctx["identity"]["mode"],
        auth_user=token_ctx["identity"].get("user"),
        query={
            "q": q_args["q"],
            "regex": q_args["regex"],
            "whole_word": q_args["whole_word"],
            "ignore_case": q_args["ignore_case"],
            "before": q_args["before"],
            "after": q_args["after"],
            "path": request.args.getlist("path") or None,
            "paths": request.args.get("paths"),
            "prefix": q_args["prefix"] or None,
            "path_q": q_args["path_q"] or None,
            "ext": q_args["ext"] or None,
            "name": q_args["name"] or None,
            "glob": q_args["glob"] or None,
        },
        limits={
            "max_hits": q_args["max_hits"],
            "max_hits_per_file": q_args["max_hits_per_file"],
            "max_files": q_args["max_files"],
            "max_total_bytes": q_args["max_total_bytes"],
            "max_file_bytes_for_scan": MAX_FILE_BYTES_FOR_SCAN,
        },
        scan={
            "truncated_tree": bool(truncated_tree),
            "total_candidate_files": total_candidates,
            "files_scanned": files_scanned,
            "files_with_hits": files_with_hits,
            "files_skipped_large": files_skipped_large,
            "files_skipped_binary": files_skipped_binary,
            "files_errors": files_errors,
            "scanned_bytes": scanned_bytes,
            "limited_by_max_files": limited_by_max_files,
            "stop_reason": stop_reason,
        },
        hits_count=len(hits),
        hits=hits,
        file_stats=files_stats,
    )


@bp.get("/search_code_zoom")
def github_search_code_zoom():
    """
    Zoom directo a un punto concreto (path + line) con before/after variables.
    Útil para ampliar contexto tras un hit de /search_code sin relanzar búsqueda global.
    """
    try:
        project = _safe_project_alias(request.args.get("project", ""))
        path = _safe_path(request.args.get("path", ""))
        line_no = _int_arg("line", 1, min_value=1)
        before = _int_arg("before", 20, min_value=0, max_value=MAX_CONTEXT_LINES)
        after = _int_arg("after", 40, min_value=0, max_value=MAX_CONTEXT_LINES)
    except ValueError as e:
        return _json_error(str(e), 400)

    token_ctx, err = _resolve_project_access(project)
    if err:
        return err

    gh_token = token_ctx["github_token"]
    ref = (request.args.get("ref") or "").strip() or None
    numbered = _bool_arg("numbered", True)

    try:
        data = get_file_bytes(project=project, path=path, token=gh_token, ref=ref)
    except KeyError as e:
        return _json_error(str(e), 404)
    except Exception as e:
        return _json_error(f"github error: {e}", 502)

    if len(data) > MAX_FILE_BYTES_FOR_SCAN:
        return _json_error(
            f"Fichero demasiado grande para /github/search_code_zoom ({len(data)} bytes)",
            413,
            path=path,
            size=len(data),
        )

    text, encoding = _decode_text(data)
    if text is None:
        return _json_error("Fichero binario o no UTF-8", 415, path=path, size=len(data))

    lines = _split_lines(text)
    total_lines = len(lines)
    if total_lines == 0:
        return jsonify(
            ok=True,
            project=project,
            ref=ref,
            path=path,
            encoding=encoding,
            size_bytes=len(data),
            total_lines=0,
            line=line_no,
            before=before,
            after=after,
            returned={"start": None, "end": None, "count": 0},
            content="",
        )

    if line_no > total_lines:
        return _json_error("line fuera de rango", 400, total_lines=total_lines)

    block = _make_block(lines, line_no, before, after, numbered)
    r = block["range"]

    return jsonify(
        ok=True,
        project=project,
        ref=ref,
        path=path,
        encoding=encoding,
        size_bytes=len(data),
        total_lines=total_lines,
        line=line_no,
        before=before,
        after=after,
        returned={"start": r["start"], "end": r["end"], "count": r["end"] - r["start"] + 1},
        has_more_before=block["has_more_before"],
        has_more_after=block["has_more_after"],
        content=block["content"],
        next_zoom={
            "before": min(MAX_CONTEXT_LINES, before * 2 if before else 20),
            "after": min(MAX_CONTEXT_LINES, after * 2 if after else 40),
        },
    )
