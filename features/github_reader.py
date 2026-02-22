from __future__ import annotations

import base64
import fnmatch
from typing import Any, Dict, List, Optional, Tuple

from flask import Blueprint, Response, current_app, jsonify, request

from core.auth import require_token
from services.github_reader import (
    get_file_bytes,
    get_file_meta,
    list_paths_recursive,
    parse_project_map,
)

bp = Blueprint("github_reader", __name__, url_prefix="/github")

# ---- Límites (ajústalos a tu gusto) -----------------------------------------

MAX_PATHS_LIMIT = 20000           # máximo paths devueltos por /paths
DEFAULT_PATHS_LIMIT = 5000

MAX_TEXT_BYTES = 2 * 1024 * 1024  # /github/file (JSON) -> 2MB
MAX_FILE_BYTES_FOR_LINES = 8 * 1024 * 1024  # /github/file_lines / file_chunk / find_in_file
MAX_LINES_SPAN = 1200             # líneas máximas por petición en /file_lines
MAX_CHUNK_LINES = 1200            # chunk_lines máximas
DEFAULT_CHUNK_LINES = 200

MAX_READMANY_FILES = 20           # /readmany: nº máx ficheros
MAX_READMANY_TOTAL_BYTES = 3 * 1024 * 1024  # suma de bytes devueltos (texto/binario base64 no cuenta aquí; se limita raw)
MAX_FIND_HITS = 50                # /find_in_file


# ---- Helpers ----------------------------------------------------------------

def _json_error(msg: str, status: int = 400, **extra):
    payload = {"ok": False, "error": msg}
    payload.update(extra)
    return jsonify(payload), status


def _get_bridge_token() -> str:
    s = current_app.config["SETTINGS"]
    return (getattr(s, "GITHUB_TOKEN", "") or "").strip()


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
    # higiene básica anti-traversal
    parts = p.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("path inválido")
    return p


def _decode_text(data: bytes) -> Tuple[Optional[str], Optional[str]]:
    # Primero UTF-8 normal, luego UTF-8 BOM
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("utf-8-sig"), "utf-8-sig"
    except UnicodeDecodeError:
        return None, None


def _split_lines(text: str) -> List[str]:
    # splitlines() mantiene compatibilidad con CRLF/LF y no incluye saltos
    return text.splitlines()


def _apply_path_filters(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filtros soportados por query:
      - prefix=src
      - kind=files|dirs|all
      - q=texto (substring sobre path)
      - name=main.py (nombre exacto del fichero)
      - ext=.py  (o py)
      - glob=**/*.py | *.md | src/*/main.py (fnmatch simple)
      - min_size, max_size (solo blobs)
    """
    prefix = (request.args.get("prefix") or "").strip().strip("/")
    kind = (request.args.get("kind") or "files").strip().lower()  # files | dirs | all
    q = (request.args.get("q") or "").strip().lower()
    name = (request.args.get("name") or "").strip()
    ext = (request.args.get("ext") or "").strip()
    glob_pat = (request.args.get("glob") or "").strip()
    min_size_raw = request.args.get("min_size")
    max_size_raw = request.args.get("max_size")

    if ext and not ext.startswith("."):
        ext = "." + ext

    min_size = None
    max_size = None
    if min_size_raw:
        try:
            min_size = int(min_size_raw)
        except Exception:
            raise ValueError("min_size inválido")
    if max_size_raw:
        try:
            max_size = int(max_size_raw)
        except Exception:
            raise ValueError("max_size inválido")

    out = []

    for e in entries:
        path = e.get("path", "")
        typ = e.get("type")
        size = e.get("size")

        if prefix and not (path == prefix or path.startswith(prefix + "/")):
            continue

        if kind == "files" and typ != "blob":
            continue
        if kind == "dirs" and typ != "tree":
            continue
        # kind=all -> no filtra

        if q and q not in path.lower():
            continue

        if name:
            if path.split("/")[-1] != name:
                continue

        if ext:
            if not path.endswith(ext):
                continue

        if glob_pat:
            if not fnmatch.fnmatch(path, glob_pat):
                continue

        if typ == "blob":
            if min_size is not None and (size is None or size < min_size):
                continue
            if max_size is not None and (size is None or size > max_size):
                continue

        out.append(e)

    return out


def _entries_to_public(entries: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    return [
        {
            "path": e.get("path"),
            "type": e.get("type"),   # blob/tree/commit
            "size": e.get("size"),   # solo blobs
            "sha": e.get("sha"),
            "mode": e.get("mode"),
        }
        for e in entries[:limit]
    ]


def _parse_paths_multi() -> List[str]:
    """
    Soporta:
      ?path=a&path=b&path=c
      ?paths=a,b,c
      ?paths_json=["a","b"]
    """
    out: List[str] = []

    # repetido path=
    for p in request.args.getlist("path"):
        if p and p.strip():
            out.append(p.strip())

    # paths=a,b,c
    paths_csv = (request.args.get("paths") or "").strip()
    if paths_csv:
        out.extend([p.strip() for p in paths_csv.split(",") if p.strip()])

    # No hacemos JSON parsing aquí para mantener simple/seguro en GET
    # (si quieres, lo añadimos luego)
    # Deduplicar preservando orden
    seen = set()
    uniq: List[str] = []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _safe_project_alias(project: str) -> str:
    project = (project or "").strip()
    if not project:
        raise ValueError("Falta project")
    return project


# ---- Endpoints ---------------------------------------------------------------

@bp.get("/projects")
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def github_projects():
    """
    Lista aliases de proyectos configurados en GITHUB_PROJECTS.
    Por defecto no revela owner/repo, solo alias y ref.
    """
    try:
        projects = parse_project_map()
    except Exception as e:
        return _json_error(f"GITHUB_PROJECTS inválido: {e}", 500)

    reveal = _bool_arg("reveal", False)  # opcional para ti, con auth
    data = []
    for alias, cfg in projects.items():
        item = {"project": alias, "ref": cfg.get("ref", "main")}
        if reveal:
            item["owner"] = cfg.get("owner")
            item["repo"] = cfg.get("repo")
        data.append(item)

    data.sort(key=lambda x: x["project"])
    return jsonify(ok=True, count=len(data), projects=data)


@bp.get("/paths")
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def github_paths():
    """
    Lista paths recursivos de un proyecto alias.

    Ejemplos:
      /github/paths?project=proyecto_xx
      /github/paths?project=proyecto_xx&prefix=src
      /github/paths?project=proyecto_xx&name=main.py
      /github/paths?project=proyecto_xx&ext=py
      /github/paths?project=proyecto_xx&glob=**/*.md
      /github/paths?project=proyecto_xx&q=requirements
      /github/paths?project=proyecto_xx&kind=dirs
    """
    token = _get_bridge_token()
    if not token:
        return _json_error("Falta GITHUB_TOKEN", 500)

    try:
        project = _safe_project_alias(request.args.get("project", ""))
    except ValueError as e:
        return _json_error(str(e), 400)

    ref = (request.args.get("ref") or "").strip() or None
    limit = request.args.get("limit", str(DEFAULT_PATHS_LIMIT))
    try:
        limit_n = int(limit)
    except Exception:
        return _json_error("limit inválido", 400)
    limit_n = max(1, min(limit_n, MAX_PATHS_LIMIT))

    try:
        entries, truncated = list_paths_recursive(project=project, token=token, ref=ref)
        entries = _apply_path_filters(entries)
    except KeyError as e:
        return _json_error(str(e), 404)
    except ValueError as e:
        return _json_error(str(e), 400)
    except Exception as e:
        return _json_error(f"github error: {e}", 502)

    # Stats básicas antes de recortar
    total_filtered = len(entries)
    files_count = sum(1 for e in entries if e.get("type") == "blob")
    dirs_count = sum(1 for e in entries if e.get("type") == "tree")

    entries_public = _entries_to_public(entries, limit_n)

    return jsonify(
        ok=True,
        project=project,
        ref=ref,
        truncated=truncated,          # del árbol GitHub
        total_filtered=total_filtered,
        returned=len(entries_public),
        limit_applied=limit_n,
        counts={"files": files_count, "dirs": dirs_count},
        entries=entries_public,
    )


@bp.get("/find")
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def github_find():
    """
    Alias de /paths orientado a búsqueda (mismos filtros).
    Devuelve resultado más compacto.
    """
    token = _get_bridge_token()
    if not token:
        return _json_error("Falta GITHUB_TOKEN", 500)

    try:
        project = _safe_project_alias(request.args.get("project", ""))
    except ValueError as e:
        return _json_error(str(e), 400)

    ref = (request.args.get("ref") or "").strip() or None
    try:
        limit_n = _int_arg("limit", 200, min_value=1, max_value=5000)
    except ValueError as e:
        return _json_error(str(e), 400)

    try:
        entries, truncated = list_paths_recursive(project=project, token=token, ref=ref)
        entries = _apply_path_filters(entries)
    except KeyError as e:
        return _json_error(str(e), 404)
    except ValueError as e:
        return _json_error(str(e), 400)
    except Exception as e:
        return _json_error(f"github error: {e}", 502)

    items = []
    for e in entries[:limit_n]:
        items.append({
            "path": e.get("path"),
            "type": e.get("type"),
            "size": e.get("size"),
        })

    return jsonify(
        ok=True,
        project=project,
        ref=ref,
        query={
            "q": request.args.get("q"),
            "name": request.args.get("name"),
            "ext": request.args.get("ext"),
            "glob": request.args.get("glob"),
            "prefix": request.args.get("prefix"),
            "kind": request.args.get("kind", "files"),
        },
        truncated_tree=truncated,
        total_matches=len(entries),
        returned=len(items),
        items=items,
    )


@bp.get("/file")
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def github_file():
    """
    Devuelve contenido de fichero para Claude.
    Por defecto: texto UTF-8.
    Si es binario/no UTF-8:
      - binary=error  -> 415
      - binary=base64 -> devuelve content en base64 (ojo contexto)
    """
    token = _get_bridge_token()
    if not token:
        return _json_error("Falta GITHUB_TOKEN", 500)

    try:
        project = _safe_project_alias(request.args.get("project", ""))
        path = _safe_path(request.args.get("path", ""))
    except ValueError as e:
        return _json_error(str(e), 400)

    ref = (request.args.get("ref") or "").strip() or None
    binary_mode = (request.args.get("binary") or "error").strip().lower()  # error | base64
    include_meta = _bool_arg("meta", True)
    include_line_count = _bool_arg("line_count", False)

    try:
        meta = get_file_meta(project=project, path=path, token=token, ref=ref) if include_meta else {}
        # Si meta es lista, te han pedido un directorio, no un fichero
        if include_meta and isinstance(meta, list):
            return _json_error("El path es un directorio, no un fichero", 400, path=path)
        data = get_file_bytes(project=project, path=path, token=token, ref=ref)
    except KeyError as e:
        return _json_error(str(e), 404)
    except Exception as e:
        return _json_error(f"github error: {e}", 502)

    if len(data) > MAX_TEXT_BYTES:
        return _json_error(
            f"Fichero demasiado grande para /github/file ({len(data)} bytes). Usa /github/file_lines, /github/file_chunk o /github/download",
            413,
            path=path,
            size=len(data),
        )

    text, encoding = _decode_text(data)
    if text is not None:
        payload = {
            "ok": True,
            "project": project,
            "ref": ref,
            "path": path,
            "size": len(data),
            "encoding": encoding,
            "content": text,
        }
        if include_line_count:
            payload["total_lines"] = len(_split_lines(text))
        if include_meta:
            payload["meta"] = {
                "sha": meta.get("sha"),
                "name": meta.get("name"),
                "html_url": meta.get("html_url"),
                "download_url": meta.get("download_url"),  # temporal
                "type": meta.get("type"),
            }
        return jsonify(payload)

    if binary_mode == "base64":
        payload = {
            "ok": True,
            "project": project,
            "ref": ref,
            "path": path,
            "size": len(data),
            "encoding": "base64",
            "content": base64.b64encode(data).decode("ascii"),
        }
        if include_meta:
            payload["meta"] = {
                "sha": meta.get("sha") if isinstance(meta, dict) else None,
                "name": meta.get("name") if isinstance(meta, dict) else None,
                "html_url": meta.get("html_url") if isinstance(meta, dict) else None,
                "download_url": meta.get("download_url") if isinstance(meta, dict) else None,
                "type": meta.get("type") if isinstance(meta, dict) else None,
            }
        return jsonify(payload)

    return _json_error(
        "Fichero binario o no UTF-8. Usa binary=base64 o /github/download",
        415,
        path=path,
        size=len(data),
    )


@bp.get("/file_lines")
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def github_file_lines():
    """
    Devuelve un rango de líneas (1-based, inclusive) de un fichero texto UTF-8.
    Ej:
      /github/file_lines?project=xx&path=src/main.py&start=1&end=200&numbered=1
    """
    token = _get_bridge_token()
    if not token:
        return _json_error("Falta GITHUB_TOKEN", 500)

    try:
        project = _safe_project_alias(request.args.get("project", ""))
        path = _safe_path(request.args.get("path", ""))
        start = _int_arg("start", 1, min_value=1)
        end = _int_arg("end", start + 199, min_value=1)
    except ValueError as e:
        return _json_error(str(e), 400)

    if end < start:
        return _json_error("end debe ser >= start", 400)

    span = end - start + 1
    if span > MAX_LINES_SPAN:
        return _json_error(f"Demasiadas líneas pedidas ({span}). Máximo {MAX_LINES_SPAN}", 400)

    ref = (request.args.get("ref") or "").strip() or None
    numbered = _bool_arg("numbered", False)

    try:
        data = get_file_bytes(project=project, path=path, token=token, ref=ref)
    except KeyError as e:
        return _json_error(str(e), 404)
    except Exception as e:
        return _json_error(f"github error: {e}", 502)

    if len(data) > MAX_FILE_BYTES_FOR_LINES:
        return _json_error(
            f"Fichero demasiado grande para /github/file_lines ({len(data)} bytes). Usa /github/download",
            413,
            path=path,
            size=len(data),
        )

    text, encoding = _decode_text(data)
    if text is None:
        return _json_error("Fichero binario o no UTF-8. Usa /github/download", 415, path=path, size=len(data))

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
            requested={"start": start, "end": end},
            returned={"start": None, "end": None, "count": 0},
            has_more_before=False,
            has_more_after=False,
            content="",
        )

    if start > total_lines:
        return jsonify(
            ok=True,
            project=project,
            ref=ref,
            path=path,
            encoding=encoding,
            size_bytes=len(data),
            total_lines=total_lines,
            requested={"start": start, "end": end},
            returned={"start": None, "end": None, "count": 0},
            has_more_before=True,
            has_more_after=False,
            content="",
        )

    start_idx = start - 1
    end_idx_excl = min(total_lines, end)  # end es inclusive (1-based)
    selected = lines[start_idx:end_idx_excl]

    actual_start = start_idx + 1 if selected else None
    actual_end = start_idx + len(selected) if selected else None

    if numbered:
        content = "\n".join(f"{i}: {line}" for i, line in enumerate(selected, start=start_idx + 1))
    else:
        content = "\n".join(selected)

    return jsonify(
        ok=True,
        project=project,
        ref=ref,
        path=path,
        encoding=encoding,
        size_bytes=len(data),
        total_lines=total_lines,
        requested={"start": start, "end": end},
        returned={"start": actual_start, "end": actual_end, "count": len(selected)},
        has_more_before=(actual_start is not None and actual_start > 1),
        has_more_after=(actual_end is not None and actual_end < total_lines),
        content=content,
    )


@bp.get("/file_chunk")
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def github_file_chunk():
    """
    Lee por chunks de líneas.
    chunk=0 y chunk_lines=200 -> líneas 1..200
    chunk=1 -> 201..400
    """
    token = _get_bridge_token()
    if not token:
        return _json_error("Falta GITHUB_TOKEN", 500)

    try:
        project = _safe_project_alias(request.args.get("project", ""))
        path = _safe_path(request.args.get("path", ""))
        chunk = _int_arg("chunk", 0, min_value=0)
        chunk_lines = _int_arg("chunk_lines", DEFAULT_CHUNK_LINES, min_value=1, max_value=MAX_CHUNK_LINES)
    except ValueError as e:
        return _json_error(str(e), 400)

    # Convertir chunk a rango 1-based inclusive
    start = chunk * chunk_lines + 1
    end = start + chunk_lines - 1

    # Reutilizamos la lógica central de file_lines a nivel local (sin duplicar endpoint call)
    ref = (request.args.get("ref") or "").strip() or None
    numbered = _bool_arg("numbered", False)

    try:
        data = get_file_bytes(project=project, path=path, token=token, ref=ref)
    except KeyError as e:
        return _json_error(str(e), 404)
    except Exception as e:
        return _json_error(f"github error: {e}", 502)

    if len(data) > MAX_FILE_BYTES_FOR_LINES:
        return _json_error(
            f"Fichero demasiado grande para /github/file_chunk ({len(data)} bytes). Usa /github/download",
            413,
            path=path,
            size=len(data),
        )

    text, encoding = _decode_text(data)
    if text is None:
        return _json_error("Fichero binario o no UTF-8. Usa /github/download", 415, path=path, size=len(data))

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
            chunk=chunk,
            chunk_lines=chunk_lines,
            requested={"start": start, "end": end},
            returned={"start": None, "end": None, "count": 0},
            has_more_before=False,
            has_more_after=False,
            content="",
        )

    if start > total_lines:
        return jsonify(
            ok=True,
            project=project,
            ref=ref,
            path=path,
            encoding=encoding,
            size_bytes=len(data),
            total_lines=total_lines,
            chunk=chunk,
            chunk_lines=chunk_lines,
            requested={"start": start, "end": end},
            returned={"start": None, "end": None, "count": 0},
            has_more_before=True,
            has_more_after=False,
            content="",
        )

    start_idx = start - 1
    end_idx_excl = min(total_lines, end)
    selected = lines[start_idx:end_idx_excl]

    actual_start = start_idx + 1 if selected else None
    actual_end = start_idx + len(selected) if selected else None

    if numbered:
        content = "\n".join(f"{i}: {line}" for i, line in enumerate(selected, start=start_idx + 1))
    else:
        content = "\n".join(selected)

    return jsonify(
        ok=True,
        project=project,
        ref=ref,
        path=path,
        encoding=encoding,
        size_bytes=len(data),
        total_lines=total_lines,
        chunk=chunk,
        chunk_lines=chunk_lines,
        requested={"start": start, "end": end},
        returned={"start": actual_start, "end": actual_end, "count": len(selected)},
        has_more_before=(actual_start is not None and actual_start > 1),
        has_more_after=(actual_end is not None and actual_end < total_lines),
        next_chunk=(chunk + 1) if (actual_end is not None and actual_end < total_lines) else None,
        prev_chunk=(chunk - 1) if chunk > 0 else None,
        content=content,
    )


@bp.get("/readmany")
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def github_readmany():
    """
    Lee varios ficheros de golpe (ideal para Claude cuando ya conoce los paths).
    Parámetros:
      - project (required)
      - path=... repetido, o paths=a,b,c
      - ref (optional)
      - binary=error|skip|base64   (default=skip)
      - meta=1|0
      - numbered=1|0  (si texto, añade líneas numeradas)
      - max_files (<=20)
    """
    token = _get_bridge_token()
    if not token:
        return _json_error("Falta GITHUB_TOKEN", 500)

    try:
        project = _safe_project_alias(request.args.get("project", ""))
    except ValueError as e:
        return _json_error(str(e), 400)

    ref = (request.args.get("ref") or "").strip() or None
    binary_mode = (request.args.get("binary") or "skip").strip().lower()  # error | skip | base64
    include_meta = _bool_arg("meta", False)
    numbered = _bool_arg("numbered", False)

    try:
        max_files = _int_arg("max_files", 10, min_value=1, max_value=MAX_READMANY_FILES)
    except ValueError as e:
        return _json_error(str(e), 400)

    raw_paths = _parse_paths_multi()
    if not raw_paths:
        return _json_error("Falta path (repetido) o paths=a,b,c", 400)

    paths: List[str] = []
    try:
        for p in raw_paths[:max_files]:
            paths.append(_safe_path(p))
    except ValueError as e:
        return _json_error(str(e), 400)

    results = []
    total_bytes = 0

    for path in paths:
        item: Dict[str, Any] = {"path": path}
        try:
            meta = get_file_meta(project=project, path=path, token=token, ref=ref) if include_meta else {}
            if include_meta and isinstance(meta, list):
                item.update(ok=False, error="Es un directorio, no un fichero")
                results.append(item)
                continue

            data = get_file_bytes(project=project, path=path, token=token, ref=ref)
            total_bytes += len(data)
            if total_bytes > MAX_READMANY_TOTAL_BYTES:
                item.update(
                    ok=False,
                    error=f"Límite total de /readmany excedido ({MAX_READMANY_TOTAL_BYTES} bytes)",
                    size=len(data),
                )
                results.append(item)
                break

            text, encoding = _decode_text(data)
            if text is not None:
                if numbered:
                    lines = _split_lines(text)
                    text = "\n".join(f"{i}: {line}" for i, line in enumerate(lines, start=1))
                item.update(ok=True, size=len(data), encoding=encoding, content=text)
            else:
                if binary_mode == "error":
                    item.update(ok=False, size=len(data), error="Binario/no-UTF8")
                elif binary_mode == "skip":
                    item.update(ok=False, size=len(data), skipped=True, error="Binario/no-UTF8")
                elif binary_mode == "base64":
                    item.update(
                        ok=True,
                        size=len(data),
                        encoding="base64",
                        content=base64.b64encode(data).decode("ascii"),
                    )
                else:
                    item.update(ok=False, size=len(data), error=f"binary inválido: {binary_mode}")

            if include_meta and isinstance(meta, dict):
                item["meta"] = {
                    "sha": meta.get("sha"),
                    "name": meta.get("name"),
                    "type": meta.get("type"),
                    "html_url": meta.get("html_url"),
                    "download_url": meta.get("download_url"),
                }

        except KeyError as e:
            item.update(ok=False, error=str(e))
        except Exception as e:
            item.update(ok=False, error=f"github error: {e}")

        results.append(item)

    return jsonify(
        ok=True,
        project=project,
        ref=ref,
        requested_count=len(raw_paths),
        processed_count=len(results),
        total_bytes_returned_raw=total_bytes,
        results=results,
    )


@bp.get("/find_in_file")
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def github_find_in_file():
    """
    Busca texto dentro de un fichero y devuelve hits con contexto de líneas.
    Parámetros:
      - project, path
      - q (texto a buscar) [required]
      - ref (optional)
      - ignore_case=1 (default=1)
      - context=3 (líneas antes/después)
      - max_hits=20
      - numbered=1 (default=1)
    """
    token = _get_bridge_token()
    if not token:
        return _json_error("Falta GITHUB_TOKEN", 500)

    try:
        project = _safe_project_alias(request.args.get("project", ""))
        path = _safe_path(request.args.get("path", ""))
    except ValueError as e:
        return _json_error(str(e), 400)

    q = (request.args.get("q") or "").strip()
    if not q:
        return _json_error("Falta q (texto a buscar)", 400)

    ref = (request.args.get("ref") or "").strip() or None
    ignore_case = _bool_arg("ignore_case", True)
    numbered = _bool_arg("numbered", True)

    try:
        context_n = _int_arg("context", 3, min_value=0, max_value=50)
        max_hits = _int_arg("max_hits", 20, min_value=1, max_value=MAX_FIND_HITS)
    except ValueError as e:
        return _json_error(str(e), 400)

    try:
        data = get_file_bytes(project=project, path=path, token=token, ref=ref)
    except KeyError as e:
        return _json_error(str(e), 404)
    except Exception as e:
        return _json_error(f"github error: {e}", 502)

    if len(data) > MAX_FILE_BYTES_FOR_LINES:
        return _json_error(
            f"Fichero demasiado grande para /github/find_in_file ({len(data)} bytes). Usa /github/download",
            413,
            path=path,
            size=len(data),
        )

    text, encoding = _decode_text(data)
    if text is None:
        return _json_error("Fichero binario o no UTF-8. Usa /github/download", 415, path=path, size=len(data))

    lines = _split_lines(text)
    total_lines = len(lines)

    needle = q.lower() if ignore_case else q
    hits = []

    for idx, line in enumerate(lines, start=1):
        hay = line.lower() if ignore_case else line
        if needle in hay:
            start = max(1, idx - context_n)
            end = min(total_lines, idx + context_n)
            block = lines[start - 1:end]
            if numbered:
                content = "\n".join(f"{i}: {ln}" for i, ln in enumerate(block, start=start))
            else:
                content = "\n".join(block)

            hits.append({
                "line": idx,
                "match_line": line,
                "range": {"start": start, "end": end},
                "content": content,
            })

            if len(hits) >= max_hits:
                break

    return jsonify(
        ok=True,
        project=project,
        ref=ref,
        path=path,
        encoding=encoding,
        size_bytes=len(data),
        total_lines=total_lines,
        query=q,
        ignore_case=ignore_case,
        context=context_n,
        max_hits=max_hits,
        hits_count=len(hits),
        hits=hits,
    )


@bp.get("/download")
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def github_download():
    """
    Proxy raw/binario para navegador/scripts.
    Devuelve attachment con el nombre del fichero.
    """
    token = _get_bridge_token()
    if not token:
        return _json_error("Falta GITHUB_TOKEN", 500)

    try:
        project = _safe_project_alias(request.args.get("project", ""))
        path = _safe_path(request.args.get("path", ""))
    except ValueError as e:
        return _json_error(str(e), 400)

    ref = (request.args.get("ref") or "").strip() or None

    try:
        data = get_file_bytes(project=project, path=path, token=token, ref=ref)
    except KeyError as e:
        return _json_error(str(e), 404)
    except Exception as e:
        return _json_error(f"github error: {e}", 502)

    filename = path.split("/")[-1] or "download.bin"
    return Response(
        data,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
        mimetype="application/octet-stream",
    )
