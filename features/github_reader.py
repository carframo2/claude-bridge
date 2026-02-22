from flask import Blueprint, request, jsonify, current_app, Response
import base64
from core.auth import require_token  # reutiliza tu auth del bridge
from services.github_reader import list_paths_recursive, get_file_bytes, get_file_meta

bp = Blueprint("github_reader", __name__, url_prefix="/github")

MAX_TEXT_BYTES = 2 * 1024 * 1024  # 2MB para respuestas JSON a Claude

def _safe_path(p: str) -> str:
    p = (p or "").strip().lstrip("/")
    # higiene básica (evita traversal raros)
    if ".." in p.split("/"):
        raise ValueError("path inválido")
    if not p:
        raise ValueError("path vacío")
    return p

def _decode_text(data: bytes):
    # prioridad UTF-8 (código fuente, md, json, yaml...)
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return None, None

@bp.get("/paths")
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def github_paths():
    """
    Lista recursiva de paths para un proyecto alias.
    Ej:
      /github/paths?project=proyecto_xx
      /github/paths?project=proyecto_xx&prefix=src
      /github/paths?project=proyecto_xx&kind=files
    """
    s = current_app.config["SETTINGS"]
    token = s.GITHUB_TOKEN
    if not token:
        return jsonify(error="Falta GITHUB_TOKEN"), 500

    project = (request.args.get("project") or "").strip()
    ref = (request.args.get("ref") or "").strip() or None
    prefix = (request.args.get("prefix") or "").strip()
    kind = (request.args.get("kind") or "files").strip()  # files | all
    limit = min(int(request.args.get("limit", "5000")), 20000)

    if not project:
        return jsonify(error="Falta project"), 400

    try:
        entries, truncated = list_paths_recursive(project=project, token=token, ref=ref, prefix=prefix)
    except KeyError as e:
        return jsonify(error=str(e)), 404
    except Exception as e:
        return jsonify(error=f"github error: {e}"), 502

    if kind == "files":
        entries = [e for e in entries if e.get("type") == "blob"]

    # respuesta amigable para Claude (solo lo útil)
    out = []
    for e in entries[:limit]:
        out.append({
            "path": e.get("path"),
            "type": e.get("type"),     # blob/tree/commit
            "size": e.get("size"),     # solo blobs
            "sha": e.get("sha"),
        })

    return jsonify(
        ok=True,
        project=project,
        ref=ref,
        count=len(out),
        truncated=truncated,
        limit_applied=limit,
        entries=out
    )

@bp.get("/file")
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def github_file():
    """
    Devuelve contenido de fichero para Claude.
    Por defecto intenta texto UTF-8 y si no puede, devuelve base64 opcionalmente.
    Ej:
      /github/file?project=proyecto_xx&path=src/main.py
      /github/file?project=proyecto_xx&path=data.bin&binary=base64
    """
    s = current_app.config["SETTINGS"]
    token = s.GITHUB_TOKEN
    if not token:
        return jsonify(error="Falta GITHUB_TOKEN"), 500

    project = (request.args.get("project") or "").strip()
    ref = (request.args.get("ref") or "").strip() or None
    binary_mode = (request.args.get("binary") or "error").strip()  # error | base64
    include_meta = (request.args.get("meta") or "1") in ("1", "true", "True", "yes")

    try:
        path = _safe_path(request.args.get("path", ""))
    except ValueError as e:
        return jsonify(error=str(e)), 400

    if not project:
        return jsonify(error="Falta project"), 400

    try:
        meta = get_file_meta(project=project, path=path, token=token, ref=ref) if include_meta else {}
        data = get_file_bytes(project=project, path=path, token=token, ref=ref)
    except KeyError as e:
        return jsonify(error=str(e)), 404
    except Exception as e:
        return jsonify(error=f"github error: {e}"), 502

    if len(data) > MAX_TEXT_BYTES:
        return jsonify(
            ok=False,
            error=f"Fichero demasiado grande para /github/file ({len(data)} bytes). Usa /github/download",
            size=len(data),
            path=path
        ), 413

    text, encoding = _decode_text(data)
    if text is not None:
        return jsonify(
            ok=True,
            project=project,
            ref=ref,
            path=path,
            size=len(data),
            encoding=encoding,
            content=text,
            meta={
                "sha": meta.get("sha"),
                "name": meta.get("name"),
                "download_url": meta.get("download_url"),
                "html_url": meta.get("html_url"),
            } if include_meta else None
        )

    if binary_mode == "base64":
        return jsonify(
            ok=True,
            project=project,
            ref=ref,
            path=path,
            size=len(data),
            encoding="base64",
            content=base64.b64encode(data).decode("ascii"),
            meta={
                "sha": meta.get("sha"),
                "name": meta.get("name"),
                "download_url": meta.get("download_url"),
                "html_url": meta.get("html_url"),
            } if include_meta else None
        )

    return jsonify(
        ok=False,
        error="Fichero binario/no-UTF8. Usa binary=base64 o /github/download",
        path=path,
        size=len(data)
    ), 415

@bp.get("/download")
@require_token(header_name="X-BRIDGE-TOKEN", env_attr="BRIDGE_TOKEN")
def github_download():
    """
    Proxy raw para navegador/scripts (binarios, zips, etc).
    """
    s = current_app.config["SETTINGS"]
    token = s.GITHUB_TOKEN
    if not token:
        return jsonify(error="Falta GITHUB_TOKEN"), 500

    project = (request.args.get("project") or "").strip()
    ref = (request.args.get("ref") or "").strip() or None

    try:
        path = _safe_path(request.args.get("path", ""))
    except ValueError as e:
        return jsonify(error=str(e)), 400

    if not project:
        return jsonify(error="Falta project"), 400

    try:
        data = get_file_bytes(project=project, path=path, token=token, ref=ref)
    except Exception as e:
        return jsonify(error=f"github error: {e}"), 502

    filename = path.split("/")[-1] or "download.bin"
    return Response(
        data,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
        mimetype="application/octet-stream",
    )
