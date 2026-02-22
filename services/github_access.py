from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple

from werkzeug.security import check_password_hash


def parse_projects_full() -> Dict[str, Dict[str, Any]]:
    """
    Lee GITHUB_PROJECTS (JSON) con soporte para token por proyecto.

    Ejemplo:
    {
      "proyecto_xx": {
        "owner": "carframo2",
        "repo": "repo-xx",
        "ref": "main",
        "token_env": "GITHUB_TOKEN_PROYECTO_XX"
      }
    }
    """
    raw = os.environ.get("GITHUB_PROJECTS", "").strip()
    if not raw:
        return {}

    data = json.loads(raw)
    out: Dict[str, Dict[str, Any]] = {}

    for alias, cfg in data.items():
        if not isinstance(cfg, dict):
            raise ValueError(f"GITHUB_PROJECTS[{alias}] debe ser objeto")
        owner = (cfg.get("owner") or "").strip()
        repo = (cfg.get("repo") or "").strip()
        ref = (cfg.get("ref") or "main").strip()
        token_env = (cfg.get("token_env") or "").strip()  # opcional

        if not owner or not repo:
            raise ValueError(f"GITHUB_PROJECTS[{alias}] requiere owner y repo")

        out[alias] = {
            "owner": owner,
            "repo": repo,
            "ref": ref,
            "token_env": token_env,
        }

    return out


def parse_users_acl() -> Dict[str, Dict[str, Any]]:
    """
    Lee GITHUB_USERS (JSON) con usuarios + permisos.

    Formato recomendado:
    {
      "carlos": {
        "password_hash": "scrypt:....",
        "projects": ["proyecto_xx", "proyecto_yy"]
      },
      "veronica": {
        "password_hash": "scrypt:....",
        "projects": ["proyecto_xx"]
      },
      "alvaro": {
        "password_hash": "scrypt:....",
        "projects": ["proyecto_yy"]
      }
    }

    También soporta projects="*" (todos).
    Opcionalmente soporta "password" en claro (NO recomendado).
    """
    raw = os.environ.get("GITHUB_USERS", "").strip()
    if not raw:
        return {}

    data = json.loads(raw)
    out: Dict[str, Dict[str, Any]] = {}

    for username, cfg in data.items():
        if not isinstance(cfg, dict):
            raise ValueError(f"GITHUB_USERS[{username}] debe ser objeto")

        username_clean = (username or "").strip()
        if not username_clean:
            raise ValueError("Usuario vacío en GITHUB_USERS")

        password_hash = (cfg.get("password_hash") or "").strip()
        password_plain = (cfg.get("password") or "").strip()  # fallback (inseguro)
        projects = cfg.get("projects", [])

        if not password_hash and not password_plain:
            raise ValueError(f"GITHUB_USERS[{username_clean}] requiere password_hash (o password)")

        if projects != "*" and not isinstance(projects, list):
            raise ValueError(f"GITHUB_USERS[{username_clean}].projects debe ser lista o '*'")

        projects_norm = "*" if projects == "*" else [str(p).strip() for p in projects if str(p).strip()]

        out[username_clean] = {
            "password_hash": password_hash,
            "password": password_plain,  # no recomendado
            "projects": projects_norm,
        }

    return out


def verify_user_password(username: str, password: str) -> Tuple[bool, str]:
    """
    Devuelve (ok, motivo).
    """
    users = parse_users_acl()
    cfg = users.get(username)
    if not cfg:
        return False, "Usuario no existe"

    pwd = password or ""
    pwd_hash = cfg.get("password_hash") or ""
    pwd_plain = cfg.get("password") or ""

    if pwd_hash:
        try:
            if check_password_hash(pwd_hash, pwd):
                return True, "ok"
            return False, "Password incorrecta"
        except Exception:
            return False, "Hash inválido"

    # fallback inseguro (solo si decides usar password en claro)
    if pwd_plain and pwd == pwd_plain:
        return True, "ok"

    return False, "Password incorrecta"


def user_allowed_for_project(username: str, project_alias: str) -> bool:
    users = parse_users_acl()
    cfg = users.get(username)
    if not cfg:
        return False

    projects = cfg.get("projects", [])
    if projects == "*":
        return True
    return project_alias in projects


def resolve_project_token(project_alias: str) -> str:
    """
    Resuelve el token GitHub del proyecto:
    - si GITHUB_PROJECTS[alias].token_env está definido -> lee ese env var
    - si no, fallback a GITHUB_TOKEN (legacy)
    """
    projects = parse_projects_full()
    cfg = projects.get(project_alias)
    if not cfg:
        raise KeyError(f"Proyecto no configurado: {project_alias}")

    token_env = (cfg.get("token_env") or "").strip()
    if token_env:
        token = (os.environ.get(token_env) or "").strip()
        if not token:
            raise ValueError(f"Falta env var del token del proyecto: {token_env}")
        return token

    # fallback legacy (un solo token global)
    token = (os.environ.get("GITHUB_TOKEN") or "").strip()
    if not token:
        raise ValueError(f"Proyecto {project_alias} sin token_env y falta GITHUB_TOKEN")
    return token


def list_projects_for_user(username: str) -> List[str]:
    users = parse_users_acl()
    projects = parse_projects_full()

    cfg = users.get(username)
    if not cfg:
        return []

    allowed = cfg.get("projects", [])
    if allowed == "*":
        return sorted(projects.keys())

    return sorted([p for p in allowed if p in projects])


def list_all_projects() -> List[str]:
    return sorted(parse_projects_full().keys())
