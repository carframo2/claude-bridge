import os
import json
import requests
from typing import Dict, Any, List, Tuple

API = "https://api.github.com"

def _gh_headers(token: str, accept: str = "application/vnd.github+json") -> Dict[str, str]:
    return {
        "Accept": accept,
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

def parse_project_map() -> Dict[str, Dict[str, str]]:
    """
    Env esperado (JSON):
    GITHUB_PROJECTS='{
      "proyecto_xx": {"owner":"carframo2", "repo":"repo-privado-xx", "ref":"main"},
      "manuales": {"owner":"carframo2", "repo":"manuales-priv", "ref":"main"}
    }'
    """
    raw = os.environ.get("GITHUB_PROJECTS", "").strip()
    if not raw:
        return {}
    data = json.loads(raw)
    out = {}
    for k, v in data.items():
        out[k] = {
            "owner": v["owner"],
            "repo": v["repo"],
            "ref": v.get("ref", "main"),
        }
    return out

def _project_cfg(project: str) -> Dict[str, str]:
    projects = parse_project_map()
    if project not in projects:
        raise KeyError(f"Proyecto no configurado: {project}")
    return projects[project]

def list_paths_recursive(project: str, token: str, ref: str | None = None, prefix: str = "") -> Tuple[List[Dict[str, Any]], bool]:
    """
    Devuelve entries del árbol recursivo (principalmente blobs).
    """
    cfg = _project_cfg(project)
    owner, repo = cfg["owner"], cfg["repo"]
    tree_ref = ref or cfg["ref"]

    url = f"{API}/repos/{owner}/{repo}/git/trees/{tree_ref}"
    r = requests.get(
        url,
        headers=_gh_headers(token),
        params={"recursive": "1"},
        timeout=60,
    )
    r.raise_for_status()
    data = r.json()

    tree = data.get("tree", [])
    truncated = bool(data.get("truncated", False))

    if prefix:
        prefix = prefix.strip("/")
        tree = [e for e in tree if e.get("path", "").startswith(prefix + "/") or e.get("path", "") == prefix]

    return tree, truncated

def get_file_bytes(project: str, path: str, token: str, ref: str | None = None) -> bytes:
    cfg = _project_cfg(project)
    owner, repo = cfg["owner"], cfg["repo"]
    ref = ref or cfg["ref"]

    # Contents API raw media type
    url = f"{API}/repos/{owner}/{repo}/contents/{path}"
    r = requests.get(
        url,
        headers=_gh_headers(token, accept="application/vnd.github.raw+json"),
        params={"ref": ref},
        timeout=90,
    )
    r.raise_for_status()
    return r.content

def get_file_meta(project: str, path: str, token: str, ref: str | None = None) -> Dict[str, Any]:
    cfg = _project_cfg(project)
    owner, repo = cfg["owner"], cfg["repo"]
    ref = ref or cfg["ref"]

    url = f"{API}/repos/{owner}/{repo}/contents/{path}"
    r = requests.get(
        url,
        headers=_gh_headers(token, accept="application/vnd.github+json"),
        params={"ref": ref},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()
