from flask import Blueprint, request, jsonify, current_app
import requests
from core.auth import require_upload_secret

bp = Blueprint("github_uploads", __name__, url_prefix="/github")

def _get_or_create_release(owner: str, repo: str, token: str, tag: str):
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}", headers=headers, timeout=30)
    if r.ok:
        return r.json()

    r = requests.post(
        f"https://api.github.com/repos/{owner}/{repo}/releases",
        headers={**headers, "Content-Type": "application/json"},
        json={"tag_name": tag, "name": f"Uploads {tag}", "draft": False, "prerelease": True},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()

@bp.post("/upload")
@require_upload_secret
def upload_zip():
    s = current_app.config["SETTINGS"]

    if not (s.GH_OWNER and s.GH_REPO and s.GITHUB_TOKEN):
        return jsonify(error="Faltan GH_OWNER / GH_REPO / GITHUB_TOKEN en env"), 500

    f = request.files.get("file")
    if not f:
        return jsonify(error="Falta file (multipart/form-data)"), 400
    if not f.filename.lower().endswith(".zip"):
        return jsonify(error="Solo .zip"), 400

    # release por año para no acercarte al límite de assets
    year = str(__import__("datetime").datetime.utcnow().year)
    tag = f"uploads-{year}"

    release = _get_or_create_release(s.GH_OWNER, s.GH_REPO, s.GITHUB_TOKEN, tag)

    base_upload_url = release["upload_url"].replace("{?name,label}", "")
    asset_name = f"{__import__('time').time_ns()}-{f.filename}"
    upload_url = f"{base_upload_url}?name={requests.utils.quote(asset_name)}"

    data = f.read()
    up = requests.post(
        upload_url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {s.GITHUB_TOKEN}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/zip",
        },
        data=data,  # binario raw (NO base64)
        timeout=120,
    )

    if not up.ok:
        return jsonify(error="GitHub upload failed", detail=up.text), up.status_code

    asset = up.json()
    return jsonify(
        ok=True,
        release_html=release["html_url"],
        asset_name=asset["name"],
        browser_download_url=asset["browser_download_url"],  # en repo privado, tú podrás descargar logueado
    )
