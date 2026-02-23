from functools import wraps
from flask import request, jsonify, current_app

def require_token(header_name: str = "X-BRIDGE-TOKEN", env_attr: str = "BRIDGE_TOKEN"):
    """
    Si el token está vacío en settings => no exige auth (como tu app actual).
    Lee token de header, query ?token, json {token}, form token.
    """
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if request.method == "OPTIONS":
                return ("", 204)
            s = current_app.config["SETTINGS"]
            expected = getattr(s, env_attr, "") or ""
            expected = expected.strip()
            if not expected:
                return fn(*args, **kwargs)

            provided = (
                request.headers.get(header_name)
                or request.args.get("token")
                or (request.is_json and (request.get_json(silent=True) or {}).get("token"))
                or request.form.get("token")
            )
            if not provided or provided.strip() != expected:
                return jsonify({"content": "(unauthorized) token inválido"}), 401
            return fn(*args, **kwargs)
        return wrapper
    return deco

def require_upload_secret(fn):
    """
    Para /github/upload: usa UPLOAD_SECRET si existe; si no, cae a BRIDGE_TOKEN.
    Header: X-UPLOAD-SECRET (o X-BRIDGE-TOKEN por compatibilidad).
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return ("", 204)        
        s = current_app.config["SETTINGS"]
        expected = (s.UPLOAD_SECRET or s.BRIDGE_TOKEN or "").strip()
        if not expected:
            return fn(*args, **kwargs)

        provided = (
            request.headers.get("X-UPLOAD-SECRET")
            or request.headers.get("X-BRIDGE-TOKEN")
            or request.args.get("token")
        )
        if not provided or provided.strip() != expected:
            return {"error": "Unauthorized"}, 401
        return fn(*args, **kwargs)
    return wrapper
