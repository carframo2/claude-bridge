from flask import Flask

def install_cors(app: Flask) -> None:
    @app.after_request
    def add_cors_headers(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-BRIDGE-TOKEN, X-UPLOAD-SECRET"
        resp.headers["Access-Control-Max-Age"] = "86400"
        return resp
