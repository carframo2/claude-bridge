from flask import Flask
from core.settings import Settings
from core.cors import install_cors
from core.rate_limit import RateLimiter
from core.feature_loader import register_all_features

def create_app() -> Flask:
    app = Flask(__name__)

    # settings + rate limiter accesibles desde current_app.config
    app.config["SETTINGS"] = Settings()
    app.config["RATE_LIMITER"] = RateLimiter(app.config["SETTINGS"].RATE_LIMIT_PER_MIN)

    install_cors(app)
    register_all_features(app)

    return app
