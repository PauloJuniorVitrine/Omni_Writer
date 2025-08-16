"""
Fábrica de criação da aplicação Flask.
Centraliza configuração, extensões e registro de blueprints.
"""
import os
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from app.routes import routes_bp
from app.blog_routes import blog_routes_bp

from shared.config import SENTRY_DSN


def create_app() -> Flask:
    """
    Cria e configura a aplicação Flask, registrando blueprints e extensões.
    """
    app = Flask(__name__, template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates')))
    app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24))

    # Rate limiting global
    limiter = Limiter(get_remote_address, app=app, default_limits=["30 per minute"])
    CORS(app)

    # Registro dos blueprints
    app.register_blueprint(routes_bp)
    app.register_blueprint(blog_routes_bp)

    # Sentry opcional
    if SENTRY_DSN:
        import sentry_sdk
        sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=1.0)

    return app 