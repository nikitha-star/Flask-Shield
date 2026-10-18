import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask

from . import db

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("FLASKSHIELD_SECRET", os.urandom(32).hex()),
        DATABASE=os.path.join(BASE_DIR, "flaskshield.db"),
        SAMPLES_DIR=os.path.join(BASE_DIR, "samples"),
        LOG_DIR=os.path.join(BASE_DIR, "logs"),
        MAX_CONTENT_LENGTH=20 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.config["LOG_DIR"], exist_ok=True)
    _setup_logging(app)
    db.init_db(app.config["DATABASE"])
    app.teardown_appcontext(db.close_db)

    from .routes import bp
    app.register_blueprint(bp)

    @app.after_request
    def headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        return resp

    return app


def _setup_logging(app):
    log = logging.getLogger("flaskshield")
    if log.handlers:
        return
    log.setLevel(logging.INFO)
    h = RotatingFileHandler(os.path.join(app.config["LOG_DIR"], "flaskshield.log"),
                            maxBytes=1_000_000, backupCount=3)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    log.addHandler(h)
    log.addHandler(logging.StreamHandler())
