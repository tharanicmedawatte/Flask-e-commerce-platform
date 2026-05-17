# app/config.py
# All configuration loaded from environment variables.
# Never hardcode secrets here — use a .env file locally, env vars in production.
# Copy .env.example to .env and fill in values before running.

import os
from datetime import timedelta


class Config:
    """Base configuration shared across all environments."""

    # ------------------------------------------------------------------
    # Core Flask
    # ------------------------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY") or _require("SECRET_KEY")
    DEBUG = False
    TESTING = False

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DATABASE_URL") or "sqlite:///ecommerce_dev.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,          # detect stale connections
        "pool_recycle": 300,            # recycle connections every 5 minutes
    }

    # ------------------------------------------------------------------
    # Mail (Flask-Mail)
    # ------------------------------------------------------------------
    MAIL_SERVER   = os.environ.get("MAIL_SERVER",   "smtp.gmail.com")
    MAIL_PORT     = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS  = os.environ.get("MAIL_USE_TLS",  "true").lower() == "true"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@shopname.com")

    # ------------------------------------------------------------------
    # Session
    # ------------------------------------------------------------------
    SESSION_COOKIE_HTTPONLY = True      # JS cannot read session cookie
    SESSION_COOKIE_SAMESITE = "Lax"    # CSRF mitigation
    SESSION_COOKIE_SECURE   = True     # HTTPS only (overridden in DevelopmentConfig)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------
    RATELIMIT_STORAGE_URI = os.environ.get("REDIS_URL", "memory://")
    RATELIMIT_DEFAULT = "200 per day;50 per hour"

    # ------------------------------------------------------------------
    # Payment webhook secret (used by Dev 3)
    # ------------------------------------------------------------------
    PAYMENT_WEBHOOK_SECRET = os.environ.get("PAYMENT_WEBHOOK_SECRET", "")


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False       # allow HTTP in local dev
    SQLALCHEMY_DATABASE_URI = "sqlite:///ecommerce_dev.db"
    MAIL_SUPPRESS_SEND = True           # print emails to console, don't send
    WTF_CSRF_ENABLED = False            # easier API testing locally


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    MAIL_SUPPRESS_SEND = True
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")  # must be set
    SESSION_COOKIE_SECURE = True
    RATELIMIT_STORAGE_URI = os.environ.get("REDIS_URL")       # Redis in production


# Map string name → class (used by create_app)
config_map = {
    "development": DevelopmentConfig,
    "testing":     TestingConfig,
    "production":  ProductionConfig,
    "default":     DevelopmentConfig,
}


def _require(var: str) -> str:
    """Raise a clear error if a required env var is missing."""
    raise RuntimeError(
        f"Environment variable '{var}' is required but not set. "
        f"Copy .env.example to .env and fill in the value."
    )


# =============================================================================
# app/__init__.py  — App factory
# =============================================================================
# Placed here to keep all seven files in one response.
# In the real repo this lives at app/__init__.py

APP_FACTORY = '''
# app/__init__.py

import os
from flask import Flask
from flask_talisman import Talisman

from app.extensions import db, login_manager, mail, limiter, csrf, migrate
from app.config import config_map


def create_app(env: str | None = None) -> Flask:
    """
    Application factory.
    Call with an environment name or set FLASK_ENV in the environment.

    Usage:
        app = create_app("development")   # local dev
        app = create_app("production")    # production
    """
    if env is None:
        env = os.environ.get("FLASK_ENV", "default")

    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_map[env])

    # ------------------------------------------------------------------
    # Security headers (STRIDE — Information Disclosure, Tampering)
    # Talisman adds: HSTS, X-Frame-Options, X-Content-Type-Options,
    #                Content-Security-Policy, Referrer-Policy.
    # ------------------------------------------------------------------
    csp = {
        "default-src": "'self'",
        "script-src":  "'self'",
        "style-src":   "'self' 'unsafe-inline'",    # loosen if using a CSS CDN
        "img-src":     "'self' data:",
    }
    Talisman(
        app,
        force_https=not app.debug,
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        content_security_policy=csp,
        referrer_policy="strict-origin-when-cross-origin",
    )

    # ------------------------------------------------------------------
    # Initialise extensions
    # ------------------------------------------------------------------
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)

    # ------------------------------------------------------------------
    # Register blueprints (one per developer)
    # ------------------------------------------------------------------
    from app.auth.routes     import auth_bp       # Developer 1
    from app.products.routes import products_bp   # Developer 2
    from app.orders.routes   import orders_bp     # Developer 3

    app.register_blueprint(auth_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(orders_bp)

    # ------------------------------------------------------------------
    # Global error handlers
    # ------------------------------------------------------------------
    @app.errorhandler(404)
    def not_found(e):
        from flask import jsonify
        return jsonify({"error": "Resource not found."}), 404

    @app.errorhandler(429)
    def rate_limited(e):
        from flask import jsonify
        return jsonify({"error": "Too many requests. Please slow down."}), 429

    @app.errorhandler(500)
    def internal_error(e):
        from flask import jsonify
        db.session.rollback()
        return jsonify({"error": "An internal error occurred."}), 500

    return app
'''

# Print the app factory so it can be copied to app/__init__.py
# (In the real project, just move the string above into that file.)
