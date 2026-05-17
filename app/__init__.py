# app/__init__.py  — Application factory

import os
from flask import Flask, jsonify
from flask_talisman import Talisman

from app.extensions import db, login_manager, mail, limiter, csrf, migrate
from app.config import config_map


def create_app(env: str | None = None) -> Flask:
    """
    Application factory. Import and call this in run.py.

    Usage:
        app = create_app("development")
        app = create_app("production")
    """
    if env is None:
        env = os.environ.get("FLASK_ENV", "default")

    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_map[env])

    # ------------------------------------------------------------------
    # Security headers  (STRIDE — Information Disclosure, Tampering)
    # ------------------------------------------------------------------
    csp = {
        "default-src": "'self'",
        "script-src":  "'self'",
        "style-src":   "'self' 'unsafe-inline'",
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
    # Extensions
    # ------------------------------------------------------------------
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)

    # ------------------------------------------------------------------
    # Blueprints — one folder per developer, zero cross-blueprint imports
    # ------------------------------------------------------------------
    from app.auth.routes     import auth_bp      # Developer 1
    from app.products.routes import products_bp  # Developer 2  (stub until merged)
    from app.orders.routes   import orders_bp    # Developer 3  (stub until merged)

    app.register_blueprint(auth_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(orders_bp)

    # ------------------------------------------------------------------
    # Global error handlers
    # ------------------------------------------------------------------
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource not found."}), 404

    @app.errorhandler(429)
    def rate_limited(e):
        return jsonify({"error": "Too many requests. Please slow down."}), 429

    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        return jsonify({"error": "An internal error occurred."}), 500

    return app
