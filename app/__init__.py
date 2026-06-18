# =============================================================================
# app/__init__.py — Application Factory
# =============================================================================

import os
from flask import Flask
from flask_cors import CORS
from flask_talisman import Talisman
from app.extensions import db, migrate, limiter, login_manager, mail, csrf


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)

    # ── Config ────────────────────────────────────────────────────────────────
    from app.config import config_map
    cfg = config_name or os.getenv("FLASK_ENV", "development")
    app.config.from_object(config_map[cfg])

    if cfg == "production":
        config_map["production"].validate()

    # ── Extensions ────────────────────────────────────────────────────────────
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)

    # CORS
    frontend_url = app.config.get("FRONTEND_URL", "http://localhost:3000")
    origins = [o.strip() for o in frontend_url.split(",")]
    CORS(app, resources={
        r"/api/*":    {"origins": origins},
        r"/orders/*": {"origins": origins},
        r"/auth/*":   {"origins": origins},
    })

    # Security headers
    Talisman(
        app,
        force_https=app.config.get("TALISMAN_FORCE_HTTPS", False),
        content_security_policy=app.config.get("CONTENT_SECURITY_POLICY", {}),
        content_security_policy_nonce_in=["script-src"],
    )

    # ── Import models ─────────────────────────────────────────────────────────
    with app.app_context():
        from app import models  # noqa: F401

    # ── Blueprints ────────────────────────────────────────────────────────────
    from app.auth import auth_bp
    from app.products import products_bp, register_products
    from app.orders import orders_bp

    # Register blueprints first
    app.register_blueprint(auth_bp)
    register_products(app)
    app.register_blueprint(orders_bp)

    # Exempt ALL blueprints from CSRF after registration
    # All routes are REST API endpoints authenticated via Auth0 JWT tokens
    csrf.exempt(auth_bp)
    csrf.exempt(products_bp)
    csrf.exempt(orders_bp)

    return app