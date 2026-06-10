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

    # Validate required env vars when running in production — fails loudly
    # at startup rather than silently serving broken responses later.
    if cfg == "production":
        config_map["production"].validate()

    # ── Extensions ────────────────────────────────────────────────────────────
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)

    # CORS — only the whitelisted frontend origin may call the API.
    # Wildcard "*" is never used (STRIDE Info Disclosure).
    frontend_url = app.config.get("FRONTEND_URL", "http://localhost:3000")
    origins = [o.strip() for o in frontend_url.split(",")]
    CORS(app, resources={r"/api/*": {"origins": origins}})

    # Security headers — force HTTPS + CSP in production; relaxed in dev.
    Talisman(
        app,
        force_https=app.config.get("TALISMAN_FORCE_HTTPS", False),
        content_security_policy=app.config.get("CONTENT_SECURITY_POLICY", {}),
        content_security_policy_nonce_in=["script-src"],
    )

    # ── Import models so Alembic can detect all tables ────────────────────────
    with app.app_context():
        from app import models  # noqa: F401

    # ── Blueprints ────────────────────────────────────────────────────────────
    # Auth (Dev 1)
    from app.auth import auth_bp
    app.register_blueprint(auth_bp)

    # Products + Cart (Dev 2)
    from app.products import register_products
    register_products(app)

    # Orders / Payments (Dev 3) — uncomment when Dev 3 is ready
    from app.orders import orders_bp
    app.register_blueprint(orders_bp)

    return app