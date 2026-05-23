# =============================================================================
# app/__init__.py — Application Factory
# =============================================================================

import os
from flask import Flask
from flask_cors import CORS
from app.extensions import db, migrate, limiter, login_manager


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)

    # ── Config ────────────────────────────────────────────────────────────────
    from app.config import config_map
    cfg = config_name or os.getenv("FLASK_ENV", "development")
    app.config.from_object(config_map[cfg])

    # ── Extensions ────────────────────────────────────────────────────────────
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    login_manager.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": os.getenv("CORS_ORIGINS", "*")}})

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
    # from app.orders import register_orders
    # register_orders(app)

    return app