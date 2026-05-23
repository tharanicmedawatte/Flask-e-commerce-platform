# =============================================================================
# app/products/__init__.py
# Developer 2 — Products Blueprint
# =============================================================================

from flask import Blueprint

products_bp = Blueprint(
    "products",
    __name__,
    url_prefix="/api/v1",
)

from . import routes  # noqa: E402, F401


def register_products(app):
    app.register_blueprint(products_bp)
    app.logger.info("Products blueprint registered — prefix: /api/v1")