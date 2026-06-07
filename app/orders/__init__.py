# app/orders/__init__.py
# Developer 3 — Orders blueprint registration
#
# This is the only file Dev 1 imports from this module.
# Dev 1 registers this blueprint in app/__init__.py like so:
#
#   from app.orders import orders_bp
#   app.register_blueprint(orders_bp)

from .routes import orders_bp

__all__ = ["orders_bp"]
