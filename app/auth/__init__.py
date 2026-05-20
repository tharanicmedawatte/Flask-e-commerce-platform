# app/auth/__init__.py
# Exposes only the blueprint object.
# Dev 2 and Dev 3 never need to import anything else from this package.

from .routes import auth_bp

__all__ = ["auth_bp"]
