# app/auth/decorators.py
# Reusable route decorators for all three developers.
# Dev 2 and Dev 3 import from here — they never write their own auth guards.
#
# Usage:
#   from app.auth.decorators import login_required, require_role, guest_or_user
#
# STRIDE — Elevation of Privilege:
#   require_role() enforces server-side role checks on every request.
#   Roles cannot be changed from the client; they come from the DB via JWT.

import functools
from flask import jsonify, request, g
from flask_login import current_user

from app.models import User


# ---------------------------------------------------------------------------
# login_required
# ---------------------------------------------------------------------------

def login_required(f):
    """
    Protect a route: user must be authenticated (valid JWT or active session).
    Returns 401 JSON for API clients, redirect for browser clients.
    Works for both registered users (Flask-Login session) and JWT-authenticated
    API calls.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # 1. Check JWT in Authorization header (API clients)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            payload = User.verify_jwt(token)
            if not payload:
                return jsonify({"error": "Invalid or expired token."}), 401
            user = User.query.get(payload["sub"])
            if not user or not user.is_active:
                return jsonify({"error": "User not found or deactivated."}), 401
            g.current_user = user       # available in the route via flask.g
            return f(*args, **kwargs)

        # 2. Fall back to Flask-Login session (browser clients)
        if current_user.is_authenticated and current_user.is_active:
            g.current_user = current_user
            return f(*args, **kwargs)

        # 3. Not authenticated
        if _wants_json():
            return jsonify({"error": "Authentication required."}), 401
        from flask import redirect, url_for
        return redirect(url_for("auth.login"))

    return decorated


# ---------------------------------------------------------------------------
# require_role
# ---------------------------------------------------------------------------

def require_role(*roles: str):
    """
    Require the authenticated user to have one of the specified roles.
    Must be used AFTER @login_required (or it won't have g.current_user).

    Example:
        @products_bp.route('/admin/products', methods=['DELETE'])
        @login_required
        @require_role('admin')
        def delete_product(product_id):
            ...
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            user = getattr(g, "current_user", current_user)
            if not user or not user.is_authenticated:
                return jsonify({"error": "Authentication required."}), 401
            if user.role not in roles:
                return jsonify({"error": "You do not have permission to perform this action."}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ---------------------------------------------------------------------------
# guest_or_user
# ---------------------------------------------------------------------------

def guest_or_user(f):
    """
    Allows both unregistered guests and logged-in users.
    Sets g.current_user to the authenticated user if logged in,
    or sets g.is_guest = True if not.

    Use this for routes like product browsing, search, and the homepage
    where unregistered access is intentional.

    Example:
        @products_bp.route('/products')
        @guest_or_user
        def list_products():
            if g.is_guest:
                # show limited view or prompt to register
                ...
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            payload = User.verify_jwt(token)
            if payload:
                user = User.query.get(payload["sub"])
                if user and user.is_active:
                    g.current_user = user
                    g.is_guest = False
                    return f(*args, **kwargs)

        if current_user.is_authenticated and current_user.is_active:
            g.current_user = current_user
            g.is_guest = False
            return f(*args, **kwargs)

        # Unauthenticated — treat as guest
        g.current_user = None
        g.is_guest = True
        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# verified_required
# ---------------------------------------------------------------------------

def verified_required(f):
    """
    Require the user to have verified their email address.
    Use on top of @login_required for sensitive operations.

    Example:
        @orders_bp.route('/checkout', methods=['POST'])
        @login_required
        @verified_required
        def checkout():
            ...
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        user = getattr(g, "current_user", current_user)
        if not getattr(user, "is_verified", False):
            return jsonify({
                "error": "Please verify your email address before continuing."
            }), 403
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _wants_json() -> bool:
    """True if the client prefers JSON over HTML."""
    best = request.accept_mimetypes.best_match(["application/json", "text/html"])
    return best == "application/json"
