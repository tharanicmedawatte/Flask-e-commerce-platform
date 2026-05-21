# =============================================================================
# app/auth/decorators.py
# Route protection decorators used by ALL THREE developers.
#
# What this file does:
#   Provides reusable decorators that protect Flask routes by verifying
#   Auth0 JWT tokens and enforcing role-based access control (RBAC).
#
# How to use (for Developer 2 and Developer 3):
#   from app.auth.decorators import (
#       login_required,
#       require_role,
#       guest_or_user,
#       verified_required,
#   )
#
# Decorator stacking order — ALWAYS follow this order:
#   @products_bp.route("/cart", methods=["POST"])
#   @login_required           ← 1st: confirms identity
#   @verified_required        ← 2nd: confirms email verified
#   @require_role("customer") ← 3rd: confirms role is allowed
#   def add_to_cart():
#       ...
#
# After any decorator runs successfully, the authenticated user is
# available in the route via:
#   from flask import g
#   user = g.current_user   ← User object from MySQL
#
# STRIDE coverage:
#   Spoofing          — every decorator verifies Auth0 JWT before trusting
#                       any user identity claim
#   Elevation         — require_role() enforces server-side RBAC;
#                       role cannot be changed from the client
#   Info Disclosure   — unauthenticated requests get generic 401/403
#                       with no internal detail
#   Repudiation       — ACCESS_DENIED events written to AuditLog
# =============================================================================

import functools
import logging

from flask import g, jsonify, request
from flask_login import current_user

from app.models import AuditLog, User
from app.extensions import db

logger = logging.getLogger(__name__)


# =============================================================================
# Private helpers — shared by all decorators in this file
# =============================================================================

def _extract_token() -> str | None:
    """
    Extract Bearer token from Authorization header.
    Returns token string or None.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer ") and len(auth_header) > 7:
        return auth_header.split(" ", 1)[1].strip()
    return None


def _verify_and_load_user() -> "User | None":
    """
    Verify the Auth0 JWT token and load the matching User from MySQL.

    Checks in order:
      1. JWT Bearer token in Authorization header (API / Next.js clients)
      2. Flask-Login session cookie (browser fallback)

    Returns the User object on success, None on any failure.

    STRIDE Spoofing:
      Token is verified cryptographically — signature, expiry, audience,
      issuer all checked before the User row is loaded from MySQL.
      We never trust the user ID inside the token without verification.
    """
    # ------------------------------------------------------------------
    # Path 1 — JWT Bearer token (primary: Next.js / API clients)
    # ------------------------------------------------------------------
    token = _extract_token()
    if token:
        # Import here to avoid circular imports
        from app.auth.services import Auth0TokenService
        payload = Auth0TokenService.verify(token)
        if payload:
            auth0_id = payload.get("sub")
            if auth0_id:
                user = User.query.filter_by(
                    auth0_id=auth0_id,
                    is_active=True,
                ).first()
                if user:
                    return user
        # Token present but invalid — do NOT fall through to session check.
        # An invalid token should always return 401, never silently
        # fall back to a session, which could mask a security issue.
        return None

    # ------------------------------------------------------------------
    # Path 2 — Flask-Login session cookie (browser fallback)
    # ------------------------------------------------------------------
    if current_user.is_authenticated and current_user.is_active:
        return current_user

    return None


def _wants_json() -> bool:
    """True if the client prefers a JSON response over HTML."""
    best = request.accept_mimetypes.best_match(
        ["application/json", "text/html"]
    )
    return best == "application/json"


def _deny(message: str, status: int, event: str, user_id: str | None = None) -> tuple:
    """
    Return a JSON or redirect deny response and write to AuditLog.

    STRIDE Repudiation: every access denial is recorded.
    STRIDE Info Disclosure: message is generic — no internal detail.
    """
    if user_id:
        AuditLog.record(
            event=event,
            user_id=user_id,
            ip_address=_get_ip(),
            user_agent=_get_ua(),
        )
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    if _wants_json():
        return jsonify({"error": message}), status

    # Browser fallback — redirect to frontend login
    from flask import redirect, current_app
    frontend_url = current_app.config.get("FRONTEND_URL", "http://localhost:3000")
    from werkzeug.utils import redirect as wz_redirect
    return wz_redirect(f"{frontend_url}/login"), 302


def _get_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _get_ua() -> str:
    return (request.user_agent.string or "unknown")[:256]


# =============================================================================
# login_required
# =============================================================================

def login_required(f):
    """
    Require a valid Auth0 JWT token or active Flask-Login session.

    Sets g.current_user to the authenticated User object so the route
    can access it without another database query.

    Use on any route that requires the user to be logged in:
        @products_bp.route("/cart", methods=["GET"])
        @login_required
        def get_cart():
            user = g.current_user   ← available here
            ...

    Returns 401 if no valid token or session is found.

    STRIDE Spoofing:
        Token verified by Auth0TokenService before User is loaded.
        Inactive users (is_active=False) are rejected even with a valid token.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        user = _verify_and_load_user()

        if not user:
            return _deny(
                message="Authentication required.",
                status=401,
                event="ACCESS_DENIED_NO_AUTH",
            )

        # Make user available in the route via g.current_user
        g.current_user = user
        return f(*args, **kwargs)

    return decorated


# =============================================================================
# require_role
# =============================================================================

def require_role(*roles: str):
    """
    Require the authenticated user to have one of the specified roles.

    MUST be stacked AFTER @login_required — it reads g.current_user
    which login_required sets.

    Allowed roles: 'customer', 'admin'

    Examples:
        # Only admins can delete products
        @products_bp.route("/products/<id>", methods=["DELETE"])
        @login_required
        @require_role("admin")
        def delete_product(id):
            ...

        # Both customers and admins can view order history
        @orders_bp.route("/orders/history", methods=["GET"])
        @login_required
        @require_role("customer", "admin")
        def order_history():
            ...

    Returns 403 if the user's role is not in the allowed list.

    STRIDE Elevation of Privilege:
        Role is read from the MySQL User row — set server-side only.
        It is never read from the JWT token or request body.
        Even if someone edits their JWT payload, the role check uses
        the value in MySQL, not the token.
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            # g.current_user must exist — login_required sets it
            user = getattr(g, "current_user", None)

            if not user:
                # Decorator used without @login_required above it
                logger.error(
                    "[require_role] g.current_user not set. "
                    "Did you forget @login_required above @require_role?"
                )
                return _deny(
                    message="Authentication required.",
                    status=401,
                    event="ACCESS_DENIED_NO_AUTH",
                )

            if user.role not in roles:
                logger.warning(
                    f"[require_role] Access denied. "
                    f"User {user.email} has role '{user.role}', "
                    f"required one of {roles}."
                )
                return _deny(
                    message="You do not have permission to perform this action.",
                    status=403,
                    event="ACCESS_DENIED_WRONG_ROLE",
                    user_id=user.id,
                )

            return f(*args, **kwargs)
        return decorated
    return decorator


# =============================================================================
# guest_or_user
# =============================================================================

def guest_or_user(f):
    """
    Allow both unauthenticated guests AND logged-in users.

    Sets:
        g.current_user = User object  (if logged in)
        g.is_guest     = False        (if logged in)
        g.current_user = None         (if guest)
        g.is_guest     = True         (if guest)

    Use on routes that unregistered visitors can access:
        - Product listing and search
        - Individual product pages
        - Homepage

    Example:
        @products_bp.route("/products", methods=["GET"])
        @guest_or_user
        def list_products():
            if g.is_guest:
                # Guest: show products but prompt to register at checkout
                pass
            else:
                # Logged in: show personalised recommendations, saved items
                user = g.current_user
                pass

    STRIDE Elevation:
        Guest role is set server-side only.
        Guests cannot access cart, checkout, or order history.
        Those routes use @login_required which rejects guests.

    STRIDE Spoofing:
        If an Authorization header IS present, the token is still
        verified fully — a bad token does not silently become a guest.
        It returns 401 instead. Only a missing token becomes a guest.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()

        if token:
            # Token present — verify it properly; never treat bad token as guest
            from app.auth.services import Auth0TokenService
            payload = Auth0TokenService.verify(token)
            if not payload:
                return _deny(
                    message="Invalid or expired token.",
                    status=401,
                    event="ACCESS_DENIED_BAD_TOKEN",
                )
            auth0_id = payload.get("sub")
            user = User.query.filter_by(
                auth0_id=auth0_id,
                is_active=True,
            ).first()
            if user:
                g.current_user = user
                g.is_guest = False
                return f(*args, **kwargs)
            # Token valid but user not synced to MySQL yet
            return _deny(
                message="User profile not found. Please call /auth/sync first.",
                status=404,
                event="ACCESS_DENIED_NOT_SYNCED",
            )

        # No token — check Flask-Login session
        if current_user.is_authenticated and current_user.is_active:
            g.current_user = current_user
            g.is_guest = False
            return f(*args, **kwargs)

        # No token, no session — treat as guest
        g.current_user = None
        g.is_guest = True
        return f(*args, **kwargs)

    return decorated


# =============================================================================
# verified_required
# =============================================================================

def verified_required(f):
    """
    Require the user to have a verified email address.

    MUST be stacked AFTER @login_required.

    Use on sensitive routes where an unverified email is a risk:
        - Checkout and payment
        - Changing account details
        - Accessing order history

    Example:
        @orders_bp.route("/checkout", methods=["POST"])
        @login_required
        @verified_required
        def checkout():
            ...

    Returns 403 with a clear message if the email is not verified.

    STRIDE Info Disclosure:
        Unverified users cannot complete purchases — this prevents
        throwaway email addresses from being used for fraudulent orders.

    Note:
        Auth0 sends the verification email automatically after registration.
        Users can request a new one from the Auth0 Universal Login page.
        is_verified is updated on every /auth/sync call from the token.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        user = getattr(g, "current_user", None)

        if not user:
            logger.error(
                "[verified_required] g.current_user not set. "
                "Did you forget @login_required above @verified_required?"
            )
            return _deny(
                message="Authentication required.",
                status=401,
                event="ACCESS_DENIED_NO_AUTH",
            )

        if not user.is_verified:
            return _deny(
                message=(
                    "Please verify your email address before continuing. "
                    "Check your inbox for a verification email from Auth0."
                ),
                status=403,
                event="ACCESS_DENIED_UNVERIFIED",
                user_id=user.id,
            )

        return f(*args, **kwargs)
    return decorated
