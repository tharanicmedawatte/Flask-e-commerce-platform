# =============================================================================
# app/auth/routes.py
# HTTP endpoints for the auth blueprint.
#
# What this file does:
#   Exposes the API endpoints that Next.js calls after Auth0 authentication.
#   Every route is intentionally thin — it only:
#     1. Extracts data from the request
#     2. Calls a service function
#     3. Returns a JSON response
#   All logic lives in services.py, not here.
#
# Endpoints:
#   POST /auth/sync      — called by Next.js after every Auth0 login
#                          creates/updates the MySQL user row
#   GET  /auth/me        — returns the current user's profile
#   POST /auth/logout    — records logout event in AuditLog
#   GET  /auth/status    — health check, tells Next.js if token is valid
#
# Auth flow reminder:
#   Next.js → Auth0 Universal Login → Auth0 returns JWT → Next.js stores token
#   → Next.js calls /auth/sync with token → Flask verifies + syncs MySQL row
#   → All subsequent requests carry Authorization: Bearer <token>
#
# What this file does NOT do:
#   - No login form or register form — Auth0 handles those
#   - No password handling — Auth0 handles that
#   - No MFA setup — Auth0 handles that (configured in Auth0 dashboard)
#   - No email verification emails — Auth0 handles those too
# =============================================================================

import logging
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request
from flask_login import logout_user

from app.extensions import db, limiter
from app.models import AuditLog, User
from .services import Auth0TokenService, UserSyncService

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# =============================================================================
# Helper — used by every route in this file
# =============================================================================

def _extract_token() -> str | None:
    """
    Extract the Bearer token from the Authorization header.

    Expected header format:
        Authorization: Bearer eyJhbGciOiJSUzI1NiIs...

    Returns the token string or None if the header is missing or malformed.

    STRIDE Spoofing: token is extracted here but NOT trusted until
    Auth0TokenService.verify() confirms the signature in each route.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer ") and len(auth_header) > 7:
        return auth_header.split(" ", 1)[1].strip()
    return None


def _get_ip() -> str:
    """Real client IP, respecting X-Forwarded-For behind Nginx."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _get_ua() -> str:
    """Truncated User-Agent for audit logging."""
    return (request.user_agent.string or "unknown")[:256]


# =============================================================================
# POST /auth/sync
# =============================================================================

@auth_bp.route("/sync", methods=["POST"])
@limiter.limit("30 per minute")
def sync_user():
    """
    Sync an Auth0 user into MySQL after login.

    Called by Next.js immediately after Auth0 returns a token.
    This is the entry point for all new users into the MySQL database.
    Returning users are updated (last_login_at, is_verified).

    Request:
        POST /auth/sync
        Authorization: Bearer <auth0_access_token>
        Content-Type: application/json  (body can be empty)

    Response 200:
        {
            "message": "User synced successfully.",
            "user": { id, email, username, role, is_verified, ... }
        }

    Response 401:
        { "error": "..." }

    STRIDE Spoofing:
        Token is verified cryptographically before any DB operation.
        A missing, expired, or tampered token returns 401 immediately.

    STRIDE Repudiation:
        REGISTRATION_AUTH0 or LOGIN_AUTH0 written to AuditLog in service.

    STRIDE DoS:
        Rate limited to 30 requests per minute per IP.
        In practice, Next.js calls this once per login — limit is generous
        but still protects against automated abuse.
    """
    token = _extract_token()
    if not token:
        # STRIDE Info Disclosure: generic message — no detail about what's wrong
        return jsonify({"error": "Authorization token required."}), 401

    # Verify token signature, expiry, audience, issuer with Auth0
    auth0_payload = Auth0TokenService.verify(token)
    if not auth0_payload:
        return jsonify({"error": "Invalid or expired token."}), 401

    # Sync to MySQL — creates new row or updates existing
    user, error = UserSyncService.sync(auth0_payload)
    if error:
        return jsonify({"error": error}), 500

    return jsonify({
        "message": "User synced successfully.",
        "user": user.to_dict(),
    }), 200


# =============================================================================
# GET /auth/me
# =============================================================================

@auth_bp.route("/me", methods=["GET"])
@limiter.limit("60 per minute")
def me():
    """
    Return the authenticated user's profile from MySQL.

    Called by Next.js to get the full user profile (role, verified status, etc.)
    after Auth0 login. Auth0's own /userinfo endpoint returns Auth0 data;
    this endpoint returns our application data (role, created_at, order history).

    Request:
        GET /auth/me
        Authorization: Bearer <auth0_access_token>

    Response 200:
        {
            "user": { id, email, username, role, is_verified, created_at, ... }
        }

    Response 401:
        { "error": "..." }

    Response 404:
        { "error": "User not found. Please sync first." }
        This happens if Next.js calls /me before calling /sync.
        Next.js should always call /sync first, then /me.

    STRIDE Info Disclosure:
        to_dict() returns a whitelist of safe fields only.
        auth0_id, internal flags, and audit logs are never returned.
    """
    token = _extract_token()
    if not token:
        return jsonify({"error": "Authorization token required."}), 401

    auth0_payload = Auth0TokenService.verify(token)
    if not auth0_payload:
        return jsonify({"error": "Invalid or expired token."}), 401

    auth0_id = auth0_payload.get("sub")
    user = User.query.filter_by(auth0_id=auth0_id).first()

    if not user:
        # User exists in Auth0 but not yet synced to MySQL
        # Instruct Next.js to call /auth/sync first
        return jsonify({
            "error": "User profile not found. Please call /auth/sync first."
        }), 404

    if not user.is_active:
        # STRIDE Elevation: deactivated users cannot access any resource
        AuditLog.record(
            event="ACCESS_DENIED_INACTIVE",
            user_id=user.id,
            ip_address=_get_ip(),
            user_agent=_get_ua(),
        )
        db.session.commit()
        return jsonify({"error": "Account deactivated. Please contact support."}), 403

    return jsonify({"user": user.to_dict()}), 200


# =============================================================================
# POST /auth/logout
# =============================================================================

@auth_bp.route("/logout", methods=["POST"])
@limiter.limit("30 per minute")
def logout():
    """
    Record a logout event in AuditLog.

    Auth0 and Next.js handle the actual session/token invalidation on
    the frontend. This endpoint exists purely for the server-side audit trail.

    Next.js logout flow:
        1. Call POST /auth/logout (this endpoint) — records audit event
        2. Call Auth0's /v2/logout — clears Auth0 session
        3. Clear the token from Next.js state/localStorage

    Request:
        POST /auth/logout
        Authorization: Bearer <auth0_access_token>

    Response 200:
        { "message": "Logged out successfully." }

    STRIDE Repudiation:
        LOGOUT event written to AuditLog so there is a server-side record
        that the user ended their session at a specific time from a specific IP.
    """
    token = _extract_token()

    if token:
        auth0_payload = Auth0TokenService.verify(token)
        if auth0_payload:
            auth0_id = auth0_payload.get("sub")
            user = User.query.filter_by(auth0_id=auth0_id).first()
            if user:
                AuditLog.record(
                    event="LOGOUT",
                    user_id=user.id,
                    ip_address=_get_ip(),
                    user_agent=_get_ua(),
                )
                db.session.commit()
                logger.info(f"[Auth] Logout recorded for user: {user.email}")

    # Clear Flask-Login session if active (browser clients)
    logout_user()

    # Always return 200 — logout should never fail from the user's perspective
    return jsonify({"message": "Logged out successfully."}), 200


# =============================================================================
# GET /auth/status
# =============================================================================

@auth_bp.route("/status", methods=["GET"])
@limiter.limit("60 per minute")
def status():
    """
    Token validity check — used by Next.js to gate protected pages.

    Next.js calls this on page load to check if the stored token is still
    valid before rendering protected content (e.g. account page, checkout).
    Faster than calling /me — returns minimal data.

    Request:
        GET /auth/status
        Authorization: Bearer <auth0_access_token>

    Response 200 (valid token, active user):
        {
            "authenticated": true,
            "role": "customer",
            "is_verified": true
        }

    Response 200 (no token / invalid token):
        {
            "authenticated": false
        }

    Note: Always returns HTTP 200 — Next.js checks the "authenticated" field.
    This avoids error handling complexity on the frontend for this common check.

    STRIDE Info Disclosure:
        Returns only role and is_verified — the minimum Next.js needs to
        decide which page to render. Full profile requires /auth/me.
    """
    token = _extract_token()

    if not token:
        return jsonify({"authenticated": False}), 200

    auth0_payload = Auth0TokenService.verify(token)
    if not auth0_payload:
        return jsonify({"authenticated": False}), 200

    auth0_id = auth0_payload.get("sub")
    user = User.query.filter_by(auth0_id=auth0_id).first()

    if not user or not user.is_active:
        return jsonify({"authenticated": False}), 200

    return jsonify({
        "authenticated": True,
        "role":          user.role,
        "is_verified":   user.is_verified,
    }), 200
