# app/auth/routes.py
# HTTP routes for the auth blueprint.
# Kept thin — validation and business logic live in services.py.
# Each route does: parse → call service → return response → nothing else.
#
# Endpoints:
#   POST /auth/register          — new user registration
#   GET  /auth/verify/<token>    — email verification link
#   POST /auth/login             — login (returns JWT)
#   POST /auth/logout            — logout (clears session + audit)
#   GET  /auth/me                — current user profile (JWT-protected)
#   POST /auth/guest-session     — initialise a guest session token

from flask import Blueprint, jsonify, request, session
from flask_login import login_user, logout_user, current_user

from app.extensions import limiter
from .decorators import login_required, guest_or_user
from .services import AuthService, create_guest_session

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5 per minute; 20 per hour")     # prevents account-creation floods
def register():
    """
    Register a new user account.

    Expects JSON:
        { "email": "...", "username": "...",
          "password": "...", "confirm_password": "..." }

    On success: 201 with user dict (no password, no token — user must verify first).
    On failure: 400 with list of validation errors.

    STRIDE — Spoofing: generic error on duplicate (no email enumeration).
    STRIDE — DoS:      rate-limited to 5 attempts/minute per IP.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    user, errors = AuthService.register(data)

    if errors:
        return jsonify({"errors": errors}), 400

    return jsonify({
        "message": "Account created. Please check your email to verify your address.",
        "user": user.to_dict(),
    }), 201


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------

@auth_bp.route("/verify/<string:token>", methods=["GET"])
@limiter.limit("10 per minute")
def verify_email(token: str):
    """
    One-click email verification.
    The link is emailed to the user after registration.

    On success: 200 — account is now active.
    On failure: 400 — token invalid or expired.

    STRIDE — Info Disclosure: token is opaque (random hex); no PII in URL.
    """
    if len(token) != 64:                    # quick sanity check before hitting DB
        return jsonify({"error": "Invalid verification link."}), 400

    user, error = AuthService.verify_email(token)

    if error:
        return jsonify({"error": error}), 400

    return jsonify({
        "message": "Email verified successfully. You can now log in.",
        "user": user.to_dict(),
    }), 200


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute; 50 per hour")    # brute-force guard
def login():
    """
    Authenticate with email + password.

    Expects JSON: { "email": "...", "password": "..." }

    On success: 200 with JWT access token.
    On failure: 401 with generic error (same message for wrong email OR password).

    STRIDE — Spoofing:     bcrypt comparison + generic error message.
    STRIDE — DoS:          rate-limited + account lockout after 5 failures.
    STRIDE — Repudiation:  login event written to AuditLog in service layer.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    email = data.get("email", "")
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    user, token, error = AuthService.authenticate(email, password)

    if error:
        return jsonify({"error": error}), 401

    # For browser clients: also set Flask-Login session
    login_user(user, remember=data.get("remember_me", False))

    return jsonify({
        "message": "Login successful.",
        "token": token,                # JWT for API / mobile clients
        "user": user.to_dict(),
    }), 200


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """
    Log out the current user.
    Clears Flask-Login session and records the event.

    STRIDE — Repudiation: logout event written to AuditLog.
    """
    from flask import g
    user = getattr(g, "current_user", current_user)
    AuthService.logout(user.id)
    logout_user()
    session.clear()

    return jsonify({"message": "Logged out successfully."}), 200


# ---------------------------------------------------------------------------
# Current user profile
# ---------------------------------------------------------------------------

@auth_bp.route("/me", methods=["GET"])
@login_required
def me():
    """
    Return the authenticated user's profile.
    Never returns password_hash or sensitive tokens.

    STRIDE — Info Disclosure: to_dict() is the whitelist; nothing else is sent.
    """
    from flask import g
    user = getattr(g, "current_user", current_user)
    return jsonify({"user": user.to_dict()}), 200


# ---------------------------------------------------------------------------
# Guest session
# ---------------------------------------------------------------------------

@auth_bp.route("/guest-session", methods=["POST"])
@limiter.limit("20 per minute")
def guest_session():
    """
    Initialise a guest session for unregistered visitors.
    Returns a signed session identifier so the guest's cart and browsing
    context can be persisted across requests without a DB row.

    Guests can browse products and add items to cart.
    They are prompted to register at checkout.

    STRIDE — Elevation: role='guest' is set server-side; cannot be escalated
                        without completing registration.
    """
    guest_data = create_guest_session()

    # Store guest context in the Flask signed cookie session
    session["guest_id"] = guest_data["guest_id"]
    session["role"] = "guest"

    return jsonify({
        "guest_id": guest_data["guest_id"],
        "role": "guest",
        "message": "Guest session started. Register to save your cart and order history.",
    }), 200


# ---------------------------------------------------------------------------
# Blueprint __init__.py helper (also register here so imports are clean)
# ---------------------------------------------------------------------------
# app/auth/__init__.py should contain only:
#   from .routes import auth_bp
#   __all__ = ["auth_bp"]
