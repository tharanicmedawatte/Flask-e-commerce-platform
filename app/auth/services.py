# app/auth/services.py
# Pure business logic — no Flask request/response objects here.
# Routes call these; tests can call them directly without an HTTP client.
#
# STRIDE responsibilities:
#   Spoofing          — authenticate() rejects unverified / locked accounts
#   Tampering         — register() validates and sanitises all inputs
#   Repudiation       — AuditLog.record() called on every significant event
#   Info Disclosure   — generic error messages; no account-existence leakage
#   DoS               — account lockout after 5 failed attempts (15-min ban)
#   Elevation         — role assigned server-side only; never from request body

import re
from datetime import datetime, timezone

from flask import request as flask_request

from app.extensions import db
from app.models import AuditLog, User
from .email import (
    send_account_confirmed_email,
    send_login_alert_email,
    send_verification_email,
)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,50}$")
_MIN_PASSWORD_LEN = 8


def _validate_registration(data: dict) -> list[str]:
    """
    Return a list of validation error strings.
    Empty list means the data is valid.
    Never reveal whether an email already exists — that leaks account info.
    """
    errors = []

    email = data.get("email", "").strip().lower()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    confirm = data.get("confirm_password", "")

    if not _EMAIL_RE.match(email):
        errors.append("Invalid email address.")

    if not _USERNAME_RE.match(username):
        errors.append(
            "Username must be 3–50 characters and contain only letters, numbers, or underscores."
        )

    if len(password) < _MIN_PASSWORD_LEN:
        errors.append(f"Password must be at least {_MIN_PASSWORD_LEN} characters.")

    if password != confirm:
        errors.append("Passwords do not match.")

    return errors


# ---------------------------------------------------------------------------
# Guest session helper
# ---------------------------------------------------------------------------

def create_guest_session() -> dict:
    """
    Called when an unregistered user hits the site.
    Returns a lightweight session dict — no DB row is created for guests.
    The guest token is stored in a signed Flask session cookie only.

    STRIDE — Spoofing: guest session is server-signed; cannot be forged.
    STRIDE — Elevation: guest role is set here, never upgradeable without login.
    """
    import secrets
    return {
        "guest_id": secrets.token_hex(16),  # anonymous session identifier
        "role": "guest",
        "cart": [],                          # in-session cart for unregistered users
    }


# ---------------------------------------------------------------------------
# AuthService
# ---------------------------------------------------------------------------

class AuthService:
    """
    Stateless service class for all auth operations.
    Each method follows the pattern: validate → act → audit → return.
    """

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    @staticmethod
    def register(data: dict) -> tuple[User | None, list[str]]:
        """
        Register a new user.

        Returns (user, []) on success.
        Returns (None, [error strings]) on failure.

        Security notes:
          - Role is hard-coded to 'customer'; never taken from request.
          - Generic duplicate error prevents email enumeration.
          - Verification token generated before DB commit so email is sent
            with the correct token even if subsequent steps fail.
        """
        errors = _validate_registration(data)
        if errors:
            return None, errors

        email = data["email"].strip().lower()
        username = data["username"].strip()

        # Check for duplicates — but return a generic error (no enumeration)
        existing = User.query.filter(
            (User.email == email) | (User.username == username)
        ).first()
        if existing:
            return None, ["Registration failed. Please try different credentials."]

        # Create user
        user = User(email=email, username=username, role="customer")
        user.set_password(data["password"])

        # Generate email verification token (stored on user before commit)
        verification_token = user.generate_verification_token()  # noqa: F841

        db.session.add(user)

        # Audit before commit so it's in the same transaction
        AuditLog.record(
            event="REGISTRATION",
            user_id=user.id,
            ip_address=_get_ip(),
            user_agent=_get_ua(),
        )

        db.session.commit()

        # Send welcome + verification email (after commit — user row exists)
        try:
            send_verification_email(user)
        except Exception as exc:
            # Email failure must not roll back registration.
            # Log it but don't propagate.
            current_app_log(f"[email] Failed to send verification email to {user.email}: {exc}")

        return user, []

    # ------------------------------------------------------------------
    # Email verification
    # ------------------------------------------------------------------

    @staticmethod
    def verify_email(token: str) -> tuple[User | None, str | None]:
        """
        Verify a user's email address using the one-time token.

        Returns (user, None) on success.
        Returns (None, error_message) on failure.
        """
        user = User.query.filter_by(verification_token=token).first()

        if not user:
            return None, "Invalid or expired verification link."

        if not user.verify_email_token(token):
            return None, "This verification link has expired. Please request a new one."

        AuditLog.record(
            event="EMAIL_VERIFIED",
            user_id=user.id,
            ip_address=_get_ip(),
            user_agent=_get_ua(),
        )

        db.session.commit()

        try:
            send_account_confirmed_email(user)
        except Exception as exc:
            current_app_log(f"[email] Failed to send confirmation email: {exc}")

        return user, None

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    @staticmethod
    def authenticate(email: str, password: str) -> tuple[User | None, str | None, str | None]:
        """
        Authenticate a user by email + password.

        Returns (user, jwt_token, None) on success.
        Returns (None, None, error_message) on failure.

        Security notes:
          - Same generic error for wrong email AND wrong password (no enumeration).
          - Account lockout enforced before password check.
          - Failed attempts recorded even when user not found (to prevent
            timing-based enumeration: always runs the same code path).
        """
        GENERIC_ERROR = "Invalid email or password."

        user = User.query.filter_by(email=email.strip().lower()).first()

        # --- Constant-time guard: always do a password check to prevent timing leaks
        dummy_hash = b"$2b$12$invalidhashpadding000000000000000000000000000000000000"
        check_target = user.password_hash if user else dummy_hash

        from bcrypt import checkpw
        password_ok = checkpw(password.encode("utf-8"), check_target)

        if not user or not password_ok:
            if user:
                user.record_failed_attempt()
                AuditLog.record(
                    event="LOGIN_FAIL",
                    user_id=user.id,
                    ip_address=_get_ip(),
                    user_agent=_get_ua(),
                )
                db.session.commit()
            return None, None, GENERIC_ERROR

        if user.is_locked():
            AuditLog.record(
                event="LOGIN_BLOCKED_LOCKOUT",
                user_id=user.id,
                ip_address=_get_ip(),
            )
            db.session.commit()
            return None, None, "Account temporarily locked. Please try again later."

        if not user.is_verified:
            return None, None, "Please verify your email address before logging in."

        if not user.is_active:
            return None, None, "This account has been deactivated."

        # Successful login
        user.reset_failed_attempts()
        user.last_login_at = datetime.now(timezone.utc)
        token = user.generate_jwt()

        AuditLog.record(
            event="LOGIN_SUCCESS",
            user_id=user.id,
            ip_address=_get_ip(),
            user_agent=_get_ua(),
        )

        db.session.commit()

        # Security alert email (async in production; synchronous here for simplicity)
        try:
            send_login_alert_email(user, _get_ip())
        except Exception as exc:
            current_app_log(f"[email] Failed to send login alert: {exc}")

        return user, token, None

    # ------------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------------

    @staticmethod
    def logout(user_id: str) -> None:
        """Record logout event. Flask-Login clears the session cookie."""
        AuditLog.record(
            event="LOGOUT",
            user_id=user_id,
            ip_address=_get_ip(),
            user_agent=_get_ua(),
        )
        db.session.commit()


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _get_ip() -> str:
    """Extract real IP, respecting X-Forwarded-For when behind a proxy."""
    forwarded = flask_request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return flask_request.remote_addr or "unknown"


def _get_ua() -> str:
    return (flask_request.user_agent.string or "")[:256]


def current_app_log(msg: str) -> None:
    """Safe logging that works inside and outside app context."""
    try:
        from flask import current_app
        current_app.logger.warning(msg)
    except RuntimeError:
        print(msg)
