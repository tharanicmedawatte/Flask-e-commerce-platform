# =============================================================================
# app/extensions.py
# Initialises all Flask extensions in one place.
#
# RULES FOR ALL THREE DEVELOPERS:
#   - ALWAYS import extensions from here — never re-instantiate them.
#   - NEVER import from app/__init__.py — that causes circular imports.
#   - Extensions are created here without an app object (app factory pattern).
#     They are bound to the app later inside create_app() in app/__init__.py.
#
# Usage in any blueprint:
#   from app.extensions import db, limiter, csrf
# =============================================================================

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_cors import CORS


# -----------------------------------------------------------------------------
# Database
# ORM for all three developers — models.py defines the tables,
# blueprints use db.session to query and commit.
# -----------------------------------------------------------------------------
db = SQLAlchemy()


# -----------------------------------------------------------------------------
# Login manager (Flask-Login)
# Manages the server-side session cookie for browser clients.
# JWT via Auth0 is the primary auth method; Flask-Login is the fallback
# for server-rendered pages if needed.
#
# STRIDE Spoofing: unauthorized_handler returns 401 JSON instead of
# redirecting API clients to a login page that doesn't exist.
# -----------------------------------------------------------------------------
login_manager = LoginManager()
login_manager.session_protection = "strong"   # regenerate session ID on login


@login_manager.user_loader
def load_user(user_id: str):
    """
    Flask-Login calls this on every request to reload the user from
    the session cookie. Returns None (not raises) if not found.
    Local import breaks the circular dependency:
    extensions → models → extensions.
    """
    from app.models import User
    return db.session.get(User, user_id)


@login_manager.unauthorized_handler
def handle_unauthorized():
    """
    STRIDE Spoofing / Elevation:
    Unregistered or unauthenticated requests get a clean 401 JSON response.
    Never redirect API clients to an HTML login page.
    """
    from flask import request, jsonify, redirect, url_for
    wants_json = (
        request.accept_mimetypes.best_match(
            ["application/json", "text/html"]
        ) == "application/json"
    )
    if wants_json:
        return jsonify({"error": "Authentication required."}), 401
    # Browser fallback — Auth0 Universal Login handles the actual login page
    return redirect(url_for("auth.login"))


# -----------------------------------------------------------------------------
# Mail (Flask-Mail)
# Used by Developer 3 for order confirmation emails via SendGrid SMTP.
# Developer 1 does NOT send auth emails — Auth0 handles those
# (verification, password reset, MFA setup emails are all from Auth0).
# -----------------------------------------------------------------------------
mail = Mail()


# -----------------------------------------------------------------------------
# Rate limiter (Flask-Limiter)
# STRIDE Denial of Service: limits requests per IP across all endpoints.
#
# Default limits apply to every route automatically.
# Individual routes can override with @limiter.limit("N per period").
#
# Storage:
#   Development  — in-memory (resets on restart, fine for local dev)
#   Production   — Redis via RATELIMIT_STORAGE_URI env var
#                  Set REDIS_URL=redis://localhost:6379 in .env
# -----------------------------------------------------------------------------
limiter = Limiter(
    key_func=get_remote_address,        # rate limit by client IP
    default_limits=[
        "300 per day",
        "60 per hour",
        "10 per minute",
    ],
    headers_enabled=True,               # adds X-RateLimit-* headers to responses
                                        # so frontend can show "try again in Xs"
    storage_uri=None,                   # set via app.config["RATELIMIT_STORAGE_URI"]
)


# -----------------------------------------------------------------------------
# CSRF protection (Flask-WTF)
# STRIDE Tampering: prevents cross-site request forgery on state-changing
# endpoints that use session cookies.
#
# Notes:
#   - Auth0 endpoints use JWT Bearer tokens — CSRF is not applicable there.
#   - Developer 3's Stripe webhook must be @csrf.exempt (Stripe cannot
#     send a CSRF token).
#   - JSON API endpoints using Authorization: Bearer header are safe from
#     CSRF by definition — CSRF only affects cookie-based auth.
# -----------------------------------------------------------------------------
csrf = CSRFProtect()


# -----------------------------------------------------------------------------
# Database migrations (Flask-Migrate / Alembic)
# Used by all three developers to evolve the schema safely.
#
# Workflow when adding a new model or column:
#   flask db migrate -m "add Product model"   ← generates migration file
#   flask db upgrade                          ← applies it to the database
#
# NEVER edit the database schema directly — always go through migrations.
# NEVER commit an unapplied migration — always run upgrade before pushing.
# -----------------------------------------------------------------------------
migrate = Migrate()


# -----------------------------------------------------------------------------
# CORS (Flask-CORS)
# Allows the Next.js frontend (different domain/port) to call the Flask API.
#
# STRIDE Info Disclosure: origins are whitelisted explicitly.
# Wildcard "*" is never used — that would allow any website to call the API.
#
# Configured in create_app() with the FRONTEND_URL environment variable
# so the allowed origin can change between environments without code changes:
#   Development  — http://localhost:3000
#   Production   — https://your-nextjs-site.vercel.app
#
# This object is initialised here; actual origins are passed in __init__.py.
# -----------------------------------------------------------------------------
cors = CORS()
