# app/extensions.py
# Initialise all Flask extensions here (no app object yet — use app factory pattern).
# Import from this module everywhere. Never re-instantiate extensions in blueprints.

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate

# ---------------------------------------------------------------------------
# Core extensions
# ---------------------------------------------------------------------------

db = SQLAlchemy()

login_manager = LoginManager()
login_manager.login_view = "auth.login"           # redirect target for @login_required
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"

mail = Mail()

# ---------------------------------------------------------------------------
# Rate limiter  (DoS / brute-force mitigation)
# ---------------------------------------------------------------------------
# Default: 200 requests/day, 50/hour per IP.
# Individual routes can override with @limiter.limit("N per M").
# Storage is in-memory by default; swap to Redis in production:
#   RATELIMIT_STORAGE_URI = "redis://localhost:6379"
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    headers_enabled=True,           # adds X-RateLimit-* headers to responses
)

# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------
# Automatically protects all state-changing form/JSON routes.
# Exempt specific routes (e.g. payment webhooks) with @csrf.exempt.
csrf = CSRFProtect()

# ---------------------------------------------------------------------------
# Database migrations
# ---------------------------------------------------------------------------
migrate = Migrate()


# ---------------------------------------------------------------------------
# User loader for Flask-Login
# ---------------------------------------------------------------------------
# Defined here to avoid circular imports (models → extensions → models).

@login_manager.user_loader
def load_user(user_id: str):
    """
    Flask-Login calls this on every request to reload the user from the session.
    Returns None (not raises) if user not found — Flask-Login handles the redirect.
    """
    from app.models import User          # local import to break circular dependency
    return User.query.get(user_id)


# ---------------------------------------------------------------------------
# Unauthorised handler
# ---------------------------------------------------------------------------

@login_manager.unauthorized_handler
def handle_unauthorized():
    """
    Unregistered / unauthenticated users hitting a protected route.
    Returns JSON for API clients; could redirect to login page for browser clients.
    """
    from flask import request, jsonify, redirect, url_for
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({"error": "Authentication required"}), 401
    return redirect(url_for("auth.login"))
