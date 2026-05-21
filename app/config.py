# =============================================================================
# app/config.py
# Configuration classes for all environments.
# Shared file — owned by all three developers.
#
# What this file does:
#   Defines three configuration classes:
#     DevelopmentConfig — local development on your laptop
#     TestingConfig     — automated tests (pytest)
#     ProductionConfig  — live server
#
#   All sensitive values (passwords, API keys, secrets) are loaded from
#   environment variables — NEVER hardcoded here.
#
# How environment variables work:
#   1. Locally:    create a .env file (copied from .env.example)
#                  python-dotenv loads it automatically via run.py
#   2. On server:  set environment variables directly on the server
#                  or in your hosting platform's dashboard
#
# Adding a new config value (for all developers):
#   1. Add the variable to this file under the correct section
#   2. Add it to .env.example with a placeholder value and a comment
#   3. Tell the other two developers to add it to their .env files
#   4. Set it on the server before deploying
#
# STRIDE coverage:
#   Info Disclosure   — secrets loaded from env vars, never committed to Git
#   Tampering         — SESSION_COOKIE_HTTPONLY and SECURE prevent cookie theft
#   DoS               — rate limit defaults configured here
# =============================================================================

import os
from datetime import timedelta


# =============================================================================
# Helper — fail loudly on missing required variables
# =============================================================================

def _require(var: str) -> str:
    """
    Raise a clear RuntimeError if a required environment variable is not set.
    Called at app startup — catches missing config before any request is served.

    This is intentionally loud. A missing SECRET_KEY or AUTH0_DOMAIN should
    crash the app immediately, not silently serve broken responses.
    """
    value = os.environ.get(var)
    if not value:
        raise RuntimeError(
            f"\n\n  Missing required environment variable: '{var}'\n"
            f"  Copy .env.example to .env and fill in the value.\n"
            f"  On the server, set it as an environment variable.\n"
        )
    return value


# =============================================================================
# Base config — shared across all environments
# =============================================================================

class Config:
    """
    Base configuration. All environment-specific classes inherit from this.
    Values here apply everywhere unless overridden below.
    """

    # ------------------------------------------------------------------
    # Flask core
    # SECRET_KEY signs session cookies and CSRF tokens.
    # STRIDE Tampering: a strong, secret key prevents cookie forgery.
    # Must be a long random string — never a word or short phrase.
    # Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
    # ------------------------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    DEBUG      = False
    TESTING    = False

    # ------------------------------------------------------------------
    # Database — SQLAlchemy
    # Developer 1 owns this section.
    # Dev 2 and Dev 3 use the same DATABASE_URL — they share one database.
    # ------------------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///ecommerce_dev.db",   # safe local fallback
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping":  True,   # test connections before using — handles dropped DB connections
        "pool_recycle":   300,    # recycle connections every 5 min — prevents stale connections
        "pool_size":      10,     # max persistent connections in the pool
        "max_overflow":   20,     # max extra connections above pool_size under load
    }

    # ------------------------------------------------------------------
    # Auth0
    # Developer 1 owns this section.
    # These values come from your Auth0 dashboard:
    #   AUTH0_DOMAIN   — Settings → Domain  e.g. "yourapp.auth0.com"
    #   AUTH0_AUDIENCE — APIs → your API → Identifier
    #                    e.g. "https://api.yourapp.com"
    #
    # STRIDE Spoofing:
    #   AUTH0_DOMAIN is used to verify the JWT issuer (iss claim).
    #   AUTH0_AUDIENCE is used to verify the JWT audience (aud claim).
    #   Both must match exactly — a token from a different Auth0 tenant
    #   or a different API will be rejected.
    # ------------------------------------------------------------------
    AUTH0_DOMAIN   = os.environ.get("AUTH0_DOMAIN", "")
    AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE", "")

    # ------------------------------------------------------------------
    # Frontend URL
    # Used for:
    #   1. CORS — only this origin can call the Flask API
    #   2. Redirects — browser clients are redirected here on 401/403
    #
    # STRIDE Info Disclosure:
    #   Only the whitelisted FRONTEND_URL can make cross-origin requests.
    #   Wildcard "*" is never used.
    # ------------------------------------------------------------------
    FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")

    # ------------------------------------------------------------------
    # Session cookies
    # STRIDE Tampering / Spoofing:
    #   HTTPONLY  — JavaScript cannot read the session cookie.
    #               Prevents cookie theft via XSS.
    #   SAMESITE  — browser only sends cookie on same-site requests.
    #               "Lax" allows GET navigation, blocks cross-site POST.
    #   SECURE    — cookie only sent over HTTPS.
    #               Overridden to False in DevelopmentConfig for localhost.
    # ------------------------------------------------------------------
    SESSION_COOKIE_HTTPONLY  = True
    SESSION_COOKIE_SAMESITE  = "Lax"
    SESSION_COOKIE_SECURE    = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)

    # ------------------------------------------------------------------
    # Rate limiting (Flask-Limiter)
    # STRIDE DoS: default limits applied to every endpoint automatically.
    # Individual routes can override with @limiter.limit("N per period").
    #
    # Storage:
    #   "memory://"              — local dev (resets on restart)
    #   "redis://localhost:6379" — production (persists across restarts)
    # ------------------------------------------------------------------
    RATELIMIT_STORAGE_URI = os.environ.get("REDIS_URL", "memory://")
    RATELIMIT_DEFAULT     = "300 per day;60 per hour;10 per minute"
    RATELIMIT_HEADERS_ENABLED = True    # X-RateLimit-* headers in responses

    # ------------------------------------------------------------------
    # Mail (Flask-Mail)
    # Used by Developer 3 for order confirmation emails via SendGrid SMTP.
    # Auth0 handles all auth-related emails (verification, password reset).
    # ------------------------------------------------------------------
    MAIL_SERVER         = os.environ.get("MAIL_SERVER",  "smtp.sendgrid.net")
    MAIL_PORT           = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS        = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USERNAME       = os.environ.get("MAIL_USERNAME", "apikey")  # SendGrid uses "apikey"
    MAIL_PASSWORD       = os.environ.get("MAIL_PASSWORD", "")        # SendGrid API key
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@yourshop.com")

    # ------------------------------------------------------------------
    # SendGrid (Developer 3)
    # Direct API client — alternative to SMTP for order emails.
    # ------------------------------------------------------------------
    SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")

    # ------------------------------------------------------------------
    # Stripe (Developer 3)
    # STRIPE_SECRET_KEY      — server-side only, never sent to frontend
    # STRIPE_PUBLISHABLE_KEY — safe to send to Next.js frontend
    # STRIPE_WEBHOOK_SECRET  — verifies Stripe webhook signatures
    #
    # STRIDE Spoofing:
    #   STRIPE_WEBHOOK_SECRET is used to verify that webhook calls are
    #   genuinely from Stripe and not from a third party pretending to
    #   be Stripe. Never skip this verification.
    # ------------------------------------------------------------------
    STRIPE_SECRET_KEY       = os.environ.get("STRIPE_SECRET_KEY",      "")
    STRIPE_PUBLISHABLE_KEY  = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
    STRIPE_WEBHOOK_SECRET   = os.environ.get("STRIPE_WEBHOOK_SECRET",  "")

    # ------------------------------------------------------------------
    # Security headers (Flask-Talisman)
    # Configured in __init__.py using these values.
    # STRIDE Info Disclosure / Tampering:
    #   CSP restricts which scripts and resources the browser will load.
    #   Prevents XSS by blocking inline scripts and unknown origins.
    # ------------------------------------------------------------------
    TALISMAN_FORCE_HTTPS = True
    CONTENT_SECURITY_POLICY = {
        "default-src": "'self'",
        "script-src":  ["'self'", "https://js.stripe.com"],   # Stripe.js needs this
        "frame-src":   ["'self'", "https://js.stripe.com"],   # Stripe payment iframe
        "style-src":   ["'self'", "'unsafe-inline'"],
        "img-src":     ["'self'", "data:", "https:"],
        "connect-src": [
            "'self'",
            "https://*.auth0.com",    # Auth0 token requests from browser
            "https://api.stripe.com", # Stripe API calls from browser
        ],
    }


# =============================================================================
# Development config
# =============================================================================

class DevelopmentConfig(Config):
    """
    Local development on your laptop.
    Relaxes security settings that would break localhost workflows.
    NEVER use this in production.
    """
    DEBUG = True

    # Use SQLite locally — no MySQL installation needed for development.
    # Switch to MySQL by setting DATABASE_URL in your .env file.
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///ecommerce_dev.db",
    )

    # Allow HTTP on localhost — SESSION_COOKIE_SECURE=True would break
    # local development since localhost doesn't have HTTPS.
    SESSION_COOKIE_SECURE  = False
    TALISMAN_FORCE_HTTPS   = False

    # Print emails to the console instead of sending them.
    # Lets you see email content during development without an SMTP server.
    MAIL_SUPPRESS_SEND = True

    # Disable CSRF for easier API testing with Postman / curl.
    # Re-enable in staging/production.
    WTF_CSRF_ENABLED = False

    # More permissive rate limits locally — don't throttle yourself
    # while developing and testing.
    RATELIMIT_DEFAULT = "10000 per day;1000 per hour;100 per minute"


# =============================================================================
# Testing config
# =============================================================================

class TestingConfig(Config):
    """
    Used when running pytest.
    Uses an in-memory SQLite database — fast, isolated, no cleanup needed.
    """
    TESTING = True
    DEBUG   = True

    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

    # Never send real emails during tests
    MAIL_SUPPRESS_SEND = True

    # Disable CSRF so test clients don't need to send tokens
    WTF_CSRF_ENABLED = False

    # Disable rate limiting so tests don't throttle themselves
    RATELIMIT_ENABLED = False

    SESSION_COOKIE_SECURE  = False
    TALISMAN_FORCE_HTTPS   = False

    # Use a fixed secret key in tests for reproducibility
    SECRET_KEY = "test-secret-key-not-for-production"


# =============================================================================
# Production config
# =============================================================================

class ProductionConfig(Config):
    """
    Live server configuration.
    All required values must be set as environment variables.
    The app will refuse to start if any required variable is missing.
    """

    DEBUG   = False
    TESTING = False

    # ------------------------------------------------------------------
    # Required in production — app crashes clearly if missing.
    # This is intentional: better a startup crash than a silent failure.
    # ------------------------------------------------------------------

    @classmethod
    def validate(cls):
        """
        Call this in create_app() when env='production'.
        Raises RuntimeError for any missing required variable.
        """
        required = [
            "SECRET_KEY",
            "DATABASE_URL",
            "AUTH0_DOMAIN",
            "AUTH0_AUDIENCE",
            "FRONTEND_URL",
            "REDIS_URL",
            "STRIPE_SECRET_KEY",
            "STRIPE_PUBLISHABLE_KEY",
            "STRIPE_WEBHOOK_SECRET",
            "SENDGRID_API_KEY",
        ]
        missing = [v for v in required if not os.environ.get(v)]
        if missing:
            raise RuntimeError(
                f"\n\n  Missing required environment variables for production:\n"
                + "".join(f"    - {v}\n" for v in missing)
                + "\n  Set them on your server before deploying.\n"
            )

    # Use MySQL in production — SQLite is not suitable for a live server.
    # DATABASE_URL format:
    #   mysql+pymysql://username:password@host:3306/ecommerce
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "")

    # Use Redis for rate limiting — persists across server restarts
    # and works correctly with multiple server processes.
    RATELIMIT_STORAGE_URI = os.environ.get("REDIS_URL", "memory://")

    # All security flags on in production
    SESSION_COOKIE_SECURE  = True
    TALISMAN_FORCE_HTTPS   = True


# =============================================================================
# Config map — used by create_app() in app/__init__.py
# =============================================================================

config_map = {
    "development": DevelopmentConfig,
    "testing":     TestingConfig,
    "production":  ProductionConfig,
    "default":     DevelopmentConfig,
}
