# =============================================================================
# run.py
# Entry point for the Flask application.
#
# Development:  python run.py
# Production:   gunicorn -w 4 -b 0.0.0.0:8000 "run:app"
#
# Never use python run.py in production — it uses Flask's single-threaded
# dev server. Gunicorn handles multiple workers and real traffic.
# =============================================================================

from dotenv import load_dotenv

# Load .env file into environment variables BEFORE importing app.
# This must happen first — config.py reads os.environ at import time.
load_dotenv()

from app import create_app   # noqa: E402 (import after load_dotenv is intentional)

app = create_app()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",   # localhost only — Nginx handles public traffic
        port=5000,
        debug=True,
    )


# =============================================================================
# requirements.txt
# All Python packages needed by all three developers.
# Install with: pip install -r requirements.txt
#
# Sections:
#   Core Flask       — framework and extensions
#   Database         — SQLAlchemy + MySQL driver
#   Auth0            — JWT verification
#   Payments         — Stripe
#   Email            — SendGrid
#   Security         — Talisman, bcrypt
#   Dev tools        — testing, linting
# =============================================================================

REQUIREMENTS = """
# ── Core Flask ────────────────────────────────────────────────────────────────
flask>=3.0
flask-sqlalchemy>=3.1
flask-login>=0.6
flask-mail>=0.10
flask-limiter>=3.5
flask-wtf>=1.2
flask-migrate>=4.0
flask-talisman>=1.1
flask-cors>=4.0

# ── Database ──────────────────────────────────────────────────────────────────
pymysql>=1.1
cryptography>=42.0        # required by PyMySQL for secure connections

# ── Auth0 JWT verification ────────────────────────────────────────────────────
python-jose[cryptography]>=3.3
requests>=2.31            # fetches Auth0 JWKS public keys

# ── Payments ──────────────────────────────────────────────────────────────────
stripe>=8.0

# ── Email ─────────────────────────────────────────────────────────────────────
sendgrid>=6.11

# ── Environment variables ─────────────────────────────────────────────────────
python-dotenv>=1.0

# ── Dev tools (not needed in production) ──────────────────────────────────────
pytest>=8.0
pytest-flask>=1.3
bandit>=1.7               # security linter — catches common vulnerabilities
flake8>=7.0               # code style linter
"""
