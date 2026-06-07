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

from app import create_app  # noqa: E402 (import after load_dotenv is intentional)

app = create_app()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",   # localhost only — Nginx handles public traffic
        port=5000,
        debug=True,
    )
