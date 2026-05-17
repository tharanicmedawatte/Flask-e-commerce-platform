# run.py  — Entry point (development only; use gunicorn in production)
from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)


# =============================================================================
# requirements.txt
# =============================================================================
REQUIREMENTS = """
flask>=3.0
flask-sqlalchemy>=3.1
flask-login>=0.6
flask-mail>=0.10
flask-limiter>=3.5
flask-wtf>=1.2
flask-migrate>=4.0
flask-talisman>=1.1
bcrypt>=4.1
PyJWT>=2.8
python-dotenv>=1.0
"""

# To install:  pip install -r requirements.txt
# To run:      flask --app run db init && flask --app run db migrate && flask --app run db upgrade
#              python run.py
