from datetime import timedelta
import os
from dotenv import load_dotenv

# Charger les variables du fichier .env
load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///app.db"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # =========================
    # SESSION SECURITY
    # =========================

    SESSION_COOKIE_HTTPONLY = True

    SESSION_COOKIE_SAMESITE = "Strict"

    SESSION_COOKIE_SECURE = os.getenv(
        "SESSION_COOKIE_SECURE",
        "False"
    ).lower() == "true"

    SESSION_COOKIE_NAME = "scp_session"

    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)

    SESSION_REFRESH_EACH_REQUEST = False

    # Flask-Login session protection
    SESSION_PROTECTION = "strong"