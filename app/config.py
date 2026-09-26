from datetime import timedelta
import os
from dotenv import load_dotenv

# Charger les variables du fichier .env
load_dotenv()
WTF_CSRF_HEADERS = ["X-CSRFToken", "X-CSRF-Token"]
def _key(name: str) -> bytes:
    raw = os.environ.get(name)
    if not raw or len(raw) != 64:
        raise RuntimeError(f"{name} manquante ou invalide (64 hex attendus).")
    return bytes.fromhex(raw)

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
     # --- Clés séparées (CDC CRYP-05) ---
    CONTRACT_ENCRYPTION_KEY = _key("CONTRACT_ENCRYPTION_KEY")  # AES-256-GCM
    INTEGRITY_KEY           = _key("INTEGRITY_KEY")            # HMAC-SHA256

    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 Mo