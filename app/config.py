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

    # Empêche JavaScript côté navigateur
    # d'accéder directement au cookie de session.
    SESSION_COOKIE_HTTPONLY = True

    # Empêche les requêtes cross-site classiques
    # d'envoyer automatiquement le cookie.
    SESSION_COOKIE_SAMESITE = "Strict"

    # En développement local avec HTTP :
    # False.
    #
    # En production avec HTTPS :
    # mettre SESSION_COOKIE_SECURE=True dans .env.
    SESSION_COOKIE_SECURE = os.getenv(
        "SESSION_COOKIE_SECURE",
        "False"
    ).lower() == "true"

    # Nom explicite du cookie de session.
    SESSION_COOKIE_NAME = "scp_session"

    # La session ne peut pas dépasser 8 heures.
    #
    # Le timeout d'inactivité de 15 minutes
    # est géré séparément dans routes.py.
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # On ne demande pas à Flask de renouveler
    # automatiquement la durée à chaque requête.
    SESSION_REFRESH_EACH_REQUEST = False

    # Flask-Login session protection
    SESSION_PROTECTION = "strong"
     # --- Clés séparées (CDC CRYP-05) ---
    CONTRACT_ENCRYPTION_KEY = _key("CONTRACT_ENCRYPTION_KEY")  # AES-256-GCM
    INTEGRITY_KEY           = _key("INTEGRITY_KEY")            # HMAC-SHA256

    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 Mo