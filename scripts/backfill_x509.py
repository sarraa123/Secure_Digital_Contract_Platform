"""
Génère les certificats X.509 manquants pour les utilisateurs existants.
À exécuter UNE SEULE FOIS après la migration Alembic.

Usage (depuis la racine du projet) :
    python scripts/backfill_x509.py
"""
import sys
import os

# Ajoute la racine du projet au PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from app.extensions import db
from app.models import User
from app.services.x509_service import generate_x509_for_user


def main():
    app = create_app()
    with app.app_context():
        users = User.query.filter(User.x509_certificate_pem.is_(None)).all()
        print(f"→ {len(users)} utilisateur(s) à traiter")

        ok = 0
        skipped = 0
        failed = 0

        for user in users:
            if not user.has_signing_keys:
                print(f"⏭️  {user.email} : pas de paire de clés RSA")
                skipped += 1
                continue

            try:
                generate_x509_for_user(user)
                print(f"✅ {user.email}")
                ok += 1
            except Exception as e:
                print(f"❌ {user.email} : {e}")
                failed += 1

        print(f"\n→ OK: {ok} | Skipped: {skipped} | Failed: {failed}")


if __name__ == "__main__":
    main()