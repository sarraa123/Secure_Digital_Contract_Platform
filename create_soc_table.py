"""
Script unique pour créer la table soc_alerts.
À exécuter UNE FOIS : python create_soc_table.py
"""
from app import create_app
from app.extensions import db

# ⚠️ IMPORTANT : importer le modèle pour que SQLAlchemy le découvre
from app.models import SOCAlert  # noqa: F401


def main():
    app = create_app()

    with app.app_context():
        # Crée UNIQUEMENT les tables manquantes (n'écrase rien)
        db.create_all()
        print("✅ Tables synchronisées.")

        # Vérification
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()

        if "soc_alerts" in tables:
            print("✅ Table 'soc_alerts' présente.")
        else:
            print("❌ Table 'soc_alerts' ABSENTE — vérifie que SOCAlert est bien importé !")


if __name__ == "__main__":
    main()