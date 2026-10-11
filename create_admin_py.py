# create_admin_py.py
from app import create_app, db
from app.models import User
from app.auth.services import hash_password
from app.services.crypto_service import generate_keypair

app = create_app()

with app.app_context():
    # --- Paramètres à modifier ---
    USERNAME = "Admin"
    EMAIL = "admin1@gmail.com"
    PASSWORD = "Testtest123+"     # 12 caractères minimum
    # ------------------------------

    # Vérifier si l'admin existe déjà
    existing = User.query.filter(
        (User.username == USERNAME) | (User.email == EMAIL)
    ).first()

    if existing:
        print(f"⚠️  Un utilisateur existe déjà : {existing.username} / {existing.email}")
    else:
        # Générer les clés RSA
        private_key, public_key = generate_keypair()

        admin = User(
            username=USERNAME,
            email=EMAIL,
            password_hash=hash_password(PASSWORD),
            role="ADMIN",
            status="ACTIVE",
            must_change_password=False,
            private_key_encrypted=private_key,
            public_key_pem=public_key,
        )

        db.session.add(admin)
        db.session.commit()

        print(f"✅ Admin créé : id={admin.id}, username={admin.username}")