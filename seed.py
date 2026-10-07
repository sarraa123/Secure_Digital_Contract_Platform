"""
Initialise la base avec un Manager et quelques Clients de test.
Chaque utilisateur reçoit une paire de clés RSA-3072 pour signer.
Idempotent : relancer le script ne crée pas de doublons.
"""
from app import create_app
from app.extensions import db
from app.models import User
from app.services.crypto_service import generate_keypair
from app.auth.services import hash_password

app = create_app()

DEFAULT_PASSWORD = "Testtest123+"


MANAGERS = [
    ("David Mensah", "manager@secure.local"),
    ("Sofia Ricci",     "sofia@partner.com"),
]

CLIENTS = [
    ("Alice Bernard",   "alice@partner.com"),
    ("Marc Lefevre",    "marc@partner.com"),
    ("Nadia Ben Salah", "nadia@legal.tn"),
]


def upsert(username: str, email: str, role: str) -> None:
    existing = User.query.filter_by(email=email).first()
    if existing:
        if not existing.has_signing_keys:
            priv, pub = generate_keypair()
            existing.private_key_encrypted = priv
            existing.public_key_pem = pub
            print(f"🔑 {email:30s} clés RSA-3072 générées")
        else:
            print(f"⏭  {email:30s} existe déjà avec clés")
        return

    priv, pub = generate_keypair()
    db.session.add(User(
        username=username,
        email=email,
        role=role,
        status="ACTIVE",
        password_hash=hash_password(DEFAULT_PASSWORD),
        private_key_encrypted=priv,
        public_key_pem=pub,
    ))
    print(f"✅ {email:30s} créé ({role}) + clés RSA-3072 "
          f"(mot de passe: {DEFAULT_PASSWORD})")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        print("=== MANAGERS ===")
        for name, mail in MANAGERS:
            upsert(name, mail, "MANAGER")

        print("\n=== CLIENTS ===")
        for name, mail in CLIENTS:
            upsert(name, mail, "CLIENT")

        db.session.commit()

        print("\n=== État final ===")
        for u in User.query.order_by(User.role, User.username).all():
            key_status = "🔑" if u.has_signing_keys else "❌"
            print(f"  [{u.id:2d}] {key_status} {u.role:8s} {u.email:30s} {u.username}")