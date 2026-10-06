from app.extensions import db
from app.auth.services import hash_password
from app.models import User
from app.services.crypto_service import generate_keypair
from app.services.mail_service import send_manager_account_email


def approve_user(user: User) -> User:
    if user.status != "PENDING":
        raise ValueError("Seuls les comptes PENDING peuvent être approuvés.")

    user.status = "ACTIVE"

    # Génération des clés RSA si absentes
    if not user.has_signing_keys:
        private_key, public_key = generate_keypair()
        user.private_key_encrypted = private_key
        user.public_key_pem = public_key

    db.session.commit()
    return user


def reject_user(user: User) -> User:
    if user.status != "PENDING":
        raise ValueError("Seuls les comptes PENDING peuvent être rejetés.")

    user.status = "REJECTED"
    db.session.commit()
    return user


def create_manager(
    username: str,
    email: str,
    temporary_password: str,
) -> User:

    username = username.strip()
    email = email.strip().lower()

    if User.query.filter_by(username=username).first():
        raise ValueError("Ce nom d'utilisateur existe déjà.")

    if User.query.filter_by(email=email).first():
        raise ValueError("Cette adresse email existe déjà.")

    manager = User(
        username=username,
        email=email,
        password_hash=hash_password(temporary_password),
        role="MANAGER",
        status="ACTIVE",
        must_change_password=True,
        mfa_enabled=True,
    )

    # ⭐ Génération des clés RSA dès la création
    private_key, public_key = generate_keypair()
    manager.private_key_encrypted = private_key
    manager.public_key_pem = public_key

    db.session.add(manager)
    db.session.commit()

    send_manager_account_email(manager, temporary_password)

    return manager