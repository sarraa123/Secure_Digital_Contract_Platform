from app import db
from app.models import User
from app.services.crypto_service import generate_keypair


def approve_user(user: User) -> User:
    if user.status != "PENDING":
        raise ValueError(
            "Seuls les comptes PENDING peuvent être approuvés."
        )

    user.status = "ACTIVE"

    if not user.has_signing_keys:
        private_key, public_key = generate_keypair()
        user.private_key_encrypted = private_key
        user.public_key_pem = public_key

    db.session.commit()

    return user


def reject_user(user: User) -> User:
    if user.status != "PENDING":
        raise ValueError(
            "Seuls les comptes PENDING peuvent être rejetés."
        )

    user.status = "REJECTED"

    db.session.commit()

    return user