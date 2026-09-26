from app import db
from app.models import User
from app.auth.services import hash_password


def approve_user(user: User) -> User:
    if user.status != "PENDING":
        raise ValueError("Seuls les comptes PENDING peuvent être approuvés.")

    user.status = "ACTIVE"
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
    )

    db.session.add(manager)
    db.session.commit()

    return manager