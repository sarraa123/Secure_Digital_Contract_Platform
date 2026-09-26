from app import db
from app.models import User


def approve_user(user: User) -> User:
    if user.status != "PENDING":
        raise ValueError(
            "Seuls les comptes PENDING peuvent être approuvés."
        )

    user.status = "ACTIVE"

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