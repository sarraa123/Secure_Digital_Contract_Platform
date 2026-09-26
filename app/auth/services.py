from argon2 import PasswordHasher

from app import db
from app.models import User


password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        password_hasher.verify(password_hash, password)
        return True
    except Exception:
        return False


def create_pending_user(
    username: str,
    email: str,
    password: str,
) -> User:

    password_hash = hash_password(password)

    user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        role="CLIENT",
        status="PENDING",
    )

    db.session.add(user)
    db.session.commit()

    return user

def authenticate_user(email: str, password: str) -> User | None:
    user = User.query.filter_by(email=email).first()

    if user is None:
        return None

    if not verify_password(user.password_hash, password):
        return None

    return user


def change_user_password(
    user: User,
    current_password: str,
    new_password: str,
) -> bool:

    if not verify_password(
        user.password_hash,
        current_password,
    ):
        return False

    user.password_hash = hash_password(new_password)
    user.must_change_password = False

    db.session.commit()

    return True