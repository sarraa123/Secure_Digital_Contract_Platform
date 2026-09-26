import pytest

from app import create_app, db
from app.models import User
from app.auth.services import hash_password


@pytest.fixture
def app():
    app = create_app()

    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
    })

    with app.app_context():
        db.create_all()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_user(app):

    password = "Admin@2026!Secure"

    with app.app_context():

        user = User(
            username="testadmin",
            email="admin@example.com",
            password_hash=hash_password(password),
            role="ADMIN",
            status="ACTIVE",
            must_change_password=False,
        )

        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)
        return user


@pytest.fixture(autouse=True)
def cleanup_db(app):
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()