import pytest
from app import create_app, db


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

@pytest.fixture(autouse=True)
def cleanup_db(app):
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()