import pytest

from sqlalchemy.exc import IntegrityError

from app import db
from app.models import User


def test_duplicate_username_rejected(app):
    with app.app_context():
        user1 = User(
            username="sameuser",
            email="one@example.com",
            password_hash="hash1",
            role="CLIENT",
            status="PENDING",
        )

        user2 = User(
            username="sameuser",
            email="two@example.com",
            password_hash="hash2",
            role="CLIENT",
            status="PENDING",
        )

        db.session.add(user1)
        db.session.commit()

        db.session.add(user2)

        with pytest.raises(IntegrityError):
            db.session.commit()

        db.session.rollback()

def test_duplicate_email_rejected(app):
    with app.app_context():
        user1 = User(
            username="userone",
            email="same@example.com",
            password_hash="hash1",
            role="CLIENT",
            status="PENDING",
        )

        user2 = User(
            username="usertwo",
            email="same@example.com",
            password_hash="hash2",
            role="CLIENT",
            status="PENDING",
        )

        db.session.add(user1)
        db.session.commit()

        db.session.add(user2)

        with pytest.raises(IntegrityError):
            db.session.commit()

        db.session.rollback()

def test_user_default_role_and_status(app):
    with app.app_context():
        user = User(
            username="defaultuser",
            email="default@example.com",
            password_hash="hash",
        )

        db.session.add(user)
        db.session.commit()

        saved_user = User.query.filter_by(
            username="defaultuser"
        ).first()

        assert saved_user.role == "CLIENT"
        assert saved_user.status == "PENDING"

def test_created_at_is_generated(app):
    with app.app_context():
        user = User(
            username="timeuser",
            email="time@example.com",
            password_hash="hash",
        )

        db.session.add(user)
        db.session.commit()

        saved_user = User.query.filter_by(
            username="timeuser"
        ).first()

        assert saved_user.created_at is not None
        