import json

from app.models import SecurityEvent
from app.security.audit import log_security_event
from app.security.audit_events import (
    LOGIN_SUCCESS,
    LOGIN_FAILED,
    LOGOUT,
    USER_REGISTERED,
)


def test_security_event_is_created(app):

    with app.app_context():

        event = log_security_event(
            LOGIN_SUCCESS,
            user_id=None,
            status="SUCCESS",
            details={
                "method": "password",
            },
            ip_address="127.0.0.1",
            endpoint="auth.login",
        )

        saved_event = db_event = SecurityEvent.query.get(
            event.id
        )

        assert saved_event is not None
        assert saved_event.event_type == LOGIN_SUCCESS
        assert saved_event.status == "SUCCESS"
        assert saved_event.ip_address == "127.0.0.1"
        assert saved_event.endpoint == "auth.login"


def test_security_event_contains_timestamp(app):

    with app.app_context():

        event = log_security_event(
            USER_REGISTERED,
            status="SUCCESS",
            details={
                "role": "CLIENT",
                "status": "PENDING",
            },
        )

        assert event.timestamp is not None


def test_security_event_details_are_json(app):

    with app.app_context():

        event = log_security_event(
            LOGIN_FAILED,
            status="FAILURE",
            details={
                "reason": "invalid_credentials",
            },
        )

        parsed = json.loads(event.details)

        assert parsed["reason"] == "invalid_credentials"


def test_password_is_not_logged(app):

    with app.app_context():

        event = log_security_event(
            LOGIN_FAILED,
            status="FAILURE",
            details={
                "reason": "invalid_credentials",
            },
        )

        assert "password" not in event.details.lower()
        assert "password_hash" not in event.details.lower()


def test_mfa_secret_is_not_logged(app):

    with app.app_context():

        event = log_security_event(
            LOGIN_SUCCESS,
            status="SUCCESS",
            details={
                "method": "password+TOTP",
                "mfa": True,
            },
        )

        assert "mfa_secret" not in event.details.lower()
        assert "totp_secret" not in event.details.lower()


def test_logout_event(app):

    with app.app_context():

        event = log_security_event(
            LOGOUT,
            user_id=10,
            status="SUCCESS",
            details={
                "reason": "user_logout",
            },
        )

        assert event.event_type == LOGOUT
        assert event.user_id == 10
        assert event.status == "SUCCESS"