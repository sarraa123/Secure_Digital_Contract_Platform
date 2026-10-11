from app.models import SecurityEvent
from app.security.audit_events import USER_REGISTERED


def test_registration_creates_security_event(
    client,
    app,
):

    response = client.post(
        "/auth/register",
        data={
            "username": "logginguser",
            "email": "logginguser@example.com",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!",
        },
        follow_redirects=False,
    )

    assert response.status_code in (302, 303)

    with app.app_context():

        event = SecurityEvent.query.filter_by(
            event_type=USER_REGISTERED
        ).order_by(
            SecurityEvent.id.desc()
        ).first()

        assert event is not None
        assert event.status == "SUCCESS"
        assert event.ip_address is not None
        assert event.endpoint == "auth.register"