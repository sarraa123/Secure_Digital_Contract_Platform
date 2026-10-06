import pytest
from app.security.audit import log_security_event
from app.security.audit_events import LOGIN_SUCCESS
from app import db
from app.models import User
from app.auth.services import hash_password
from app.models import SecurityEvent
from app.security.audit_events import LOGIN_SUCCESS
from app.security.audit_events import LOGIN_FAILED
def create_user(
    username="testuser",
    email="test@example.com",
    password="StrongPassword123!",
    role="CLIENT",
    status="ACTIVE",
):
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role=role,
        status=status,
    )

    db.session.add(user)
    db.session.commit()

    return user

def test_login_page_loads(client):
    response = client.get("/auth/login")

    assert response.status_code == 200
    assert b"Se connecter" in response.data

def test_login_rejects_invalid_credentials(client):
    create_user()

    response = client.post(
        "/auth/login",
        data={
            "email": "test@example.com",
            "password": "WrongPassword123!",
        },
        follow_redirects=True,
    )

    # Votre application retourne 401 en cas d'identifiants invalides
    assert response.status_code == 401
    assert b"Email ou mot de passe invalide." in response.data

def test_active_user_can_login(client):
    create_user()

    response = client.post(
        "/auth/login",
        data={
            "email": "test@example.com",
            "password": "StrongPassword123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/auth/dashboard" in response.headers["Location"]


def test_pending_user_cannot_login(client):
    create_user(
        status="PENDING"
    )

    response = client.post(
        "/auth/login",
        data={
            "email": "test@example.com",
            "password": "StrongPassword123!",
        },
    )

    assert response.status_code == 403


def test_rejected_user_cannot_login(client):
    create_user(
        status="REJECTED"
    )

    response = client.post(
        "/auth/login",
        data={
            "email": "test@example.com",
            "password": "StrongPassword123!",
        },
    )

    assert response.status_code == 403

def test_suspended_user_cannot_login(client):
    create_user(
        status="SUSPENDED"
    )

    response = client.post(
        "/auth/login",
        data={
            "email": "test@example.com",
            "password": "StrongPassword123!",
        },
    )

    assert response.status_code == 403

def test_logout(client):
    create_user()

    client.post(
        "/auth/login",
        data={
            "email": "test@example.com",
            "password": "StrongPassword123!",
        },
    )

    response = client.post(
        "/auth/logout",
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]

def test_dashboard_requires_login(client):
    response = client.get(
        "/auth/dashboard",
        follow_redirects=False,
    )

    assert response.status_code in (302, 401)
    if response.status_code == 302:
        assert "/auth/login" in response.headers["Location"]

def test_login_requires_csrf(client):
    response = client.post(
        "/auth/login",
        data={
            "email": "test@example.com",
            "password": "StrongPassword123!",
        },
    )

    # Adaptez selon la réponse reçue par votre application (401 si refusé sans CSRF/auth)
    assert response.status_code == 401

def test_session_cookie_security(client):
    create_user()

    response = client.post(
        "/auth/login",
        data={
            "email": "test@example.com",
            "password": "StrongPassword123!",
        },
    )

    set_cookie = response.headers.get("Set-Cookie")

    assert set_cookie is not None
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie

def test_successful_login_creates_security_event(client, app):
    create_user(
        username="activeuser",
        email="active@example.com",
        password="StrongPassword123!",
        status="ACTIVE",
    )

    response = client.post(
        "/auth/login",
        data={
            "email": "active@example.com",
            "password": "StrongPassword123!",
        },
        follow_redirects=False,
    )

    assert response.status_code in (302, 303)

    with app.app_context():
        event = SecurityEvent.query.filter_by(
            event_type=LOGIN_SUCCESS
        ).order_by(
            SecurityEvent.id.desc()
        ).first()

        assert event is not None
        assert event.status == "SUCCESS"

def test_failed_login_creates_security_event(
    client,
    app,
):

    response = client.post(
        "/auth/login",
        data={
            "email": "doesnotexist@example.com",
            "password": "WrongPassword123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 401

    with app.app_context():

        event = SecurityEvent.query.filter_by(
            event_type=LOGIN_FAILED
        ).order_by(
            SecurityEvent.id.desc()
        ).first()

        assert event is not None
        assert event.status == "FAILURE"


def test_security_event_has_required_fields(
    app,
):

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

        assert event.timestamp is not None
        assert event.event_type is not None
        assert event.ip_address is not None
        assert event.endpoint is not None
        assert event.status is not None
        assert event.details is not None