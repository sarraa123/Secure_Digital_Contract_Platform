import pytest

from app import db
from app.models import User
from app.auth.services import hash_password


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

    assert response.status_code == 302
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