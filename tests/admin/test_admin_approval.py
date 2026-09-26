import pytest
from app import db
from app.models import User
from app.auth.services import hash_password


def create_user(
    username,
    email,
    password="StrongPassword123!",
    role="CLIENT",
    status="PENDING",
):
    return User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role=role,
        status=status,
    )


def login_as(client, email, password="StrongPassword123!"):
    """Authentifie l'utilisateur via la route de login officielle."""
    return client.post(
        "/auth/login",
        data={
            "email": email,
            "password": password,
        },
        follow_redirects=True,
    )


def test_admin_can_approve_pending_user(client, app):
    admin = create_user(
        "admin",
        "admin@example.com",
        role="ADMIN",
        status="ACTIVE",
    )

    pending_user = create_user(
        "pending",
        "pending@example.com",
        role="CLIENT",
        status="PENDING",
    )

    with app.app_context():
        db.session.add(admin)
        db.session.add(pending_user)
        db.session.commit()
        pending_id = pending_user.id

    login_as(client, "admin@example.com")

    response = client.post(
        f"/admin/users/{pending_id}/approve",
        follow_redirects=False,
    )

    assert response.status_code == 302

    with app.app_context():
        user = db.session.get(User, pending_id)
        assert user.status == "ACTIVE"


def test_client_cannot_approve_user(client, app):
    client_user = create_user(
        "client",
        "client@example.com",
        role="CLIENT",
        status="ACTIVE",
    )

    pending_user = create_user(
        "pending2",
        "pending2@example.com",
        role="CLIENT",
        status="PENDING",
    )

    with app.app_context():
        db.session.add(client_user)
        db.session.add(pending_user)
        db.session.commit()
        pending_id = pending_user.id

    login_as(client, "client@example.com")

    response = client.post(f"/admin/users/{pending_id}/approve")

    assert response.status_code == 403

    with app.app_context():
        user = db.session.get(User, pending_id)
        assert user.status == "PENDING"


def test_manager_cannot_approve_user(client, app):
    manager = create_user(
        "manager",
        "manager@example.com",
        role="MANAGER",
        status="ACTIVE",
    )

    pending_user = create_user(
        "pending3",
        "pending3@example.com",
        role="CLIENT",
        status="PENDING",
    )

    with app.app_context():
        db.session.add(manager)
        db.session.add(pending_user)
        db.session.commit()
        pending_id = pending_user.id

    login_as(client, "manager@example.com")

    response = client.post(f"/admin/users/{pending_id}/approve")

    assert response.status_code == 403

    with app.app_context():
        user = db.session.get(User, pending_id)
        assert user.status == "PENDING"


def test_admin_can_reject_pending_user(client, app):
    admin = create_user(
        "admin2",
        "admin2@example.com",
        role="ADMIN",
        status="ACTIVE",
    )

    pending_user = create_user(
        "pending4",
        "pending4@example.com",
        role="CLIENT",
        status="PENDING",
    )

    with app.app_context():
        db.session.add(admin)
        db.session.add(pending_user)
        db.session.commit()
        pending_id = pending_user.id

    login_as(client, "admin2@example.com")

    response = client.post(f"/admin/users/{pending_id}/reject")

    assert response.status_code == 302

    with app.app_context():
        user = db.session.get(User, pending_id)
        assert user.status == "REJECTED"


def test_active_user_cannot_be_approved_again(client, app):
    admin = create_user(
        "admin3",
        "admin3@example.com",
        role="ADMIN",
        status="ACTIVE",
    )

    active_user = create_user(
        "alreadyactive",
        "alreadyactive@example.com",
        role="CLIENT",
        status="ACTIVE",
    )

    with app.app_context():
        db.session.add(admin)
        db.session.add(active_user)
        db.session.commit()
        user_id = active_user.id

    login_as(client, "admin3@example.com")

    response = client.post(f"/admin/users/{user_id}/approve")

    assert response.status_code == 400

    with app.app_context():
        user = db.session.get(User, user_id)
        assert user.status == "ACTIVE"


def test_approve_nonexistent_user(client, app):
    admin = create_user(
        "admin4",
        "admin4@example.com",
        role="ADMIN",
        status="ACTIVE",
    )

    with app.app_context():
        db.session.add(admin)
        db.session.commit()

    login_as(client, "admin4@example.com")

    response = client.post("/admin/users/999999/approve")

    assert response.status_code == 404


def test_admin_can_view_pending_users(client, app):
    admin = create_user(
        "admin5",
        "admin5@example.com",
        role="ADMIN",
        status="ACTIVE",
    )

    pending_user = create_user(
        "pending5",
        "pending5@example.com",
        role="CLIENT",
        status="PENDING",
    )

    with app.app_context():
        db.session.add(admin)
        db.session.add(pending_user)
        db.session.commit()

    login_as(client, "admin5@example.com")

    response = client.get("/admin/users")

    assert response.status_code == 200
    assert b"pending5" in response.data