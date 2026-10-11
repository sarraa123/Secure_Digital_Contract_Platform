from app import db
from app.models import User
from app.auth.services import hash_password


def test_admin_can_create_manager(
    client,
    app,
    admin_user,
):

    response = client.post(
        "/auth/login",
        data={
            "email": admin_user.email,
            "password": "Admin@2026!Secure",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/auth/dashboard" in response.headers["Location"]

    response = client.post(
        "/admin/managers/create",
        data={
            "username": "manager01",
            "email": "manager01@example.com",
            "temporary_password": "Manager@2026!Temp",
            "confirm_password": "Manager@2026!Temp",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200

    with app.app_context():

        manager = User.query.filter_by(
            email="manager01@example.com"
        ).first()

        assert manager is not None
        assert manager.role == "MANAGER"
        assert manager.status == "ACTIVE"
        assert manager.must_change_password is True
        assert manager.password_hash != "Manager@2026!Temp"


def test_client_cannot_create_manager(
    client,
    app,
):

    password = "Client@2026!Secure"

    with app.app_context():

        user = User(
            username="client01",
            email="client01@example.com",
            password_hash=hash_password(password),
            role="CLIENT",
            status="ACTIVE",
        )

        db.session.add(user)
        db.session.commit()

    response = client.post(
        "/auth/login",
        data={
            "email": "client01@example.com",
            "password": password,
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/auth/dashboard" in response.headers["Location"]

    response = client.get(
        "/admin/managers/create",
        follow_redirects=False,
    )

    assert response.status_code == 403


def test_manager_cannot_create_manager(
    client,
    app,
):

    password = "Manager@2026!Secure"

    with app.app_context():

        manager = User(
            username="existingmanager",
            email="existingmanager@example.com",
            password_hash=hash_password(password),
            role="MANAGER",
            status="ACTIVE",
            must_change_password=False,
        )

        db.session.add(manager)
        db.session.commit()

    response = client.post(
        "/auth/login",
        data={
            "email": "existingmanager@example.com",
            "password": password,
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/auth/dashboard" in response.headers["Location"]

    response = client.get(
        "/admin/managers/create",
        follow_redirects=False,
    )

    assert response.status_code == 403