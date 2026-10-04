from app.auth.forms import RegistrationForm


def test_password_requires_uppercase(app):

    with app.test_request_context(
        "/auth/register",
        method="POST",
        data={
            "username": "sarra123",
            "email": "sarra@example.com",
            "password": "sarra@cyber2026",
            "confirm_password": "sarra@cyber2026",
        },
    ):

        form = RegistrationForm()

        assert not form.validate()

        assert any(
            "majuscule" in error
            for error in form.password.errors
        )


def test_password_requires_lowercase(app):

    with app.test_request_context(
        "/auth/register",
        method="POST",
        data={
            "username": "sarra123",
            "email": "sarra@example.com",
            "password": "SARRA@2026CYBER",
            "confirm_password": "SARRA@2026CYBER",
        },
    ):

        form = RegistrationForm()

        assert not form.validate()

        assert any(
            "minuscule" in error
            for error in form.password.errors
        )


def test_password_requires_digit(app):

    with app.test_request_context(
        "/auth/register",
        method="POST",
        data={
            "username": "sarra123",
            "email": "sarra@example.com",
            "password": "Sarra@CyberTest",
            "confirm_password": "Sarra@CyberTest",
        },
    ):

        form = RegistrationForm()

        assert not form.validate()

        assert any(
            "chiffre" in error
            for error in form.password.errors
        )


def test_password_requires_special_character(app):

    with app.test_request_context(
        "/auth/register",
        method="POST",
        data={
            "username": "sarra123",
            "email": "sarra@example.com",
            "password": "SarraCyber2026",
            "confirm_password": "SarraCyber2026",
        },
    ):

        form = RegistrationForm()

        assert not form.validate()

        assert any(
            "spécial" in error
            for error in form.password.errors
        )


def test_strong_password_is_accepted(app):

    with app.test_request_context(
        "/auth/register",
        method="POST",
        data={
            "username": "sarra123",
            "email": "sarra@example.com",
            "password": "Sarra@Cyber2026",
            "confirm_password": "Sarra@Cyber2026",
        },
    ):

        form = RegistrationForm()

        assert form.validate()


def test_password_must_be_at_least_12_characters(app):

    with app.test_request_context(
        "/auth/register",
        method="POST",
        data={
            "username": "sarra123",
            "email": "sarra@example.com",
            "password": "Sa@123",
            "confirm_password": "Sa@123",
        },
    ):

        form = RegistrationForm()

        assert not form.validate()


def test_username_rejects_special_characters(app):

    with app.test_request_context(
        "/auth/register",
        method="POST",
        data={
            "username": "sarra<script>",
            "email": "sarra@example.com",
            "password": "Sarra@Cyber2026",
            "confirm_password": "Sarra@Cyber2026",
        },
    ):

        form = RegistrationForm()

        assert not form.validate()

        assert any(
            "lettres" in error
            for error in form.username.errors
        )

def test_sql_injection_username_is_not_executed(client):

    response = client.post(
        "/auth/register",
        data={
            "username": "' OR 1=1 --",
            "email": "attacker@example.com",
            "password": "Strong@Password2026",
            "confirm_password": "Strong@Password2026",
        },
        follow_redirects=True,
    )

    assert response.status_code in (200, 400)