from app.extensions import db
from app.auth.services import hash_password
from app.models import User
from app.services.crypto_service import generate_keypair
from app.services.mail_service import (
    send_manager_account_email,
    send_account_approved_email,
    send_account_rejected_email,
)


# ==========================================================
# APPROVE CLIENT
# ==========================================================

def approve_user(user: User) -> User:
    """
    Approve a PENDING client account.

    Workflow:
        PENDING
            ↓
        ACTIVE
            ↓
        Generate RSA keys if necessary
            ↓
        Commit database
            ↓
        Send approval email
    """

    # ------------------------------------------------------
    # Security / business rule
    # ------------------------------------------------------

    if user.status != "PENDING":
        raise ValueError(
            "Seuls les comptes PENDING peuvent être approuvés."
        )

    # ------------------------------------------------------
    # Change account status
    # ------------------------------------------------------

    user.status = "ACTIVE"

    # ------------------------------------------------------
    # Génération des clés RSA si absentes
    # ------------------------------------------------------

    if not user.has_signing_keys:

        private_key, public_key = generate_keypair()

        user.private_key_encrypted = private_key
        user.public_key_pem = public_key

    # ------------------------------------------------------
    # Commit BEFORE sending email
    # ------------------------------------------------------
    #
    # Important:
    # The account must remain ACTIVE even if SMTP fails.
    #
    # The email is only a notification.
    # It must not control the database transaction.
    # ------------------------------------------------------

    db.session.commit()

    # ------------------------------------------------------
    # Send approval email
    # ------------------------------------------------------
    #
    # send_email() catches SMTP exceptions and returns False
    # if the email cannot be sent.
    #
    # Therefore, email failure does NOT undo the approval.
    # ------------------------------------------------------

    email_sent = send_account_approved_email(user)

    # ------------------------------------------------------
    # Store temporary result for the route.
    #
    # This is NOT stored in the database.
    # It is only used to display the correct admin popup.
    # ------------------------------------------------------

    user._email_sent = email_sent

    return user


# ==========================================================
# REJECT CLIENT
# ==========================================================

def reject_user(user: User) -> User:
    """
    Reject a PENDING client account.

    Workflow:
        PENDING
            ↓
        REJECTED
            ↓
        Commit database
            ↓
        Send rejection email
    """

    # ------------------------------------------------------
    # Security / business rule
    # ------------------------------------------------------

    if user.status != "PENDING":
        raise ValueError(
            "Seuls les comptes PENDING peuvent être rejetés."
        )

    # ------------------------------------------------------
    # Change account status
    # ------------------------------------------------------

    user.status = "REJECTED"

    # ------------------------------------------------------
    # Commit BEFORE sending email
    # ------------------------------------------------------

    db.session.commit()

    # ------------------------------------------------------
    # Send rejection email
    # ------------------------------------------------------

    email_sent = send_account_rejected_email(user)

    # ------------------------------------------------------
    # Store temporary result for the route.
    #
    # This is NOT stored in the database.
    # ------------------------------------------------------

    user._email_sent = email_sent

    return user


# ==========================================================
# CREATE MANAGER
# ==========================================================

def create_manager(
    username: str,
    email: str,
    temporary_password: str,
) -> User:

    username = username.strip()
    email = email.strip().lower()

    # ------------------------------------------------------
    # Check duplicate username
    # ------------------------------------------------------

    if User.query.filter_by(username=username).first():

        raise ValueError(
            "Ce nom d'utilisateur existe déjà."
        )

    # ------------------------------------------------------
    # Check duplicate email
    # ------------------------------------------------------

    if User.query.filter_by(email=email).first():

        raise ValueError(
            "Cette adresse email existe déjà."
        )

    # ------------------------------------------------------
    # Create manager
    # ------------------------------------------------------

    manager = User(
        username=username,
        email=email,
        password_hash=hash_password(temporary_password),
        role="MANAGER",
        status="ACTIVE",
        must_change_password=True,
        mfa_enabled=True,
    )

    # ------------------------------------------------------
    # Génération des clés RSA dès la création
    # ------------------------------------------------------

    private_key, public_key = generate_keypair()

    manager.private_key_encrypted = private_key
    manager.public_key_pem = public_key

    # ------------------------------------------------------
    # Save manager
    # ------------------------------------------------------

    db.session.add(manager)

    db.session.commit()

    # ------------------------------------------------------
    # Existing manager email functionality
    # ------------------------------------------------------

    email_sent = send_manager_account_email(
        manager,
        temporary_password,
    )

    # ------------------------------------------------------
    # Store temporary result for the route.
    #
    # This is NOT stored in the database.
    # ------------------------------------------------------

    manager._email_sent = email_sent

    return manager