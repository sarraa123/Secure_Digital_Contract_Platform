"""
Service d'envoi d'emails Veridoc.

Deux modes :
  - MAIL_SUPPRESS_SEND=True  → log dans la console, pas d'envoi réel
  - MAIL_SUPPRESS_SEND=False → envoi SMTP réel (Gmail)
"""
from typing import TYPE_CHECKING
import smtplib
from email.message import EmailMessage

from flask import current_app, url_for, render_template
from app.models import User

def send_email(
    to: str,
    subject: str,
    body: str,
    html_body: str = None,
    attachments: list = None,
    cc: list = None
) -> bool:
    """
    Envoie un email.

    attachments : liste de tuples (filename, mimetype, bytes)
    cc          : liste d'adresses à mettre en copie (optionnel)
    """

    # ==========================================================
    # MODE SUPPRESSION
    # ==========================================================

    if current_app.config.get("MAIL_SUPPRESS_SEND"):
        cc_str = f" | Cc: {', '.join(cc)}" if cc else ""

        current_app.logger.info(
            "[EMAIL SUPPRIMÉ] À: %s%s | Sujet: %s\n%s",
            to,
            cc_str,
            subject,
            body
        )

        return True

    # ==========================================================
    # CREATION DU MESSAGE
    # ==========================================================

    message = EmailMessage()

    message["Subject"] = subject
    message["From"] = current_app.config["MAIL_DEFAULT_SENDER"]
    message["To"] = to

    # ==========================================================
    # CC
    # ==========================================================

    if cc:
        cc_clean = [
            email
            for email in cc
            if email and "@" in email
        ]

        if cc_clean:
            message["Cc"] = ", ".join(cc_clean)

    # ==========================================================
    # TEXT BODY
    # ==========================================================

    message.set_content(body)

    # ==========================================================
    # HTML BODY
    # ==========================================================

    if html_body:
        message.add_alternative(
            html_body,
            subtype="html"
        )

    # ==========================================================
    # ATTACHMENTS
    # ==========================================================

    if attachments:
        for filename, mimetype, data in attachments:

            maintype, subtype = mimetype.split("/", 1)

            message.add_attachment(
                data,
                maintype=maintype,
                subtype=subtype,
                filename=filename
            )

    # ==========================================================
    # SMTP SEND
    # ==========================================================

    try:

        with smtplib.SMTP(
            current_app.config["MAIL_SERVER"],
            current_app.config["MAIL_PORT"],
            timeout=10,
        ) as server:

            server.ehlo()

            server.starttls()

            server.ehlo()

            server.login(
                current_app.config["MAIL_USERNAME"],
                current_app.config["MAIL_PASSWORD"],
            )

            server.send_message(message)

        return True

    except Exception:

        current_app.logger.exception(
            "Échec de l'envoi d'email à %s",
            to
        )

        return False


# ==========================================================
# MANAGER ACCOUNT EMAIL
# ==========================================================

def send_manager_account_email(
    user,
    temporary_password: str
) -> bool:
    """
    Email de création de compte gestionnaire.

    Fonctionnalité existante conservée.
    """

    login_url = url_for(
        "auth.login",
        _external=True
    )

    subject = "Votre compte gestionnaire Veridoc a été créé"

    body = (
        f"Bonjour {user.username},\n\n"
        f"Un compte gestionnaire vient d'être créé pour vous sur Veridoc.\n\n"
        f"Email de connexion : {user.email}\n"
        f"Mot de passe temporaire : {temporary_password}\n\n"
        f"Connectez-vous ici : {login_url}\n\n"
        f"Pour des raisons de sécurité, vous devrez choisir un nouveau "
        f"mot de passe dès votre première connexion.\n\n"
        f"— L'équipe Veridoc"
    )

    return send_email(
        to=user.email,
        subject=subject,
        body=body
    )


# ==========================================================
# CLIENT ACCOUNT APPROVED
# ==========================================================

def send_account_approved_email(user: User) -> bool:
    """
    Envoie un email au client lorsque son compte est approuvé.

    Le compte est déjà ACTIVE lorsque cette fonction est appelée.

    Aucun mot de passe ou secret n'est envoyé.
    L'utilisateur reçoit uniquement un lien vers la page de connexion.
    """

    login_url = url_for(
        "auth.login",
        _external=True
    )

    subject = "Votre compte Veridoc a été approuvé"

    body = (
        f"Bonjour {user.username},\n\n"
        f"Bonne nouvelle !\n\n"
        f"Votre compte client Veridoc a été approuvé par un administrateur.\n\n"
        f"Vous pouvez maintenant vous connecter à votre compte avec vos "
        f"identifiants.\n\n"
        f"Page de connexion :\n"
        f"{login_url}\n\n"
        f"Pour des raisons de sécurité, ne partagez jamais votre mot de passe.\n\n"
        f"— L'équipe Veridoc"
    )

    html_body = render_template(
        "emails/account_approved.html",
        username=user.username,
        login_url=login_url,
    )

    return send_email(
        to=user.email,
        subject=subject,
        body=body,
        html_body=html_body,
    )


# ==========================================================
# CLIENT ACCOUNT REJECTED
# ==========================================================

def send_account_rejected_email(user: User) -> bool:
    """
    Envoie un email au client lorsque sa demande est rejetée.

    Aucun mot de passe ou secret n'est envoyé.
    """

    subject = "Mise à jour de votre demande de compte Veridoc"

    body = (
        f"Bonjour {user.username},\n\n"
        f"Nous vous informons que votre demande de création de compte "
        f"Veridoc n'a malheureusement pas été acceptée par notre équipe "
        f"administrative.\n\n"
        f"Votre compte est actuellement marqué comme REJETÉ.\n\n"
        f"Si vous pensez qu'il s'agit d'une erreur ou si vous souhaitez "
        f"obtenir davantage d'informations, veuillez contacter "
        f"l'administration de Veridoc.\n\n"
        f"— L'équipe Veridoc"
    )

    html_body = render_template(
        "emails/account_rejected.html",
        username=user.username,
    )

    return send_email(
        to=user.email,
        subject=subject,
        body=body,
        html_body=html_body,
    )