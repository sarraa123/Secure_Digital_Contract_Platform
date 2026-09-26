# app/services/mail_service.py
import smtplib
from email.message import EmailMessage

from flask import current_app, url_for


def send_email(to: str, subject: str, body: str) -> bool:
    if current_app.config.get("MAIL_SUPPRESS_SEND"):
        current_app.logger.info(
            "[EMAIL SUPPRIMÉ] À: %s | Sujet: %s\n%s", to, subject, body
        )
        return True

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = current_app.config["MAIL_DEFAULT_SENDER"]
    message["To"] = to
    message.set_content(body)

    try:
        with smtplib.SMTP(
            current_app.config["MAIL_SERVER"],
            current_app.config["MAIL_PORT"],
            timeout=10,
        ) as server:
            server.ehlo()          # ← ajouté
            server.starttls()
            server.ehlo()          # ← ajouté
            server.login(
                current_app.config["MAIL_USERNAME"],
                current_app.config["MAIL_PASSWORD"],
            )
            server.send_message(message)
        return True
    except Exception:
        current_app.logger.exception(
            "Échec de l'envoi d'email à %s", to
        )
        return False


def send_manager_account_email(user, temporary_password: str) -> bool:
    login_url = url_for("auth.login", _external=True)

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

    return send_email(to=user.email, subject=subject, body=body)