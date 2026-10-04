"""
Service d'envoi d'emails Veridoc.

Deux modes :
  - MAIL_SUPPRESS_SEND=True  → log dans la console, pas d'envoi réel
  - MAIL_SUPPRESS_SEND=False → envoi SMTP réel (Gmail)
"""
import smtplib
from email.message import EmailMessage

from flask import current_app, url_for, render_template


def send_email(to: str, subject: str, body: str,
               html_body: str = None,
               attachments: list = None,
               cc: list = None) -> bool:
    """
    Envoie un email.

    attachments : liste de tuples (filename, mimetype, bytes)
    cc          : liste d'adresses à mettre en copie (optionnel)
    """
    if current_app.config.get("MAIL_SUPPRESS_SEND"):
        cc_str = f" | Cc: {', '.join(cc)}" if cc else ""
        current_app.logger.info(
            "[EMAIL SUPPRIMÉ] À: %s%s | Sujet: %s\n%s",
            to, cc_str, subject, body
        )
        return True

    message = EmailMessage()
    message["Subject"] = subject
    message["From"]    = current_app.config["MAIL_DEFAULT_SENDER"]
    message["To"]      = to

    if cc:
        cc_clean = [e for e in cc if e and "@" in e]
        if cc_clean:
            message["Cc"] = ", ".join(cc_clean)

    message.set_content(body)

    if html_body:
        message.add_alternative(html_body, subtype="html")

    if attachments:
        for filename, mimetype, data in attachments:
            maintype, subtype = mimetype.split("/", 1)
            message.add_attachment(
                data, maintype=maintype, subtype=subtype, filename=filename
            )

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
        current_app.logger.exception("Échec de l'envoi d'email à %s", to)
        return False
    
def send_manager_account_email(user, temporary_password: str) -> bool:
    """Email de création de compte gestionnaire (existant)."""
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