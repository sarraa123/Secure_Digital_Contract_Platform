"""
Service de notifications :
  - in-app  : enregistre une Notification en base (consultable via la cloche)
  - email   : envoie un email via mail_service

Chaque notification métier crée les deux (ou seulement in-app si pas d'email).
"""
from flask import url_for, current_app, has_request_context

from app.extensions import db
from app.models import User, Notification
from app.services import mail_service
from app.services.certificate_service import (
    build_certificate_pdf, build_certificate_crypto,
)
from app.security import log_event


# =========================================================================
#  In-app (cloche)
# =========================================================================
def create_notification(user_id: int, event_type: str,
                        title: str, message: str = None,
                        link: str = None,
                        contract_id: int = None,
                        actor_id: int = None) -> Notification:
    """
    Crée une notification in-app pour un utilisateur.
    Évite les doublons pour le même (user, event_type, contract_id).
    """
    if not user_id:
        return None

    # Anti-doublon : si la même notif existe déjà (non lue, même contrat),
    # on ne la recrée pas
    if contract_id is not None:
        existing = Notification.query.filter_by(
            user_id=user_id,
            event_type=event_type,
            contract_id=contract_id,
            read_at=None,
        ).first()
        if existing:
            return existing

    notif = Notification(
        user_id=user_id,
        event_type=event_type,
        title=title,
        message=message,
        link=link,
        contract_id=contract_id,
        actor_id=actor_id,
    )
    db.session.add(notif)
    db.session.commit()

    log_event("NOTIFICATION_CREATED", user_id=user_id, status="OK",
              details=f"type={event_type} contract_id={contract_id}")

    return notif


def unread_count(user_id: int) -> int:
    return Notification.query.filter_by(
        user_id=user_id, read_at=None).count()


def list_for_user(user_id: int, limit: int = 20) -> list:
    return (Notification.query
            .filter_by(user_id=user_id)
            .order_by(Notification.created_at.desc())
            .limit(limit)
            .all())


def mark_as_read(notification_id: int, user_id: int) -> bool:
    notif = Notification.query.filter_by(
        id=notification_id, user_id=user_id).first()
    if not notif:
        return False
    if notif.read_at is None:
        from datetime import datetime
        notif.read_at = datetime.utcnow()
        db.session.commit()
    return True


def mark_all_as_read(user_id: int) -> int:
    from datetime import datetime
    count = (Notification.query
             .filter_by(user_id=user_id, read_at=None)
             .update({"read_at": datetime.utcnow()}))
    db.session.commit()
    return count


# =========================================================================
#  Helpers pour les URLs
# =========================================================================
def _detail_url(contract_id: int, role: str) -> str:
    """URL de la page de détail selon le rôle."""
    if not has_request_context():
        return f"/contracts/{contract_id}"
    if role == "MANAGER":
        return url_for("employee.contract_detail", contract_id=contract_id)
    if role == "ADMIN":
        return url_for("admin.contract_detail", contract_id=contract_id)
    return url_for("client.contract_detail", contract_id=contract_id)


def _verify_url(contract_id: int) -> str:
    if not has_request_context():
        return f"/verify/{contract_id}"
    try:
        return url_for("public.verify_contract", contract_id=contract_id,
                       _external=True)
    except Exception:
        return f"https://127.0.0.1:5000/verify/{contract_id}"


# =========================================================================
#  Email
# =========================================================================
def _send_template(to_email: str, subject: str,
                   template_base: str, context: dict,
                   attachments: list = None,
                   cc: list = None) -> bool:
    html_body = None
    try:
        html_body = current_app.jinja_env.get_template(
            f"{template_base}.html").render(**context)
    except Exception:
        current_app.logger.exception(
            "Template HTML introuvable : %s", template_base)

    text_body = context.get("text_body") or subject

    return mail_service.send_email(
        to=to_email, subject=subject,
        body=text_body, html_body=html_body,
        attachments=attachments, cc=cc,
    )
    
# =========================================================================
#  Notifications métier
# =========================================================================
def notify_contract_created(contract_view, actor: User) -> None:
    """
    Contrat créé → notification in-app UNIQUEMENT (pas d'email).
    L'email viendra plus tard, au moment du partage.
    """
    if not contract_view.client_id:
        return

    client = db.session.get(User, contract_view.client_id)
    if not client or client.id == actor.id:
        return

    link = _detail_url(contract_view.id, client.role)

    # In-app pour le client
    create_notification(
        user_id=client.id,
        event_type="contract.created",
        title=f"Nouveau contrat : {contract_view.title}",
        message=f"Créé par {actor.username}",
        link=link,
        contract_id=contract_view.id,
        actor_id=actor.id,
    )

    log_event("NOTIFICATION_CONTRACT_CREATED", user_id=actor.id, status="OK",
              details=f"contract_id={contract_view.id} in_app_only=True")
def notify_contract_shared(contract_view, actor: User,
                           recipient: User, permissions: list) -> None:
    """Contrat partagé → notification au destinataire."""
    link = _detail_url(contract_view.id, recipient.role)

    create_notification(
        user_id=recipient.id,
        event_type="contract.shared",
        title=f"Contrat partagé : {contract_view.title}",
        message=f"Par {actor.username} · Permissions : {', '.join(permissions)}",
        link=link,
        contract_id=contract_view.id,
        actor_id=actor.id,
    )

    ctx = {
        "recipient_name": recipient.username,
        "contract":       contract_view,
        "actor":          actor,
        "permissions":    permissions,
        "verify_url":     _verify_url(contract_view.id),
        "text_body": (
            f"Bonjour {recipient.username},\n\n"
            f"{actor.username} vous a partagé le contrat "
            f"« {contract_view.title} ».\n\n"
            f"Permissions : {', '.join(permissions)}\n"
        ),
    }
    _send_template(
        to_email=recipient.email,
        subject=f"Contrat partagé : {contract_view.title}",
        template_base="emails/contract_shared",
        context=ctx,
    )

    log_event("NOTIFICATION_CONTRACT_SHARED", user_id=actor.id, status="OK",
              details=f"contract_id={contract_view.id} to={recipient.email}")


def notify_contract_validated(contract_view, actor: User) -> None:
    """
    Contrat validé → notification in-app UNIQUEMENT (pas d'email).
    """
    owner = db.session.get(User, contract_view.owner_id)
    if not owner or owner.id == actor.id:
        return

    link = _detail_url(contract_view.id, owner.role)

    create_notification(
        user_id=owner.id,
        event_type="contract.validated",
        title=f"Contrat validé : {contract_view.title}",
        message=f"Validé par {actor.username} ({actor.email})",
        link=link,
        contract_id=contract_view.id,
        actor_id=actor.id,
    )

    log_event("NOTIFICATION_CONTRACT_VALIDATED", user_id=actor.id, status="OK",
              details=f"contract_id={contract_view.id} in_app_only=True")

def notify_contract_signed(contract_view, actor: User, signature_model) -> None:
    """
    Contrat signé → 1 SEUL email envoyé :
      - To : propriétaire du contrat
      - Cc : signataire
      - Pièce jointe : certificat PDF + certificat crypto (.txt)
    """
    owner = db.session.get(User, contract_view.owner_id)
    verify_url = _verify_url(contract_view.id)

    # --- Notifications in-app (cloche) pour les deux
    if owner and owner.id != actor.id:
        create_notification(
            user_id=owner.id,
            event_type="contract.signed",
            title=f"Contrat signé : {contract_view.title}",
            message=f"Signé par {actor.username} ({actor.email})",
            link=_detail_url(contract_view.id, owner.role),
            contract_id=contract_view.id,
            actor_id=actor.id,
        )

    create_notification(
        user_id=actor.id,
        event_type="contract.signed_by_you",
        title=f"Vous avez signé : {contract_view.title}",
        message="Le certificat est disponible dans le contrat",
        link=_detail_url(contract_view.id, actor.role),
        contract_id=contract_view.id,
        actor_id=actor.id,
    )

    # --- Déterminer To et Cc
    if not owner:
        to_email = actor.email
        cc_list = None
        recipient_name = actor.username
    elif owner.id == actor.id:
        to_email = owner.email
        cc_list = None
        recipient_name = owner.username
    else:
        to_email = owner.email
        cc_list = [actor.email]
        recipient_name = owner.username

    # --- Pièces jointes
    attachments = []
    try:
        pdf_bytes = build_certificate_pdf(
            contract_view=contract_view,
            signature=signature_model,
            signer=actor,
            signer_ip=None,
            verify_url=verify_url,
        )
        txt_content = build_certificate_crypto(
            contract_view=contract_view,
            signature=signature_model,
            signer=actor,
            signer_ip=None,
        ).encode("utf-8")

        attachments = [
            (f"certificat_{contract_view.id}.pdf", "application/pdf", pdf_bytes),
            (f"certificat_crypto_{contract_view.id}.txt",
             "text/plain", txt_content),
        ]
    except Exception:
        current_app.logger.exception(
            "Échec de la génération des certificats pour le contrat %s",
            contract_view.id)

    # --- 1 seul email
    ctx = {
        "recipient_name": recipient_name,
        "contract":       contract_view,
        "actor":          actor,
        "verify_url":     verify_url,
        "cc_signer":      actor if (owner and owner.id != actor.id) else None,
        "text_body": (
            f"Bonjour {recipient_name},\n\n"
            f"Le contrat « {contract_view.title} » vient d'être signé "
            f"électroniquement par {actor.username} ({actor.email}).\n\n"
            f"Hash SHA-256 : {signature_model.document_hash}\n"
            f"Algorithme   : {signature_model.algorithm}\n\n"
            f"Certificat en pièce jointe.\n"
            f"Vérification en ligne : {verify_url}\n\n"
            f"— L'équipe Veridoc"
        ),
    }

    _send_template(
        to_email=to_email,
        subject=f"Contrat signé : {contract_view.title}",
        template_base="emails/contract_signed",
        context=ctx,
        attachments=attachments,
        cc=cc_list,
    )

    log_event("NOTIFICATION_CONTRACT_SIGNED", user_id=actor.id, status="OK",
              details=(f"contract_id={contract_view.id} "
                       f"to={to_email} cc={cc_list} "
                       f"attachments={len(attachments)}"))            