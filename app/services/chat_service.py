"""
Service de chat par contrat.

Fonctionnalités :
  - Envoi de messages chiffrés (AES-256-GCM, même clé que les contrats)
  - Lecture avec vérification RBAC
  - Marquage "lu" par utilisateur
  - Compteur de non-lus
  - Verrouillage automatique si contrat SIGNED
  - Messages système (ex: "Contrat signé le …")

Règles :
  - Le chat est ouvert tant que le contrat n'est pas SIGNED
  - Une fois SIGNED, lecture seule (plus d'envoi possible)
  - Seuls le propriétaire, le client associé, et les admins peuvent lire/écrire
"""
import json
from datetime import datetime

from app.extensions import db
from app.models import Contract, ContractMessage, ContractPermission, User
from app.crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt
from app.config import Config
from app.services import contract_service
from app.security import log_event
import hashlib as _hashlib

MAX_PDF_BYTES = 10 * 1024 * 1024  # 10 Mo
PDF_MAGIC = b"%PDF"


MAX_MESSAGE_LENGTH = 2000  # caractères max par message


# =========================================================================
#  Helpers internes
# =========================================================================
def _encrypt(text: str) -> bytes:
    return aes_gcm_encrypt(text.encode("utf-8"), Config.CONTRACT_ENCRYPTION_KEY)


def _decrypt(blob: bytes) -> str:
    return aes_gcm_decrypt(blob, Config.CONTRACT_ENCRYPTION_KEY).decode("utf-8")


def _is_locked(contract_id: int) -> bool:
    """
    Le chat est verrouillé si :
      - Une signature existe pour ce contrat (contrat SIGNED)
      - ET il n'y a PAS de demande d'avenant en cours

    Si une AmendmentRequest est ouverte (PENDING/NEGOTIATING),
    le chat est déverrouillé pour permettre la négociation.
    """
    from app.models import Signature, AmendmentRequest

    # Signature existe-t-elle ?
    has_signature = Signature.query.filter_by(contract_id=contract_id).first() is not None

    if not has_signature:
        return False  # Contrat non signé → jamais verrouillé

    # Contrat signé → vérifier s'il y a une demande d'avenant en cours
    pending = AmendmentRequest.query.filter_by(
        original_contract_id=contract_id,
    ).filter(
        AmendmentRequest.status.in_(["PENDING", "NEGOTIATING"])
    ).first()

    # Si demande en cours → chat déverrouillé
    if pending:
        return False

    # Sinon → verrouillé
    return True
def _user_can_access(contract_id: int, user: User) -> bool:
    """
    Vérifie que l'utilisateur peut accéder au chat de ce contrat.
    Autorisés : ADMIN, propriétaire, client associé, ou utilisateur avec permission.
    """
    if user.role == "ADMIN":
        return True

    contract = db.session.get(Contract, contract_id)
    if not contract:
        return False

    # Récupérer les métadonnées pour connaître owner_id et client_id
    try:
        from app.services.encryption_service import decrypt_contract_data
        from app.services.integrity_service import (
            verify_signature as verify_hmac
        )
        if not verify_hmac(contract.encrypted_metadata,
                           contract.encrypted_file,
                           contract.integrity_hash):
            return False
        metadata = decrypt_contract_data(contract.encrypted_metadata)
    except Exception:
        return False

    if metadata.get("owner_id") == user.id:
        return True
    if metadata.get("client_id") == user.id:
        return True

    # Permission explicite ?
    perm = ContractPermission.query.filter_by(
        contract_id=contract_id, user_id=user.id
    ).first()
    return perm is not None


def _load_or_create_read_set(msg: ContractMessage) -> set:
    """Retourne l'ensemble des user_id ayant lu ce message."""
    if not msg.read_by:
        return set()
    try:
        data = json.loads(msg.read_by)
        return set(data) if isinstance(data, list) else set()
    except Exception:
        return set()


def _save_read_set(msg: ContractMessage, read_set: set) -> None:
    msg.read_by = json.dumps(sorted(read_set))


# =========================================================================
#  API publique
# =========================================================================
def send_message(contract_id: int, sender: User, content: str,
                 message_type: str = "text") -> dict:
    """
    Envoie un message dans le chat d'un contrat.

    Retourne :
      {"ok": True, "message_id": X} en cas de succès
      {"ok": False, "error": "..."} sinon
    """
    # --- 1. Vérifier le contrat
    contract = db.session.get(Contract, contract_id)
    if not contract:
        return {"ok": False, "error": "Contrat introuvable."}

    # --- 2. RBAC
    if not _user_can_access(contract_id, sender):
        log_event("CHAT_UNAUTHORIZED_ACCESS", user_id=sender.id, status="403",
                  details=f"contract_id={contract_id} action=send")
        return {"ok": False, "error": "Accès non autorisé à ce contrat."}

    # --- 3. Chat verrouillé ?
    if _is_locked(contract_id):
        log_event("CHAT_LOCKED_ACCESS_ATTEMPT", user_id=sender.id, status="403",
                  details=f"contract_id={contract_id} action=send")
        return {"ok": False,
                "error": "Ce contrat est signé. Le chat est archivé en lecture seule."}

    # --- 4. Valider le contenu
    content = (content or "").strip()
    if not content:
        return {"ok": False, "error": "Message vide."}
    if len(content) > MAX_MESSAGE_LENGTH:
        return {"ok": False,
                "error": f"Message trop long (max {MAX_MESSAGE_LENGTH} caractères)."}

    # --- 5. Chiffrer + stocker
    try:
        encrypted = _encrypt(content)
    except Exception as e:
        log_event("CHAT_ENCRYPTION_FAILED", user_id=sender.id, status="500",
                  details=f"contract_id={contract_id} error={type(e).__name__}")
        return {"ok": False, "error": "Échec du chiffrement."}

    sender_role = sender.role  # "CLIENT", "MANAGER", "ADMIN"

    msg = ContractMessage(
        contract_id=contract_id,
        sender_id=sender.id,
        sender_role=sender_role,
        encrypted_content=encrypted,
        message_type=message_type,
        read_by=json.dumps([sender.id]),  # l'expéditeur l'a lu par définition
    )
    db.session.add(msg)
    db.session.commit()

    log_event("CHAT_MESSAGE_SENT", user_id=sender.id, status="OK",
              details=f"contract_id={contract_id} message_id={msg.id} "
                      f"role={sender_role}")

    # ✅ Notifier l'autre partie (anti-spam : 1 fois par heure)
    try:
        _notify_chat_recipient(contract_id, sender)
    except Exception:
        pass

    return {"ok": True, "message_id": msg.id,
            "created_at": msg.created_at.isoformat()}


def _notify_chat_recipient(contract_id: int, sender):
    """
    Notifie l'autre partie d'un nouveau message.
    Anti-spam : ne notifie pas si une notification a déjà été envoyée
    dans la dernière heure pour ce contrat.
    """
    from datetime import timedelta
    from app.services import notification_service
    from app.models import User as _User, Notification
    from app.services.encryption_service import decrypt_contract_data

    contract = db.session.get(Contract, contract_id)
    if not contract:
        return

    try:
        metadata = decrypt_contract_data(contract.encrypted_metadata)
    except Exception:
        return

    # Déterminer le destinataire (l'autre partie)
    recipient_id = None
    if metadata.get("owner_id") == sender.id:
        recipient_id = metadata.get("client_id")
    elif metadata.get("client_id") == sender.id:
        recipient_id = metadata.get("owner_id")

    if not recipient_id or recipient_id == sender.id:
        return

    recipient = db.session.get(_User, recipient_id)
    if not recipient:
        return

    # Anti-spam : vérifier si une notification a déjà été envoyée
    # dans la dernière heure pour ce contrat
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)

    recent = Notification.query.filter_by(
        user_id=recipient_id,
        event_type="chat.new_message",
        contract_id=contract_id,
    ).filter(
        Notification.created_at > one_hour_ago,
    ).first()

    if recent:
        return  # Déjà notifié récemment → skip

    # Titre : récupérer le titre du contrat
    title = metadata.get("title", f"Contrat #{contract_id}")

    # Créer la notification
    notification_service.create_notification(
        user_id=recipient_id,
        event_type="chat.new_message",
        title=f"Nouveau message : {title}",
        message=f"{sender.username} vous a envoyé un message.",
        link=f"/{'employee' if sender.role == 'CLIENT' else 'client'}/contracts/{contract_id}",
        contract_id=contract_id,
        actor_id=sender.id,
    )

def add_system_message(contract_id: int, text: str) -> None:
    """
    Ajoute un message système (pas d'utilisateur émetteur).
    Utilisé pour les événements : contrat signé, avenant créé, etc.
    """
    if not text:
        return

    try:
        encrypted = _encrypt(text)
    except Exception:
        return

    msg = ContractMessage(
        contract_id=contract_id,
        sender_id=None,
        sender_role="SYSTEM",
        encrypted_content=encrypted,
        message_type="system",
        read_by=json.dumps([]),
    )
    db.session.add(msg)
    db.session.commit()

    log_event("CHAT_SYSTEM_MESSAGE", status="OK",
              details=f"contract_id={contract_id} message_id={msg.id}")


def list_messages(contract_id: int, user: User,
                  limit: int = 100) -> list:
    """
    Retourne les messages d'un contrat (du plus ancien au plus récent).
    Chaque message est déchiffré.

    Retourne une liste de dict :
      [
        {"id": 1, "sender_role": "CLIENT", "sender_name": "molka",
         "content": "...", "created_at": "...", "is_read": False},
        ...
      ]
    """
    if not _user_can_access(contract_id, user):
        log_event("CHAT_UNAUTHORIZED_ACCESS", user_id=user.id, status="403",
                  details=f"contract_id={contract_id} action=list")
        return []

    rows = (ContractMessage.query
            .filter_by(contract_id=contract_id)
            .order_by(ContractMessage.created_at.asc())
            .limit(limit)
            .all())

    results = []
    for m in rows:
        try:
            content = _decrypt(m.encrypted_content)
        except Exception:
            content = "[Message illisible]"

        sender_name = "Système"
        if m.sender_id:
            sender = db.session.get(User, m.sender_id)
            sender_name = sender.username if sender else "Utilisateur inconnu"

        read_set = _load_or_create_read_set(m)

        results.append({
            "id":           m.id,
            "sender_id":    m.sender_id,
            "sender_role":  m.sender_role,
            "sender_name":  sender_name,
            "content":      content,
            "message_type": m.message_type,
            "created_at":   m.created_at.isoformat() + "Z" if m.created_at else None,
            "is_read":      user.id in read_set,
        })

    return results


def mark_as_read(contract_id: int, user: User) -> dict:
    """Marque tous les messages de ce contrat comme lus par cet utilisateur."""
    if not _user_can_access(contract_id, user):
        return {"ok": False, "error": "Accès non autorisé."}

    rows = ContractMessage.query.filter_by(contract_id=contract_id).all()
    updated = 0

    for m in rows:
        read_set = _load_or_create_read_set(m)
        if user.id not in read_set:
            read_set.add(user.id)
            _save_read_set(m, read_set)
            updated += 1

    if updated:
        db.session.commit()
        log_event("CHAT_MESSAGES_READ", user_id=user.id, status="OK",
                  details=f"contract_id={contract_id} count={updated}")

    return {"ok": True, "updated": updated}


def unread_count(contract_id: int, user: User) -> int:
    """Nombre de messages non lus par cet utilisateur sur ce contrat."""
    if not _user_can_access(contract_id, user):
        return 0

    rows = ContractMessage.query.filter_by(contract_id=contract_id).all()
    count = 0
    for m in rows:
        if m.sender_id == user.id:
            continue  # on ne compte pas ses propres messages
        read_set = _load_or_create_read_set(m)
        if user.id not in read_set:
            count += 1
    return count


def total_unread_for_user(user: User) -> int:
    """
    Nombre total de messages non lus sur tous les contrats accessibles.
    Utile pour le badge global de la cloche de notifications.
    """
    if user.role == "ADMIN":
        contracts = Contract.query.all()
    else:
        # Récupérer tous les contrats accessibles
        contracts = []
        for c in Contract.query.all():
            if _user_can_access(c.id, user):
                contracts.append(c)

    total = 0
    for c in contracts:
        total += unread_count(c.id, user)
    return total


def is_chat_locked(contract_id: int) -> bool:
    """Expose _is_locked pour usage externe."""
    return _is_locked(contract_id)

# =========================================================================
#  Gestion des PDF joints au chat
# =========================================================================

def send_pdf_message(contract_id: int, sender: User,
                     filename: str, pdf_bytes: bytes) -> dict:
    """
    Envoie un message avec un PDF joint (chiffré AES-256-GCM).

    Validations :
      - Taille max 10 Mo
      - Magic number PDF
      - Extension .pdf
      - RBAC + verrouillage
    """
    # --- 1. RBAC
    if not _user_can_access(contract_id, sender):
        log_event("CHAT_PDF_UNAUTHORIZED", user_id=sender.id, status="403",
                  details=f"contract_id={contract_id}")
        return {"ok": False, "error": "Accès non autorisé."}

    # --- 2. Verrouillage
    if _is_locked(contract_id):
        log_event("CHAT_PDF_LOCKED_ATTEMPT", user_id=sender.id, status="403",
                  details=f"contract_id={contract_id}")
        return {"ok": False,
                "error": "Contrat signé. Impossible d'envoyer un PDF."}

    # --- 3. Validation fichier
    if not pdf_bytes:
        return {"ok": False, "error": "Fichier vide."}

    if len(pdf_bytes) > MAX_PDF_BYTES:
        return {"ok": False,
                "error": f"Fichier trop gros (max "
                         f"{MAX_PDF_BYTES // 1024 // 1024} Mo)."}

    if not pdf_bytes.startswith(PDF_MAGIC):
        log_event("CHAT_PDF_INVALID_MAGIC", user_id=sender.id, status="400",
                  details=f"contract_id={contract_id} "
                          f"magic={pdf_bytes[:4]!r}")
        return {"ok": False, "error": "Seuls les PDF sont acceptés."}

    if not filename or not filename.lower().endswith(".pdf"):
        return {"ok": False, "error": "Nom de fichier invalide."}

    # --- 4. Chiffrement
    try:
        enc_pdf = aes_gcm_encrypt(pdf_bytes, Config.CONTRACT_ENCRYPTION_KEY)
    except Exception as e:
        log_event("CHAT_PDF_ENCRYPT_FAILED", user_id=sender.id, status="500",
                  details=f"contract_id={contract_id} "
                          f"error={type(e).__name__}")
        return {"ok": False, "error": "Échec du chiffrement."}

    pdf_hash = _hashlib.sha256(pdf_bytes).hexdigest()
    content = f"📎 Fichier joint : {filename}"
    enc_content = _encrypt(content)

    # --- 5. Créer le message
    msg = ContractMessage(
        contract_id=contract_id,
        sender_id=sender.id,
        sender_role=sender.role,
        encrypted_content=enc_content,
        message_type="pdf",
        read_by=json.dumps([sender.id]),
        attachment_encrypted=enc_pdf,
        attachment_filename=filename,
        attachment_hash=pdf_hash,
    )
    db.session.add(msg)
    db.session.commit()

    log_event("CHAT_PDF_SENT", user_id=sender.id, status="OK",
              details=f"contract_id={contract_id} msg_id={msg.id} "
                      f"filename={filename} size={len(pdf_bytes)}")

    return {
        "ok":         True,
        "message_id": msg.id,
        "filename":   filename,
        "created_at": msg.created_at.isoformat() + "Z",
        "content":    content,
    }


def get_pdf_bytes(message_id: int, user: User):
    """
    Récupère le PDF d'un message (déchiffré).
    Retourne (pdf_bytes, filename) ou (None, None).
    """
    msg = db.session.get(ContractMessage, message_id)
    if not msg or not msg.attachment_encrypted:
        return None, None

    if not _user_can_access(msg.contract_id, user):
        log_event("CHAT_PDF_DOWNLOAD_UNAUTHORIZED",
                  user_id=user.id, status="403",
                  details=f"message_id={message_id}")
        return None, None

    try:
        pdf_bytes = aes_gcm_decrypt(
            msg.attachment_encrypted, Config.CONTRACT_ENCRYPTION_KEY)
    except Exception:
        log_event("CHAT_PDF_DECRYPT_FAILED", user_id=user.id, status="500",
                  details=f"message_id={message_id}")
        return None, None

    log_event("CHAT_PDF_DOWNLOADED", user_id=user.id, status="OK",
              details=f"message_id={message_id} "
                      f"filename={msg.attachment_filename}")

    return pdf_bytes, msg.attachment_filename


def get_latest_pdf_message(contract_id: int):
    """
    Retourne le dernier message PDF envoyé dans la conversation.
    Utilisé par la finalisation pour détecter automatiquement
    quel PDF appliquer au contrat.
    """
    return (ContractMessage.query
            .filter_by(contract_id=contract_id, message_type="pdf")
            .order_by(ContractMessage.created_at.desc())
            .first())