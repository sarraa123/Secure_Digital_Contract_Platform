"""
Service de gestion des avenants.

Un avenant est un NOUVEAU contrat lié à un contrat signé.
Il permet de modifier un contrat sans jamais toucher à l'original.

Cycle de vie d'une AmendmentRequest :
  PENDING      → demande créée par le client
  NEGOTIATING  → discussion en cours dans le chat
  AGREED       → résumé IA validé par le manager
  APPLIED      → avenant créé (nouveau contrat lié)
  REJECTED     → demande rejetée par le manager
"""
import json
from datetime import datetime

from app.extensions import db
from app.models import (
    Contract, AmendmentRequest, User, ContractPermission,
)
from app.crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt
from app.config import Config
from app.services import (
    contract_service, chat_service, ai_summary_service,
)
from app.security import log_event


# =========================================================================
#  Helpers
# =========================================================================
def _encrypt_json(data) -> bytes:
    """Chiffre un objet JSON (dict/list) avec AES-GCM."""
    payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return aes_gcm_encrypt(payload, Config.CONTRACT_ENCRYPTION_KEY)


def _decrypt_json(blob: bytes):
    """Déchiffre et parse un blob JSON."""
    if not blob:
        return None
    payload = aes_gcm_decrypt(blob, Config.CONTRACT_ENCRYPTION_KEY)
    return json.loads(payload.decode("utf-8"))


def _can_request_amendment(contract_id: int, user: User) -> bool:
    """
    Vérifie que l'utilisateur peut demander une modification.
    Autorisés : client associé, propriétaire du contrat, admin.
    Le contrat DOIT être SIGNÉ.
    """
    from app.models import Signature

    if user.role == "ADMIN":
        return True

    contract = db.session.get(Contract, contract_id)
    if not contract:
        return False

    # Le contrat doit être signé
    if not Signature.query.filter_by(contract_id=contract_id).first():
        return False

    # Récupérer les métadonnées
    try:
        from app.services.encryption_service import decrypt_contract_data
        from app.services.integrity_service import verify_signature as verify_hmac

        if not verify_hmac(contract.encrypted_metadata,
                           contract.encrypted_file,
                           contract.integrity_hash):
            return False
        metadata = decrypt_contract_data(contract.encrypted_metadata)
    except Exception:
        return False

    # Le client ou le propriétaire peuvent demander
    if metadata.get("owner_id") == user.id:
        return True
    if metadata.get("client_id") == user.id:
        return True

    return False


# =========================================================================
#  1. Créer une demande d'avenant
# =========================================================================
def request_amendment(contract_id: int, actor: User) -> dict:
    """
    Crée une demande de modification pour un contrat SIGNÉ.

    Retourne :
      {"ok": True, "amendment_request_id": X}
      {"ok": False, "error": "..."}
    """
    contract = db.session.get(Contract, contract_id)
    if not contract:
        return {"ok": False, "error": "Contrat introuvable."}

    if not _can_request_amendment(contract_id, actor):
        log_event("AMENDMENT_REQUEST_DENIED", user_id=actor.id, status="403",
                  details=f"contract_id={contract_id} actor={actor.email}")
        return {"ok": False,
                "error": "Vous ne pouvez pas demander de modification sur ce contrat."}

    # Vérifier qu'il n'y a pas déjà une demande en cours
    existing = AmendmentRequest.query.filter_by(
        original_contract_id=contract_id,
    ).filter(
        AmendmentRequest.status.in_(["PENDING", "NEGOTIATING", "AGREED"])
    ).first()

    if existing:
        return {"ok": True, "amendment_request_id": existing.id,
                "already_exists": True}

    # Créer la demande
    req = AmendmentRequest(
        original_contract_id=contract_id,
        amendment_contract_id=None,
        requested_by=actor.id,
        status="PENDING",
    )
    db.session.add(req)
    db.session.commit()

        # Message système dans le chat du contrat original
    chat_service.add_system_message(
        contract_id,
        f"Demande de modification ouverte par {actor.username}."
    )

    # ✅ Notification in-app au propriétaire (manager)
    try:
        from app.services.encryption_service import decrypt_contract_data
        metadata = decrypt_contract_data(contract.encrypted_metadata)
        owner_id = metadata.get("owner_id")

        if owner_id and owner_id != actor.id:
            from app.services import notification_service, contract_service

            view = contract_service.load_contract(contract_id, actor)

            if view:
                notification_service.create_notification(
                    user_id=owner_id,
                    event_type="amendment.requested",
                    title=f"Demande de modification : {view.title}",
                    message=f"{actor.username} souhaite modifier ce contrat signé. "
                            f"Consultez le chat pour négocier.",
                    link=f"/employee/contracts/{contract_id}",
                    contract_id=contract_id,
                    actor_id=actor.id,
                )
    except Exception:
        pass

    log_event("AMENDMENT_REQUESTED", user_id=actor.id, status="OK",
              details=f"contract_id={contract_id} request_id={req.id}")

    return {"ok": True, "amendment_request_id": req.id}


# =========================================================================
#  2. Analyser la conversation avec l'IA
# =========================================================================
def analyze_conversation(request_id: int, actor: User) -> dict:
    """
    Récupère la conversation du contrat original, appelle l'IA,
    et stocke le résumé chiffré dans la AmendmentRequest.

    Retourne :
      {
        "ok": True,
        "modifications": [...],
        "resume": "...",
        "provider": "groq"
      }
    """
    req = db.session.get(AmendmentRequest, request_id)
    if not req:
        return {"ok": False, "error": "Demande introuvable."}

    # Seul le propriétaire ou admin peuvent lancer l'analyse
    contract = db.session.get(Contract, req.original_contract_id)
    if not contract:
        return {"ok": False, "error": "Contrat original introuvable."}

    if not _can_manage_amendment(req, actor):
        log_event("AMENDMENT_ANALYZE_DENIED", user_id=actor.id, status="403",
                  details=f"request_id={request_id}")
        return {"ok": False, "error": "Non autorisé."}

    # Récupérer les messages
    messages = chat_service.list_messages(req.original_contract_id, actor)
    if not messages:
        return {"ok": False, "error": "Aucun message dans la conversation."}

    # Appeler l'IA
    try:
        result = ai_summary_service.summarize_modifications(messages)
    except Exception as e:
        log_event("AMENDMENT_ANALYZE_FAILED", user_id=actor.id, status="500",
                  details=f"request_id={request_id} error={type(e).__name__}")
        return {"ok": False, "error": f"Échec de l'analyse : {e}"}

    # Stocker le résumé chiffré
    req.encrypted_summary = _encrypt_json({
        "resume": result.get("resume", ""),
        "provider": result.get("provider"),
        "analyzed_at": datetime.utcnow().isoformat(),
    })
    req.encrypted_modifications = _encrypt_json(
        result.get("modifications", []))
    req.status = "NEGOTIATING"
    db.session.commit()

    log_event("AMENDMENT_ANALYZED", user_id=actor.id, status="OK",
              details=(f"request_id={request_id} "
                       f"provider={result.get('provider')} "
                       f"modifs={len(result.get('modifications', []))}"))

    return {
        "ok": True,
        "modifications": result.get("modifications", []),
        "resume": result.get("resume", ""),
        "provider": result.get("provider"),
        "error": result.get("error"),
    }


def _can_manage_amendment(req: AmendmentRequest, user: User) -> bool:
    """Vérifie que l'utilisateur peut gérer l'avenant (manager ou admin)."""
    if user.role == "ADMIN":
        return True

    contract = db.session.get(Contract, req.original_contract_id)
    if not contract:
        return False

    try:
        from app.services.encryption_service import decrypt_contract_data
        metadata = decrypt_contract_data(contract.encrypted_metadata)
        return metadata.get("owner_id") == user.id
    except Exception:
        return False


# =========================================================================
#  3. Appliquer les modifications (créer l'avenant)
# =========================================================================
def apply_modifications(request_id: int, actor: User,
                        modifications: list = None) -> dict:
    """
    Crée le nouveau contrat (avenant) à partir du contrat original.

    Paramètres :
      - request_id    : ID de la AmendmentRequest
      - modifications : liste des modifications validées par le manager.
                        Si None, utilise celles stockées dans la request.

    Retourne :
      {"ok": True, "amendment_contract_id": X}
    """
    req = db.session.get(AmendmentRequest, request_id)
    if not req:
        return {"ok": False, "error": "Demande introuvable."}

    if not _can_manage_amendment(req, actor):
        log_event("AMENDMENT_APPLY_DENIED", user_id=actor.id, status="403",
                  details=f"request_id={request_id}")
        return {"ok": False, "error": "Non autorisé."}

    if req.status not in ("NEGOTIATING", "AGREED"):
        return {"ok": False,
                "error": f"Statut invalide : {req.status}. "
                         f"L'analyse IA doit être faite d'abord."}

    # Charger les modifications depuis le stockage si non fournies
    if modifications is None:
        try:
            modifications = _decrypt_json(req.encrypted_modifications) or []
        except Exception:
            return {"ok": False, "error": "Impossible de relire les modifications."}

    if not modifications:
        return {"ok": False, "error": "Aucune modification à appliquer."}

    # Charger l'original
    original = db.session.get(Contract, req.original_contract_id)
    if not original:
        return {"ok": False, "error": "Contrat original introuvable."}

    # Récupérer les métadonnées de l'original
    try:
        from app.services.encryption_service import decrypt_contract_data
        metadata = decrypt_contract_data(original.encrypted_metadata)
    except Exception:
        return {"ok": False, "error": "Impossible de lire le contrat original."}

    # Construire les nouvelles métadonnées
    new_metadata = dict(metadata)
    new_metadata["status"] = "DRAFT"
    new_metadata["created_at"] = datetime.utcnow().isoformat()
    new_metadata["updated_at"] = datetime.utcnow().isoformat()
    new_metadata["is_amendment"] = True
    new_metadata["parent_contract_id"] = original.id

    # Retirer les champs liés à la signature
    new_metadata.pop("signature", None)
    new_metadata.pop("signed_by", None)
    new_metadata.pop("signed_at", None)
    new_metadata.pop("validated_by", None)
    new_metadata.pop("validated_at", None)

    # Appliquer les modifications
    applied = []
    for mod in modifications:
        champ = (mod.get("champ") or "").strip()
        nouveau = mod.get("nouveau")
        if not champ or nouveau is None:
            continue

        # Normaliser le nom du champ
        field_map = {
            "titre":         "title",
            "title":         "title",
            "description":   "description",
            "date_debut":    "start_date",
            "date_fin":      "end_date",
            "start_date":    "start_date",
            "end_date":      "end_date",
            "contract_type": "contract_type",
        }
        field = field_map.get(champ)
        if not field:
            continue

        # Convertir les dates si nécessaire
        if field in ("start_date", "end_date"):
            try:
                from datetime import datetime as dt
                # Essayer plusieurs formats
                for fmt in ("%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y"):
                    try:
                        d = dt.strptime(str(nouveau), fmt).date()
                        nouveau = d.isoformat()
                        break
                    except ValueError:
                        continue
            except Exception:
                continue

        new_metadata[field] = nouveau
        applied.append({"champ": champ, "nouvelle_valeur": nouveau})

    if not applied:
        return {"ok": False, "error": "Aucune modification valide à appliquer."}

    # Chiffrer les nouvelles métadonnées
    from app.services.encryption_service import (
        encrypt_contract_data, encrypt_contract_file,
    )
    from app.services.integrity_service import compute_signature

    enc_meta = encrypt_contract_data(new_metadata)

    # Copier le fichier chiffré de l'original (pour l'instant)
    # On pourrait permettre l'upload d'un nouveau PDF plus tard
    enc_file = original.encrypted_file

    # Calculer le nouveau HMAC
    new_hash = compute_signature(enc_meta, enc_file)

    # Créer le nouveau contrat
    amendment = Contract(
        encrypted_metadata=enc_meta,
        encrypted_file=enc_file,
        integrity_hash=new_hash,
        version=1,
        parent_contract_id=original.id,
        is_amendment=True,
    )
    db.session.add(amendment)
    db.session.flush()  # pour avoir l'ID

    # Copier les permissions du contrat original
    # Copier les permissions du contrat original
    original_perms = ContractPermission.query.filter_by(
        contract_id=original.id).all()
    for p in original_perms:
        db.session.add(ContractPermission(
            contract_id=amendment.id,
            user_id=p.user_id,
            permission=p.permission,
        ))

    # ✅ CRITIQUE : si des permissions ont été copiées, mettre à SHARED
    if original_perms:
        new_metadata["status"] = "SHARED"
        enc_meta = encrypt_contract_data(new_metadata)
        amendment.encrypted_metadata = enc_meta
        amendment.integrity_hash = compute_signature(
            enc_meta, amendment.encrypted_file)

    # Mettre à jour la requête
    req.amendment_contract_id = amendment.id
    req.status = "APPLIED"
    req.resolved_at = datetime.utcnow()

    # Message système dans le chat de l'avenant
    db.session.commit()

    chat_service.add_system_message(
        amendment.id,
        f"Avenant créé par {actor.username}. "
        f"Il modifie le contrat #{original.id}."
    )

    # ✅ Notification in-app au client concerné
    try:
        client_id = metadata.get("client_id")

        if client_id and client_id != actor.id:
            from app.services import notification_service, contract_service

            view = contract_service.load_contract(amendment.id, actor)

            if view:
                notification_service.create_notification(
                    user_id=client_id,
                    event_type="amendment.created",
                    title=f"Nouvel avenant : {view.title}",
                    message=f"{actor.username} a créé un avenant qui modifie "
                            f"le contrat #{original.id}. À valider et signer.",
                    link=f"/client/contracts/{amendment.id}",
                    contract_id=amendment.id,
                    actor_id=actor.id,
                )
    except Exception:
        pass

    log_event("AMENDMENT_APPLIED", user_id=actor.id, status="OK",
              details=(f"request_id={request_id} "
                       f"original={original.id} amendment={amendment.id} "
                       f"modifs={len(applied)}"))

    return {
        "ok": True,
        "amendment_contract_id": amendment.id,
        "applied_modifications": applied,
    }

# =========================================================================
#  4. Rejeter une demande
# =========================================================================
def reject_amendment(request_id: int, actor: User, reason: str = None) -> dict:
    """Rejette une demande de modification."""
    req = db.session.get(AmendmentRequest, request_id)
    if not req:
        return {"ok": False, "error": "Demande introuvable."}

    if not _can_manage_amendment(req, actor):
        return {"ok": False, "error": "Non autorisé."}

    if req.status in ("APPLIED", "REJECTED"):
        return {"ok": False, "error": f"Déjà {req.status.lower()}."}

    req.status = "REJECTED"
    req.resolved_at = datetime.utcnow()
    db.session.commit()

    # Message système
    msg = f"Demande de modification rejetée par {actor.username}."
    if reason:
        msg += f" Raison : {reason}"
    chat_service.add_system_message(req.original_contract_id, msg)

    log_event("AMENDMENT_REJECTED", user_id=actor.id, status="OK",
              details=f"request_id={request_id} reason={reason or '—'}")

    return {"ok": True}


# =========================================================================
#  5. Lire les infos d'une demande
# =========================================================================
def get_amendment(request_id: int, actor: User) -> dict:
    """Retourne les infos d'une AmendmentRequest (déchiffrées)."""
    req = db.session.get(AmendmentRequest, request_id)
    if not req:
        return {"ok": False, "error": "Demande introuvable."}

    try:
        summary = _decrypt_json(req.encrypted_summary)
    except Exception:
        summary = None

    try:
        modifications = _decrypt_json(req.encrypted_modifications)
    except Exception:
        modifications = None

    return {
        "ok": True,
        "id":                    req.id,
        "original_contract_id":  req.original_contract_id,
        "amendment_contract_id": req.amendment_contract_id,
        "requested_by":          req.requested_by,
        "status":                req.status,
        "summary":               summary,
        "modifications":         modifications,
        "created_at":            req.created_at.isoformat() + "Z",
        "resolved_at":           (req.resolved_at.isoformat() + "Z"
                                  if req.resolved_at else None),
    }


# =========================================================================
#  6. Chaîne d'avenants
# =========================================================================
def get_amendment_chain(contract_id: int) -> list:
    """
    Retourne la chaîne complète d'avenants à partir d'un contrat.

    Retourne une liste ordonnée :
      [
        {"contract_id": 4, "is_amendment": False, "parent_id": None},
        {"contract_id": 5, "is_amendment": True,  "parent_id": 4},
        {"contract_id": 6, "is_amendment": True,  "parent_id": 5},
      ]
    """
    # Remonter à l'original
    current = db.session.get(Contract, contract_id)
    if not current:
        return []

    while current.parent_contract_id:
        parent = db.session.get(Contract, current.parent_contract_id)
        if not parent:
            break
        current = parent

    # Maintenant current est l'original → redescendre
    chain = []

    def _add_with_children(c):
        chain.append({
            "contract_id":  c.id,
            "is_amendment": c.is_amendment,
            "parent_id":    c.parent_contract_id,
            "version":      c.version,
            "created_at":   c.created_at.isoformat() + "Z" if c.created_at else None,
        })
        children = Contract.query.filter_by(parent_contract_id=c.id).all()
        for child in children:
            _add_with_children(child)

    _add_with_children(current)
    return chain


def get_original_contract(amendment_id: int) -> int:
    """Retourne l'ID du contrat racine pour un avenant donné."""
    contract = db.session.get(Contract, amendment_id)
    if not contract:
        return None

    while contract.parent_contract_id:
        parent = db.session.get(Contract, contract.parent_contract_id)
        if not parent:
            break
        contract = parent

    return contract.id
def _can_manage_amendment_simple(contract_id: int, user) -> bool:
    """
    Vérifie si l'utilisateur peut gérer les modifications de ce contrat.
    Autorisés : ADMIN, propriétaire, ou personne avec permission 'share'.
    """
    if user.role == "ADMIN":
        return True

    contract = db.session.get(Contract, contract_id)
    if not contract:
        return False

    try:
        from app.services.encryption_service import decrypt_contract_data
        from app.services.integrity_service import verify_signature as verify_hmac

        if not verify_hmac(contract.encrypted_metadata,
                           contract.encrypted_file,
                           contract.integrity_hash):
            return False
        metadata = decrypt_contract_data(contract.encrypted_metadata)

        # Propriétaire
        if metadata.get("owner_id") == user.id:
            return True

        # Ou permission "share"
        from app.models import ContractPermission
        perm = ContractPermission.query.filter_by(
            contract_id=contract_id,
            user_id=user.id,
            permission="share"
        ).first()
        return perm is not None
    except Exception:
        return False