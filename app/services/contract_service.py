"""
Point d'entrée unique pour lire/écrire un contrat.
Déchiffre + vérifie intégrité + vérifie RBAC AVANT de retourner quoi que ce soit.
"""
from dataclasses import dataclass
from datetime import datetime, date
from typing import Optional

from app.models.signature import Signature
from app.models.user import User
from app.extensions import db
from app.models import Contract, ContractPermission
from app.services.encryption_service import (
    encrypt_contract_data, decrypt_contract_data,
    encrypt_contract_file, decrypt_contract_file,
)
from app.services.integrity_service import (
    compute_signature,
    verify_signature as verify_signature_hmac,
)
from app.security import log_event


# =========================================================================
#  VIEW MODEL
# =========================================================================
@dataclass
class ContractView:
    id: int
    title: str
    description: str
    contract_type: str
    status: str
    version: int
    owner_id: int
    owner_name: str
    client_id: Optional[int]
    client_name: str
    start_date: Optional[date]
    end_date: Optional[date]
    created_at: datetime
    updated_at: datetime
    integrity: str
    permissions: list

    @property
    def owner(self):
        return self.owner_name

    @property
    def start_date_str(self):
        return self.start_date.strftime("%d/%m/%Y") if self.start_date else "—"

    @property
    def end_date_str(self):
        return self.end_date.strftime("%d/%m/%Y") if self.end_date else "—"

    @property
    def updated_at_str(self):
        return self.updated_at.strftime("%d/%m/%Y") if self.updated_at else "—"

    @property
    def created_at_str(self):
        return self.created_at.strftime("%d/%m/%Y") if self.created_at else "—"


# =========================================================================
#  HELPERS
# =========================================================================
def _build_metadata(form_or_dict, owner_id: int, status: str = "DRAFT") -> dict:
    def parse_date(s):
        if isinstance(s, date):
            return s.isoformat()
        try:
            return datetime.strptime(s, "%Y-%m-%d").date().isoformat()
        except (ValueError, TypeError):
            return None

    now = datetime.utcnow().isoformat()
    return {
        "title":         form_or_dict.get("title", "").strip(),
        "description":   form_or_dict.get("description", "").strip(),
        "contract_type": form_or_dict.get("contract_type", "SERVICE_AGREEMENT"),
        "status":        status,
        "owner_id":      owner_id,
        "client_id":     form_or_dict.get("client_id"),
        "start_date":    parse_date(form_or_dict.get("start_date")),
        "end_date":      parse_date(form_or_dict.get("end_date")),
        "created_at":    now,
        "updated_at":    now,
    }


def _parse_date(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s).date()
    except ValueError:
        return None


def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _user_can_access(metadata: dict, model: Contract, user: User) -> bool:
    if user.role == "ADMIN":
        return True
    if metadata.get("owner_id") == user.id:
        return True
    perms = ContractPermission.query.filter_by(
        contract_id=model.id, user_id=user.id).first()
    return perms is not None


def _save_metadata(model: Contract, metadata: dict) -> None:
    """Rechiffre + re-signe le blob métadonnées."""
    metadata["updated_at"] = datetime.utcnow().isoformat()
    enc_meta = encrypt_contract_data(metadata)
    sig      = compute_signature(enc_meta, model.encrypted_file)
    model.encrypted_metadata = enc_meta
    model.integrity_hash     = sig
    db.session.commit()


def _is_locked(metadata: dict, model: Contract) -> bool:
    """
    Un contrat SIGNED est verrouillé.
    On détecte SIGNED par la présence d'une signature (pas par le blob).
    """
    if Signature.query.filter_by(contract_id=model.id).first():
        return True
    return metadata.get("status") == "SIGNED"


def _block_if_locked(metadata: dict, model: Contract,
                     actor: User, action: str) -> Optional[dict]:
    if _is_locked(metadata, model):
        log_event("CONTRACT_MODIFICATION_AFTER_SIGNATURE",
                  user_id=actor.id, status="403",
                  details=f"contract_id={model.id} action={action} actor={actor.email}")
        return {"ok": False,
                "error": "Ce contrat est signé et ne peut plus être modifié.",
                "log_detail": None}
    return None


def _resolve_status(model: Contract, metadata: dict) -> str:
    """
    Déduit le statut réel du contrat :
    - Si une signature existe en base → SIGNED
    - Sinon → ce que dit le blob métadonnées
    """
    if Signature.query.filter_by(contract_id=model.id).first():
        return "SIGNED"
    return metadata.get("status", "DRAFT")


# =========================================================================
#  CREATE
# =========================================================================
def create_contract(form, file, owner: User) -> ContractView:
    metadata = _build_metadata(form, owner_id=owner.id, status="DRAFT")

    client_email = (form.get("client") or "").strip().lower()
    if client_email:
        client = User.query.filter_by(email=client_email).first()
        if client:
            metadata["client_id"] = client.id

    enc_meta = encrypt_contract_data(metadata)
    file.stream.seek(0)
    enc_file = encrypt_contract_file(file.read())
    signature = compute_signature(enc_meta, enc_file)

    model = Contract(
        encrypted_metadata=enc_meta,
        encrypted_file=enc_file,
        integrity_hash=signature,
        version=1,
    )
    db.session.add(model)
    db.session.commit()

    log_event("CONTRACT_CREATED", user_id=owner.id, details=f"id={model.id}")
    return load_contract(model.id, owner)


# =========================================================================
#  READ
# =========================================================================
def load_contract(contract_id: int, user: User) -> Optional[ContractView]:
    model = db.session.get(Contract, contract_id)
    if not model:
        return None

    if not verify_signature_hmac(model.encrypted_metadata,
                                 model.encrypted_file,
                                 model.integrity_hash):
        log_event("INTEGRITY_FAILURE", user_id=user.id,
                  status="CRITICAL", details=f"contract_id={contract_id}")
        return None

    try:
        metadata = decrypt_contract_data(model.encrypted_metadata)
    except Exception:
        log_event("INTEGRITY_FAILURE", user_id=user.id,
                  status="CRITICAL", details=f"decrypt failed id={contract_id}")
        return None

    if not _user_can_access(metadata, model, user):
        log_event("UNAUTHORIZED_ACCESS", user_id=user.id,
                  status="403", details=f"contract_id={contract_id}")
        return None

    # Statut réel (déduit de la présence d'une signature)
    real_status = _resolve_status(model, metadata)

    client = (User.query.get(metadata.get("client_id"))
              if metadata.get("client_id") else None)
    perms  = [p.permission for p in ContractPermission.query.filter_by(
                  contract_id=model.id).all()]
    owner_obj = User.query.get(metadata["owner_id"])

    return ContractView(
        id=model.id,
        title=metadata["title"],
        description=metadata["description"],
        contract_type=metadata["contract_type"],
        status=real_status,
        version=model.version,
        owner_id=metadata["owner_id"],
        owner_name=owner_obj.username if owner_obj else "—",
        client_id=metadata.get("client_id"),
        client_name=client.username if client else "—",
        start_date=_parse_date(metadata.get("start_date")),
        end_date=_parse_date(metadata.get("end_date")),
        created_at=_parse_dt(metadata.get("created_at")) or model.created_at,
        updated_at=_parse_dt(metadata.get("updated_at")) or model.updated_at,
        integrity="VERIFIED",
        permissions=perms,
    )


def list_contracts_for_user(user: User, q: str = "", status: str = "ALL"):
    results = []
    for model in Contract.query.order_by(Contract.created_at.desc()).all():
        if not verify_signature_hmac(model.encrypted_metadata,
                                     model.encrypted_file,
                                     model.integrity_hash):
            log_event("INTEGRITY_FAILURE", user_id=user.id,
                      status="CRITICAL", details=f"contract_id={model.id}")
            continue

        try:
            metadata = decrypt_contract_data(model.encrypted_metadata)
        except Exception:
            continue

        if not _user_can_access(metadata, model, user):
            continue

        real_status = _resolve_status(model, metadata)

        if status != "ALL" and real_status != status:
            continue
        if q and q.lower() not in metadata.get("title", "").lower():
            continue

        client = (User.query.get(metadata.get("client_id"))
                  if metadata.get("client_id") else None)
        owner_obj = User.query.get(metadata["owner_id"])

        results.append(ContractView(
            id=model.id,
            title=metadata["title"],
            description=metadata["description"],
            contract_type=metadata["contract_type"],
            status=real_status,
            version=model.version,
            owner_id=metadata["owner_id"],
            owner_name=owner_obj.username if owner_obj else "—",
            client_id=metadata.get("client_id"),
            client_name=client.username if client else "—",
            start_date=_parse_date(metadata.get("start_date")),
            end_date=_parse_date(metadata.get("end_date")),
            created_at=_parse_dt(metadata.get("created_at")) or model.created_at,
            updated_at=_parse_dt(metadata.get("updated_at")) or model.updated_at,
            integrity="VERIFIED",
            permissions=[],
        ))
    return results


def decrypt_file_for_download(contract_id: int, user: User) -> Optional[bytes]:
    model = db.session.get(Contract, contract_id)
    if not model:
        return None
    if not verify_signature_hmac(model.encrypted_metadata,
                                 model.encrypted_file,
                                 model.integrity_hash):
        log_event("INTEGRITY_FAILURE", user_id=user.id,
                  details=f"contract_id={contract_id}")
        return None
    metadata = decrypt_contract_data(model.encrypted_metadata)
    if not _user_can_access(metadata, model, user):
        log_event("UNAUTHORIZED_ACCESS", user_id=user.id,
                  status="403", details=f"contract_id={contract_id}")
        return None
    log_event("CONTRACT_DOWNLOAD", user_id=user.id,
              details=f"contract_id={contract_id}")
    return decrypt_contract_file(model.encrypted_file)


# =========================================================================
#  SHARE
# =========================================================================
ALLOWED_PERMISSIONS = {"read", "download", "sign", "share"}


def _can_manage(metadata: dict, model: Contract, user: User) -> bool:
    """Owner / admin / permission 'share' → peut partager, éditer, révoquer."""
    if user.role == "ADMIN":
        return True
    if metadata.get("owner_id") == user.id:
        return True
    return ContractPermission.query.filter_by(
        contract_id=model.id, user_id=user.id, permission="share"
    ).first() is not None


def share_contract(contract_id: int,
                   actor: User,
                   recipient_email: str,
                   permissions: list) -> dict:
    model = db.session.get(Contract, contract_id)
    if not model:
        return {"ok": False, "error": "Contrat introuvable.", "log_detail": None}

    if not verify_signature_hmac(model.encrypted_metadata,
                                 model.encrypted_file,
                                 model.integrity_hash):
        log_event("INTEGRITY_FAILURE", user_id=actor.id, status="CRITICAL",
                  details=f"share blocked contract_id={contract_id}")
        return {"ok": False, "error": "Le contrat a été altéré, partage bloqué.",
                "log_detail": None}

    metadata = decrypt_contract_data(model.encrypted_metadata)

    locked = _block_if_locked(metadata, model, actor, action="share")
    if locked:
        return locked

    if not _can_manage(metadata, model, actor):
        log_event("UNAUTHORIZED_ACCESS", user_id=actor.id, status="403",
                  details=f"share denied contract_id={contract_id} actor={actor.email}")
        return {"ok": False,
                "error": "Vous n'êtes pas autorisé à partager ce contrat.",
                "log_detail": None}

    email = (recipient_email or "").strip().lower()
    if not email or "@" not in email:
        return {"ok": False, "error": "Email destinataire invalide.",
                "log_detail": None}

    recipient = User.query.filter_by(email=email).first()
    if not recipient:
        log_event("CLIENT_NOT_FOUND", user_id=actor.id, status="404",
                  details=f"share target not found email={email}")
        return {"ok": False,
                "error": f"Aucun utilisateur avec l'email « {email} ».",
                "log_detail": None}

    if recipient.id == actor.id:
        return {"ok": False, "error": "Vous ne pouvez pas partager avec vous-même.",
                "log_detail": None}

    perms = sorted({p for p in (permissions or []) if p in ALLOWED_PERMISSIONS})
    if not perms:
        return {"ok": False, "error": "Sélectionnez au moins une permission.",
                "log_detail": None}

    ContractPermission.query.filter_by(
        contract_id=contract_id, user_id=recipient.id).delete()

    for p in perms:
        db.session.add(ContractPermission(
            contract_id=contract_id, user_id=recipient.id, permission=p))

    if metadata.get("status") == "DRAFT":
        metadata["status"] = "SHARED"
        _save_metadata(model, metadata)
    else:
        db.session.commit()

    log_event("CONTRACT_SHARED", user_id=actor.id, status="OK",
              details=(f"contract_id={contract_id} "
                       f"to={email} perms={perms} "
                       f"actor={actor.email}"))

    return {"ok": True, "error": None, "log_detail": None}


def revoke_permission(contract_id: int, actor: User,
                      recipient_email: str) -> dict:
    model = db.session.get(Contract, contract_id)
    if not model:
        return {"ok": False, "error": "Contrat introuvable."}

    if not verify_signature_hmac(model.encrypted_metadata,
                                 model.encrypted_file,
                                 model.integrity_hash):
        log_event("INTEGRITY_FAILURE", user_id=actor.id, status="CRITICAL",
                  details=f"revoke blocked contract_id={contract_id}")
        return {"ok": False, "error": "Intégrité compromise."}

    metadata = decrypt_contract_data(model.encrypted_metadata)

    locked = _block_if_locked(metadata, model, actor, action="revoke")
    if locked:
        return locked

    if not _can_manage(metadata, model, actor):
        log_event("UNAUTHORIZED_ACCESS", user_id=actor.id, status="403",
                  details=f"revoke denied contract_id={contract_id}")
        return {"ok": False, "error": "Non autorisé."}

    recipient = User.query.filter_by(
        email=recipient_email.strip().lower()).first()
    if not recipient:
        return {"ok": False, "error": "Utilisateur introuvable."}

    ContractPermission.query.filter_by(
        contract_id=contract_id, user_id=recipient.id).delete()
    db.session.commit()

    log_event("PERMISSION_REVOKED", user_id=actor.id, status="OK",
              details=f"contract_id={contract_id} from={recipient.email}")

    return {"ok": True}


def list_permissions(contract_id: int) -> list:
    rows = ContractPermission.query.filter_by(contract_id=contract_id).all()
    by_user: dict = {}
    for r in rows:
        u = db.session.get(User, r.user_id)
        if not u:
            continue
        by_user.setdefault(u.id, {
            "user_id": u.id,
            "username": u.username,
            "email": u.email,
            "permissions": [],
        })["permissions"].append(r.permission)
    return list(by_user.values())


# =========================================================================
#  UPDATE (Edit)
# =========================================================================
def update_contract(contract_id: int, actor: User,
                    title: str = None,
                    contract_type: str = None,
                    description: str = None,
                    client_email: str = None,
                    start_date: str = None,
                    end_date: str = None) -> dict:
    model = db.session.get(Contract, contract_id)
    if not model:
        return {"ok": False, "error": "Contrat introuvable."}

    if not verify_signature_hmac(model.encrypted_metadata,
                                 model.encrypted_file,
                                 model.integrity_hash):
        log_event("INTEGRITY_FAILURE", user_id=actor.id, status="CRITICAL",
                  details=f"update blocked contract_id={contract_id}")
        return {"ok": False,
                "error": "Le contrat a été altéré, modification bloquée."}

    metadata = decrypt_contract_data(model.encrypted_metadata)

    locked = _block_if_locked(metadata, model, actor, action="update")
    if locked:
        return locked

    if not _can_manage(metadata, model, actor):
        log_event("UNAUTHORIZED_ACCESS", user_id=actor.id, status="403",
                  details=f"update denied contract_id={contract_id} actor={actor.email}")
        return {"ok": False,
                "error": "Vous n'êtes pas autorisé à modifier ce contrat."}

    VALID_TYPES = {"SERVICE_AGREEMENT", "NDA", "SUPPLY",
                   "LEASE", "PARTNERSHIP", "OTHER"}

    if title is not None:
        title = title.strip()
        if not (2 <= len(title) <= 120):
            return {"ok": False,
                    "error": "Le titre doit faire entre 2 et 120 caractères."}

    if contract_type is not None:
        contract_type = contract_type.strip()
        if contract_type not in VALID_TYPES:
            return {"ok": False, "error": "Type de contrat invalide."}

    if description is not None:
        description = description.strip()
        if not (10 <= len(description) <= 500):
            return {"ok": False,
                    "error": "La description doit faire entre 10 et 500 caractères."}

    def parse_date(s):
        try:
            return datetime.strptime(s, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            return None

    new_start = metadata.get("start_date")
    new_end   = metadata.get("end_date")

    if start_date is not None and start_date != "":
        d = parse_date(start_date)
        if not d:
            return {"ok": False, "error": "Date de début invalide."}
        new_start = d.isoformat()

    if end_date is not None and end_date != "":
        d = parse_date(end_date)
        if not d:
            return {"ok": False, "error": "Date d'expiration invalide."}
        new_end = d.isoformat()

    if new_start and new_end and new_end <= new_start:
        return {"ok": False,
                "error": "La date d'expiration doit être postérieure à la date de début."}

    if client_email is not None:
        client_email = client_email.strip().lower()
        if client_email:
            client = User.query.filter_by(email=client_email).first()
            if not client:
                return {"ok": False,
                        "error": f"Aucun utilisateur avec l'email « {client_email} »."}
            metadata["client_id"] = client.id
        else:
            metadata["client_id"] = None

    if title is not None:
        metadata["title"] = title
    if contract_type is not None:
        metadata["contract_type"] = contract_type
    if description is not None:
        metadata["description"] = description
    if new_start:
        metadata["start_date"] = new_start
    if new_end:
        metadata["end_date"] = new_end

    _save_metadata(model, metadata)

    log_event("CONTRACT_UPDATED", user_id=actor.id, status="OK",
              details=f"contract_id={contract_id} actor={actor.email}")

    return {"ok": True}


# =========================================================================
#  VALIDATE / SIGN
# =========================================================================
VALID_TRANSITIONS = {
    "DRAFT":     {"target": "SHARED",    "perm": "share"},
    "SHARED":    {"target": "VALIDATED", "perm": "validate"},
    "VALIDATED": {"target": "SIGNED",    "perm": "sign"},
    "SIGNED":    None,
}


def _can_transition(metadata: dict, model: Contract, user: User, perm: str) -> bool:
    """Owner / admin / permission explicite. `sign` implique `validate`."""
    if user.role == "ADMIN":
        return True
    if metadata.get("owner_id") == user.id:
        return True

    accepted_perms = [perm]
    if perm == "validate":
        accepted_perms.append("sign")

    return ContractPermission.query.filter(
        ContractPermission.contract_id == model.id,
        ContractPermission.user_id    == user.id,
        ContractPermission.permission.in_(accepted_perms),
    ).first() is not None


def validate_contract(contract_id: int, actor: User) -> dict:
    return _transition(contract_id, actor, target="VALIDATED", perm="validate")


def sign_contract(contract_id: int, actor: User) -> dict:
    """
    VALIDATED → SIGNED.
    Calcule la signature RSA-PSS-SHA256 sur le contenu chiffré ACTUEL.
    NE MODIFIE PAS le blob après signature (sinon la signature serait invalidée).
    Le statut SIGNED est déduit de la présence d'une ligne dans `signatures`.
    """
    from app.services import signature_service

    model = db.session.get(Contract, contract_id)
    if not model:
        return {"ok": False, "error": "Contrat introuvable."}

    if not verify_signature_hmac(model.encrypted_metadata,
                                 model.encrypted_file,
                                 model.integrity_hash):
        log_event("INTEGRITY_FAILURE", user_id=actor.id, status="CRITICAL",
                  details=f"sign blocked contract_id={contract_id}")
        return {"ok": False, "error": "Le contrat a été altéré, signature bloquée."}

    metadata = decrypt_contract_data(model.encrypted_metadata)

    current = metadata.get("status", "DRAFT")
    if current != "VALIDATED":
        log_event("INVALID_TRANSITION", user_id=actor.id, status="400",
                  details=f"contract_id={contract_id} from={current} to=SIGNED")
        return {"ok": False,
                "error": f"Transition impossible : {current} → SIGNED."}

    if not _can_transition(metadata, model, actor, "sign"):
        log_event("UNAUTHORIZED_ACCESS", user_id=actor.id, status="403",
                  details=f"sign denied contract_id={contract_id} actor={actor.email}")
        return {"ok": False,
                "error": "Vous n'avez pas la permission « sign » sur ce contrat."}

    if not actor.has_signing_keys:
        log_event("SIGNING_KEY_MISSING", user_id=actor.id, status="500",
                  details=f"actor={actor.email}")
        return {"ok": False,
                "error": "Aucune clé de signature associée à votre compte."}

    existing = Signature.query.filter_by(contract_id=contract_id).first()
    if existing:
        return {"ok": False, "error": "Ce contrat est déjà signé."}

    # ⚠️ IMPORTANT : on signe le blob TEL QU'IL EST, sans le modifier ensuite.
    try:
        sig = signature_service.create_signature(model, actor)
    except Exception as e:
        log_event("SIGNATURE_FAILED", user_id=actor.id, status="500",
                  details=f"exception={type(e).__name__}")
        return {"ok": False, "error": "Échec du calcul de la signature."}

    # ⚠️ ON NE MODIFIE PAS LE BLOB après signature.
    # Le statut SIGNED sera déduit par _resolve_status() lors des lectures.

    log_event("CONTRACT_SIGNED", user_id=actor.id, status="OK",
              details=(f"contract_id={contract_id} actor={actor.email} "
                       f"algo={sig.algorithm} doc_hash={sig.document_hash[:16]}…"))

    return {"ok": True, "new_status": "SIGNED",
            "signature_id": sig.id,
            "document_hash": sig.document_hash}


def verify_signature_of_contract(contract_id: int) -> dict:
    """Vérifie la signature RSA-PSS stockée dans la table `signatures`."""
    from app.services import signature_service

    model = db.session.get(Contract, contract_id)
    if not model:
        return {"ok": False, "reason": "not_found", "signer": None}

    metadata = decrypt_contract_data(model.encrypted_metadata)

    # Le statut SIGNED est détecté par la présence d'une signature
    sig_exists = Signature.query.filter_by(contract_id=contract_id).first()
    if not sig_exists:
        return {"ok": False, "reason": "not_signed", "signer": None}

    result = signature_service.verify_signature_for_contract(model)

    log_event("SIGNATURE_VERIFIED" if result["ok"] else "SIGNATURE_INVALID",
              status="OK" if result["ok"] else "CRITICAL",
              details=(f"contract_id={contract_id} "
                       f"reason={result['reason']} "
                       f"signer={result['signer'].email if result['signer'] else '—'}"))

    return {
        "ok":     result["ok"],
        "reason": result["reason"],
        "signer": result["signer"],
        "signature": result["signature"],
    }


def _transition(contract_id: int, actor: User, target: str, perm: str) -> dict:
    model = db.session.get(Contract, contract_id)
    if not model:
        return {"ok": False, "error": "Contrat introuvable."}

    if not verify_signature_hmac(model.encrypted_metadata,
                                 model.encrypted_file,
                                 model.integrity_hash):
        log_event("INTEGRITY_FAILURE", user_id=actor.id, status="CRITICAL",
                  details=f"{perm} blocked contract_id={contract_id}")
        return {"ok": False, "error": "Le contrat a été altéré, action bloquée."}

    metadata = decrypt_contract_data(model.encrypted_metadata)

    current = metadata.get("status", "DRAFT")
    allowed = VALID_TRANSITIONS.get(current)
    if not allowed or allowed["target"] != target:
        log_event("INVALID_TRANSITION", user_id=actor.id, status="400",
                  details=f"contract_id={contract_id} from={current} to={target}")
        return {"ok": False,
                "error": f"Transition impossible : {current} → {target}."}

    if not _can_transition(metadata, model, actor, perm):
        log_event("UNAUTHORIZED_ACCESS", user_id=actor.id, status="403",
                  details=f"{perm} denied contract_id={contract_id} actor={actor.email}")
        return {"ok": False,
                "error": f"Vous n'avez pas la permission « {perm} » sur ce contrat."}

    now = datetime.utcnow().isoformat()
    metadata["status"] = target

    if target == "VALIDATED":
        metadata["validated_by"] = actor.id
        metadata["validated_at"] = now
    elif target == "SIGNED":
        metadata["signed_by"] = actor.id
        metadata["signed_at"] = now

    _save_metadata(model, metadata)

    event = "CONTRACT_VALIDATED" if target == "VALIDATED" else "CONTRACT_SIGNED"
    log_event(event, user_id=actor.id, status="OK",
              details=f"contract_id={contract_id} actor={actor.email}")

    return {"ok": True, "new_status": target}