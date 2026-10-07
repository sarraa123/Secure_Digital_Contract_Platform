from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from app.services import amendment_service


bp = Blueprint("amendments", __name__, url_prefix="/api")


# =========================================================================
#  POST /api/contracts/<id>/amendments/request
# =========================================================================
@bp.route("/contracts/<int:contract_id>/amendments/request", methods=["POST"])
@login_required
def request_amendment(contract_id):
    """Crée une demande de modification sur un contrat SIGNÉ."""
    result = amendment_service.request_amendment(contract_id, current_user)
    if not result["ok"]:
        return jsonify({"ok": False, "error": result["error"]}), 400
    return jsonify({
        "ok":                   True,
        "amendment_request_id": result["amendment_request_id"],
        "already_exists":       result.get("already_exists", False),
    })


# =========================================================================
#  POST /api/amendments/<req_id>/analyze
# =========================================================================
@bp.route("/amendments/<int:request_id>/analyze", methods=["POST"])
@login_required
def analyze_amendment(request_id):
    """Lance l'analyse IA sur la conversation."""
    result = amendment_service.analyze_conversation(request_id, current_user)
    if not result["ok"]:
        return jsonify({"ok": False, "error": result["error"]}), 400
    return jsonify({
        "ok":            True,
        "modifications": result["modifications"],
        "resume":        result["resume"],
        "provider":      result["provider"],
    })


# =========================================================================
#  POST /api/amendments/<req_id>/apply
# =========================================================================
@bp.route("/amendments/<int:request_id>/apply", methods=["POST"])
@login_required
def apply_amendment(request_id):
    """Crée l'avenant (nouveau contrat)."""
    data = request.get_json(silent=True) or {}
    modifications = data.get("modifications")
    result = amendment_service.apply_modifications(
        request_id, current_user, modifications)
    if not result["ok"]:
        return jsonify({"ok": False, "error": result["error"]}), 400
    return jsonify({
        "ok":                    True,
        "amendment_contract_id": result["amendment_contract_id"],
        "applied_modifications": result["applied_modifications"],
    })


# =========================================================================
#  POST /api/amendments/<req_id>/reject
# =========================================================================
@bp.route("/amendments/<int:request_id>/reject", methods=["POST"])
@login_required
def reject_amendment(request_id):
    """Rejette une demande de modification."""
    data = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip() or None
    result = amendment_service.reject_amendment(request_id, current_user, reason)
    if not result["ok"]:
        return jsonify({"ok": False, "error": result["error"]}), 400
    return jsonify({"ok": True})


# =========================================================================
#  GET /api/amendments/<req_id>
# =========================================================================
@bp.route("/amendments/<int:request_id>", methods=["GET"])
@login_required
def get_amendment(request_id):
    """Retourne les détails d'une demande."""
    result = amendment_service.get_amendment(request_id, current_user)
    if not result["ok"]:
        return jsonify({"ok": False, "error": result["error"]}), 404
    return jsonify(result)


# =========================================================================
#  GET /api/contracts/<id>/amendments/chain
# =========================================================================
@bp.route("/contracts/<int:contract_id>/amendments/chain", methods=["GET"])
@login_required
def amendment_chain(contract_id):
    """Retourne la chaîne d'avenants d'un contrat."""
    chain = amendment_service.get_amendment_chain(contract_id)
    return jsonify({
        "ok":          True,
        "contract_id": contract_id,
        "chain":       chain,
    })


# =========================================================================
#  POST /api/contracts/<id>/amendments/finalize
# =========================================================================
@bp.route("/contracts/<int:contract_id>/amendments/finalize", methods=["POST"])
@login_required
def finalize_amendment(contract_id):
    """Analyse IA + création avenant ou modification directe."""
    from app.services import chat_service, ai_summary_service
    from app.models import Contract, Signature
    from app.extensions import db

    contract = db.session.get(Contract, contract_id)
    if not contract:
        return jsonify({"ok": False, "error": "Contrat introuvable."}), 404

    if not amendment_service._can_manage_amendment_simple(contract_id, current_user):
        return jsonify({"ok": False,
                        "error": "Seul le propriétaire peut finaliser."}), 403

    messages = chat_service.list_messages(contract_id, current_user)
    if not messages:
        return jsonify({"ok": False, "error": "Aucun message à analyser."}), 400

    user_messages = [m for m in messages
                     if m.get("sender_role") in ("CLIENT", "MANAGER", "ADMIN")]
    if len(user_messages) < 2:
        return jsonify({"ok": False,
                        "error": "Il faut au moins 2 messages pour analyser."}), 400

    try:
        result = ai_summary_service.summarize_modifications(user_messages)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Erreur IA : {e}"}), 500

    modifications = result.get("modifications", [])
    latest_pdf = chat_service.get_latest_pdf_message(contract_id)

    if not modifications and not latest_pdf:
        return jsonify({
            "ok": False,
            "error": "Aucune modification détectée (ni champ, ni PDF)."
        }), 400

    is_signed = Signature.query.filter_by(contract_id=contract_id).first() is not None

    if not is_signed:
        return _apply_modifications_directly(
            contract_id, modifications, result, current_user)
    else:
        return _apply_modifications_via_amendment(
            contract_id, modifications, result, current_user)


def _apply_modifications_directly(contract_id, modifications, ia_result, actor):
    """Modifie directement le contrat (non signé)."""
    from app.services import contract_service, chat_service
    from app.models import Contract
    from app.services.integrity_service import compute_signature
    from app.extensions import db

    kwargs = {}
    for mod in modifications:
        champ = (mod.get("champ") or "").strip().lower()
        nouveau = mod.get("nouveau")
        if nouveau is None or nouveau == "—":
            continue
        if champ in ("titre", "title"):
            kwargs["title"] = str(nouveau)
        elif champ == "description":
            kwargs["description"] = str(nouveau)
        elif champ in ("date_debut", "start_date"):
            kwargs["start_date"] = str(nouveau)
        elif champ in ("date_fin", "end_date"):
            kwargs["end_date"] = str(nouveau)
        elif champ in ("contract_type", "type"):
            kwargs["contract_type"] = str(nouveau)

    latest_pdf_msg = chat_service.get_latest_pdf_message(contract_id)

    if kwargs:
        result = contract_service.update_contract(contract_id, actor, **kwargs)
        if not result.get("ok"):
            return jsonify({"ok": False,
                            "error": result.get("error", "Échec.")}), 400

    pdf_replaced = False
    pdf_filename = None

    if latest_pdf_msg and latest_pdf_msg.attachment_encrypted:
        contract = db.session.get(Contract, contract_id)
        if contract:
            contract.encrypted_file = latest_pdf_msg.attachment_encrypted
            contract.integrity_hash = compute_signature(
                contract.encrypted_metadata, contract.encrypted_file)
            db.session.commit()
            pdf_replaced = True
            pdf_filename = latest_pdf_msg.attachment_filename

    if not kwargs and not pdf_replaced:
        return jsonify({"ok": False,
                        "error": "Aucune modification à appliquer."}), 400

    msg_parts = [f"✅ Contrat mis à jour par {actor.username}"]
    if kwargs:
        msg_parts.append(f"• Champs modifiés : {', '.join(kwargs.keys())}")
    if pdf_replaced:
        msg_parts.append(f"• PDF remplacé : {pdf_filename}")

    chat_service.add_system_message(contract_id, "\n".join(msg_parts))

    return jsonify({
        "ok":             True,
        "mode":           "direct",
        "contract_id":    contract_id,
        "applied_fields": list(kwargs.keys()),
        "pdf_replaced":   pdf_replaced,
        "pdf_filename":   pdf_filename,
        "resume":         ia_result.get("resume", ""),
        "provider":       ia_result.get("provider", ""),
    })


def _apply_modifications_via_amendment(contract_id, modifications, ia_result, actor):
    """Crée un avenant (contrat signé)."""
    from app.services import amendment_service

    req = amendment_service.request_amendment(contract_id, actor)
    if not req.get("ok"):
        return jsonify({"ok": False, "error": req.get("error")}), 400

    request_id = req["amendment_request_id"]

    try:
        amendment_service.analyze_conversation(request_id, actor)
    except Exception:
        pass

    apply_result = amendment_service.apply_modifications(
        request_id, actor, modifications)

    if not apply_result.get("ok"):
        return jsonify({"ok": False, "error": apply_result.get("error")}), 400

    return jsonify({
        "ok":                    True,
        "mode":                  "amendment",
        "amendment_contract_id": apply_result["amendment_contract_id"],
        "applied_modifications": apply_result["applied_modifications"],
        "resume":                ia_result.get("resume", ""),
        "provider":              ia_result.get("provider", ""),
    })


# =========================================================================
#  GET /api/contracts/<id>/amendments/share-preview
# =========================================================================
@bp.route("/contracts/<int:contract_id>/amendments/share-preview", methods=["GET"])
@login_required
def share_preview(contract_id):
    """Retourne les permissions du contrat original (à copier)."""
    from app.models import Contract, ContractPermission, User
    from app.extensions import db

    contract = db.session.get(Contract, contract_id)
    if not contract:
        return jsonify({"ok": False, "error": "Contrat introuvable."}), 404

    if not amendment_service._can_manage_amendment_simple(contract_id, current_user):
        return jsonify({"ok": False, "error": "Accès non autorisé."}), 403

    if not contract.parent_contract_id:
        return jsonify({
            "ok":           True,
            "is_amendment": False,
            "users":        [],
        })

    original_perms = ContractPermission.query.filter_by(
        contract_id=contract.parent_contract_id,
    ).all()

    by_user = {}
    for p in original_perms:
        u = db.session.get(User, p.user_id)
        if not u:
            continue
        if u.id not in by_user:
            by_user[u.id] = {
                "user_id":     u.id,
                "username":    u.username,
                "email":       u.email,
                "permissions": [],
            }
        by_user[u.id]["permissions"].append(p.permission)

    users = list(by_user.values())

    existing = ContractPermission.query.filter_by(
        contract_id=contract_id,
    ).all()
    already_shared = {p.user_id for p in existing}

    for u in users:
        u["already_shared"] = u["user_id"] in already_shared

    return jsonify({
        "ok":           True,
        "is_amendment": True,
        "original_id":  contract.parent_contract_id,
        "users":        users,
        "has_any":      len(users) > 0,
    })


# =========================================================================
#  POST /api/contracts/<id>/amendments/auto-share
# =========================================================================
@bp.route("/contracts/<int:contract_id>/amendments/auto-share", methods=["POST"])
@login_required
def auto_share(contract_id):
    """Copie les permissions du contrat original vers cet avenant."""
    from app.models import Contract, ContractPermission, User
    from app.extensions import db
    from app.services import notification_service, chat_service
    from app.services.encryption_service import (
        encrypt_contract_data, decrypt_contract_data,
    )
    from app.services.integrity_service import compute_signature
    from app.security import log_event

    contract = db.session.get(Contract, contract_id)
    if not contract:
        return jsonify({"ok": False, "error": "Contrat introuvable."}), 404

    if not amendment_service._can_manage_amendment_simple(contract_id, current_user):
        return jsonify({"ok": False, "error": "Accès non autorisé."}), 403

    if not contract.parent_contract_id:
        return jsonify({"ok": False,
                        "error": "Ce contrat n'est pas un avenant."}), 400

    original_perms = ContractPermission.query.filter_by(
        contract_id=contract.parent_contract_id,
    ).all()

    if not original_perms:
        return jsonify({"ok": False,
                        "error": "Le contrat original n'était partagé avec personne."}), 400

    by_user = {}
    for p in original_perms:
        by_user.setdefault(p.user_id, []).append(p.permission)

    ContractPermission.query.filter_by(contract_id=contract_id).delete()

    shared_users = []
    for user_id, perms in by_user.items():
        u = db.session.get(User, user_id)
        if not u:
            continue
        for perm in set(perms):
            db.session.add(ContractPermission(
                contract_id=contract_id,
                user_id=user_id,
                permission=perm,
            ))
        shared_users.append(u)

    try:
        metadata = decrypt_contract_data(contract.encrypted_metadata)
        old_status = metadata.get("status")
        metadata["status"] = "SHARED"

        enc_meta = encrypt_contract_data(metadata)
        contract.encrypted_metadata = enc_meta
        contract.integrity_hash = compute_signature(
            enc_meta, contract.encrypted_file)

        db.session.commit()

        log_event("AUTO_SHARE_STATUS_UPDATED",
                  user_id=current_user.id, status="OK",
                  details=f"contract_id={contract_id} "
                          f"old={old_status} new=SHARED")

    except Exception as e:
        db.session.rollback()
        log_event("AUTO_SHARE_STATUS_FAILED",
                  user_id=current_user.id, status="500",
                  details=f"contract_id={contract_id} error={e}")
        return jsonify({"ok": False,
                        "error": f"Erreur métadonnées : {e}"}), 500

    from app.services import contract_service
    view = contract_service.load_contract(contract_id, current_user)

    for u in shared_users:
        if u.id == current_user.id:
            continue
        try:
            perms_list = sorted(set(by_user[u.id]))
            notification_service.notify_contract_shared(
                view, current_user, u, perms_list)
        except Exception:
            pass

    chat_service.add_system_message(
        contract_id,
        f"Permissions copiées depuis le contrat #{contract.parent_contract_id} "
        f"({len(shared_users)} utilisateur(s))."
    )

    log_event("AMENDMENT_AUTO_SHARED", user_id=current_user.id, status="OK",
              details=f"contract_id={contract_id} "
                      f"original={contract.parent_contract_id} "
                      f"users={[u.email for u in shared_users]}")

    return jsonify({
        "ok":           True,
        "shared_count": len(shared_users),
    })