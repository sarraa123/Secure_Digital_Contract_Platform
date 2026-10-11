"""
Routes publiques (accessibles SANS login) :
  - /verify/<contract_id>         → page HTML de vérification
  - /verify/<contract_id>/json    → API JSON
"""
from flask import Blueprint, render_template, jsonify, abort

from app.extensions import db
from app.models import Contract, Signature, User
from app.services import signature_service
from app.security import log_event

bp = Blueprint("public", __name__, url_prefix="/verify")


@bp.route("/<int:contract_id>")
def verify_contract(contract_id):
    """Page publique de vérification d'une signature."""
    contract = db.session.get(Contract, contract_id)
    if not contract:
        abort(404)

    sig = (Signature.query
           .filter_by(contract_id=contract_id)
           .order_by(Signature.signed_at.desc())
           .first())

    if not sig:
        # Le contrat existe mais n'est pas signé
        return render_template("public/verify.html",
                               contract_id=contract_id,
                               signed=False,
                               verified=False,
                               signer=None,
                               signature=None,
                               reason="no_signature")

    # Vérification cryptographique
    result = signature_service.verify_signature_for_contract(contract)

    signer = db.session.get(User, sig.signer_id)

    log_event("PUBLIC_VERIFICATION",
              status="OK" if result["ok"] else "CRITICAL",
              details=f"contract_id={contract_id} reason={result['reason']}")

    return render_template("public/verify.html",
                           contract_id=contract_id,
                           signed=True,
                           verified=result["ok"],
                           reason=result["reason"],
                           signer=signer,
                           signature=sig)


@bp.route("/<int:contract_id>/json")
def verify_contract_json(contract_id):
    """API JSON de vérification (pour intégrations tierces)."""
    contract = db.session.get(Contract, contract_id)
    if not contract:
        return jsonify({"ok": False, "reason": "not_found"}), 404

    sig = (Signature.query
           .filter_by(contract_id=contract_id)
           .order_by(Signature.signed_at.desc())
           .first())

    if not sig:
        return jsonify({
            "ok": False,
            "reason": "not_signed",
            "contract_id": contract_id,
        }), 200

    result = signature_service.verify_signature_for_contract(contract)
    signer = db.session.get(User, sig.signer_id)

    log_event("PUBLIC_VERIFICATION_JSON",
              status="OK" if result["ok"] else "CRITICAL",
              details=f"contract_id={contract_id} reason={result['reason']}")

    return jsonify({
        "ok":              result["ok"],
        "reason":          result["reason"],
        "contract_id":     contract_id,
        "document_hash":   sig.document_hash,
        "algorithm":       sig.algorithm,
        "signed_at":       sig.signed_at.isoformat() + "Z" if sig.signed_at else None,
        "signer": {
            "name":  signer.username if signer else None,
            "email": signer.email if signer else None,
        } if signer else None,
    }), 200