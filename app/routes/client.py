from io import BytesIO
from app.auth.services import change_user_password
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, send_file, abort)
from flask_login import current_user

from app.models import User
from app.services import contract_service
from app.security import log_event
from app.security.authorization import require_role

from app.extensions import db

bp = Blueprint("client", __name__, url_prefix="/client")


@bp.before_request
def _guard():
    """Tout /client exige un utilisateur connecté avec le rôle CLIENT."""
    return require_role("CLIENT")


@bp.context_processor
def _inject_layout():
    return {"layout": "client", "user": current_user}


def current_client():
    return current_user


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@bp.route("/")
def dashboard():
    user = current_client()
    contracts = contract_service.list_contracts_for_user(user)

    waiting    = [c for c in contracts
                  if c.status == "SHARED" and "validate" in c.permissions]
    ready_sign = [c for c in contracts
                  if c.status == "VALIDATED" and "sign" in c.permissions]
    completed  = [c for c in contracts if c.status == "SIGNED"]

    return render_template("client/dashboard.html",
                           active="client-dashboard",
                           breadcrumb="Overview",
                           user_name=user.username,
                           contracts=contracts,
                           waiting=waiting,
                           ready_sign=ready_sign,
                           completed=completed)


# ---------------------------------------------------------------------------
# Liste
# ---------------------------------------------------------------------------
@bp.route("/contracts")
def contracts():
    user = current_client()
    items = contract_service.list_contracts_for_user(user)
    return render_template("client/contracts.html",
                           active="client-contracts",
                           breadcrumb="My contracts",
                           contracts=items)


# ---------------------------------------------------------------------------
# Détail
# ---------------------------------------------------------------------------
@bp.route("/contracts/<int:contract_id>")
def contract_detail(contract_id):
    user = current_client()
    view = contract_service.load_contract(contract_id, user)
    if not view:
        abort(404)

    # Vérifier s'il y a une demande d'avenant en cours
    from app.models import AmendmentRequest
    pending_amendment = AmendmentRequest.query.filter_by(
        original_contract_id=contract_id,
    ).filter(
        AmendmentRequest.status.in_(["PENDING", "NEGOTIATING"])
    ).first()

    return render_template("client/contract_detail.html",
                           active="client-contracts",
                           breadcrumb="Contract detail",
                           contract=view,
                           pending_amendment=pending_amendment)
# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
def _slug(s):
    import re, unicodedata
    s = unicodedata.normalize("NFKD", str(s or ""))
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = re.sub(r"[^\w\s-]", "", s).strip()
    s = re.sub(r"[\s_]+", "_", s)
    return s or "—"


@bp.route("/contracts/<int:contract_id>/download")
def download_contract(contract_id):
    user = current_client()
    blob = contract_service.decrypt_file_for_download(contract_id, user)
    if not blob:
        abort(403)

    view = contract_service.load_contract(contract_id, user)

    title_slug  = _slug(view.title)[:60]
    owner_slug  = _slug(view.owner_name)
    client_slug = _slug(view.client_name)
    date_slug   = view.updated_at.strftime("%Y-%m-%d") if view.updated_at else "date"

    filename = f"{title_slug}_{owner_slug}_{client_slug}_{date_slug}.pdf"

    return send_file(
        BytesIO(blob),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@bp.route("/contracts/<int:contract_id>/preview")
def preview_contract(contract_id):
    user = current_client()
    blob = contract_service.decrypt_file_for_download(contract_id, user)
    if not blob:
        abort(403)
    log_event("CONTRACT_PREVIEW", user_id=user.id,
              details=f"contract_id={contract_id}")
    return send_file(
        BytesIO(blob),
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"preview_{contract_id}.pdf",
    )


# ---------------------------------------------------------------------------
# Validate (AJAX)
# ---------------------------------------------------------------------------
@bp.route("/contracts/<int:contract_id>/validate", methods=["POST"])
def validate_contract(contract_id):
    user = current_client()
    wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )

    result = contract_service.validate_contract(contract_id, user)

    if wants_json:
        if result["ok"]:
            return {"ok": True,
                    "redirect": url_for("client.contract_detail",
                                        contract_id=contract_id)}
        return {"ok": False, "error": result["error"]}, 400

    flash("Contrat validé." if result["ok"] else result["error"],
          "success" if result["ok"] else "error")
    return redirect(url_for("client.contract_detail", contract_id=contract_id))


# ---------------------------------------------------------------------------
# Sign (AJAX) — accepte signature_image
# ---------------------------------------------------------------------------
@bp.route("/contracts/<int:contract_id>/sign", methods=["POST"])
def sign_contract(contract_id):
    user = current_client()
    wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )

    signature_image_b64 = None
    if request.is_json:
        signature_image_b64 = (request.get_json(silent=True) or {}).get("signature_image")
    else:
        signature_image_b64 = request.form.get("signature_image")

    result = contract_service.sign_contract(contract_id, user, signature_image_b64)

    if wants_json:
        if result["ok"]:
            return {"ok": True,
                    "redirect": url_for("client.contract_detail",
                                        contract_id=contract_id)}
        return {"ok": False, "error": result["error"]}, 400

    flash("Contrat signé." if result["ok"] else result["error"],
          "success" if result["ok"] else "error")
    return redirect(url_for("client.contract_detail", contract_id=contract_id))


# ---------------------------------------------------------------------------
# Verify signature (AJAX)
# ---------------------------------------------------------------------------
@bp.route("/contracts/<int:contract_id>/verify-signature")
def verify_signature(contract_id):
    user = current_client()

    view = contract_service.load_contract(contract_id, user)
    if not view:
        abort(404)

    result = contract_service.verify_signature_of_contract(contract_id)

    return {
        "ok":     result["ok"],
        "reason": result["reason"],
        "signer": {
            "id":    result["signer"].id,
            "name":  result["signer"].username,
            "email": result["signer"].email,
        } if result["signer"] else None,
    }


# ---------------------------------------------------------------------------
# Certificat PDF de preuve
# ---------------------------------------------------------------------------
@bp.route("/contracts/<int:contract_id>/certificate")
def download_certificate(contract_id):
    from app.services import certificate_service
    from app.models import Signature

    user = current_client()
    view = contract_service.load_contract(contract_id, user)
    if not view:
        abort(404)

    sig = (Signature.query
           .filter_by(contract_id=contract_id)
           .order_by(Signature.signed_at.desc())
           .first())
    if not sig:
        abort(404)

    signer = db.session.get(User, sig.signer_id)
    if not signer:
        abort(404)

    signer_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if signer_ip and "," in signer_ip:
        signer_ip = signer_ip.split(",")[0].strip()

    verify_url = url_for("client.verify_signature",
                         contract_id=contract_id, _external=True)

    pdf_bytes = certificate_service.build_certificate_pdf(
        contract_view=view, signature=sig, signer=signer,
        signer_ip=signer_ip, verify_url=verify_url,
    )

    log_event("CERTIFICATE_DOWNLOADED", user_id=user.id, status="OK",
              details=f"contract_id={contract_id} format=pdf")

    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"certificat_{_slug(view.title)[:60]}_{contract_id}.pdf",
    )


# ---------------------------------------------------------------------------
# Certificat cryptographique .txt
# ---------------------------------------------------------------------------
@bp.route("/contracts/<int:contract_id>/certificate-crypto")
def download_certificate_crypto(contract_id):
    from app.services import certificate_service
    from app.models import Signature

    user = current_client()
    view = contract_service.load_contract(contract_id, user)
    if not view:
        abort(404)

    sig = (Signature.query
           .filter_by(contract_id=contract_id)
           .order_by(Signature.signed_at.desc())
           .first())
    if not sig:
        abort(404)

    signer = db.session.get(User, sig.signer_id)
    if not signer:
        abort(404)

    signer_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if signer_ip and "," in signer_ip:
        signer_ip = signer_ip.split(",")[0].strip()

    txt = certificate_service.build_certificate_crypto(
        contract_view=view, signature=sig, signer=signer, signer_ip=signer_ip,
    )

    log_event("CERTIFICATE_DOWNLOADED", user_id=user.id, status="OK",
              details=f"contract_id={contract_id} format=crypto")

    return send_file(
        BytesIO(txt.encode("utf-8")),
        mimetype="text/plain",
        as_attachment=True,
        download_name=f"certificat_crypto_{_slug(view.title)[:60]}_{contract_id}.txt",
    )


# ---------------------------------------------------------------------------
# Certificat X.509 personnel
# ---------------------------------------------------------------------------
@bp.route("/profile/certificate")
def download_x509_certificate():
    user = current_client()

    if not user.x509_certificate_pem:
        log_event("X509_NOT_FOUND", user_id=user.id, status="404")
        abort(404)

    log_event("X509_DOWNLOADED", user_id=user.id, status="OK")

    return send_file(
        BytesIO(user.x509_certificate_pem.encode("utf-8")),
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name=f"{_slug(user.username)}_certificate.pem",
    )


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------
@bp.route("/profile")
def profile():
    user = current_client()

    all_contracts = contract_service.list_contracts_for_user(user)
    stats = {
        "total":   len(all_contracts),
        "pending": sum(1 for c in all_contracts
                       if c.status in ("SHARED", "VALIDATED")),
        "signed":  sum(1 for c in all_contracts if c.status == "SIGNED"),
    }

    return render_template(
        "profile.html",
        active="client-profile",
        breadcrumb="Profile",
        profile_user=user,
        stats=stats,
    )


@bp.route("/profile/update", methods=["POST"])
def update_profile():
    user = current_client()

    username = (request.form.get("username") or "").strip()
    email    = (request.form.get("email") or "").strip().lower()

    wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )

    def fail(msg, status=400):
        if wants_json:
            return {"ok": False, "error": msg}, status
        flash(msg, "error")
        return redirect(url_for("client.profile"))

    if not (2 <= len(username) <= 64):
        return fail("Le nom doit faire entre 2 et 64 caractères.")
    if not email or "@" not in email or len(email) > 120:
        return fail("Email invalide.")

    from app.models import User as _User
    conflict = _User.query.filter(
        _User.id != user.id,
        (_User.email == email) | (_User.username == username)
    ).first()
    if conflict:
        return fail("Ce nom ou cet email est déjà utilisé par un autre compte.")

    user.username = username
    user.email    = email
    db.session.commit()

    log_event("PROFILE_UPDATED", user_id=user.id, status="OK",
              details=f"username={username} email={email}")

    if wants_json:
        return {"ok": True}
    flash("Profil mis à jour.", "success")
    return redirect(url_for("client.profile"))


@bp.route("/profile/password", methods=["POST"])
def change_password():
    wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )

    def fail(msg, status=400):
        if wants_json:
            return {"ok": False, "error": msg}, status
        flash(msg, "error")
        return redirect(url_for("client.profile"))

    user = current_client()

    current_password = request.form.get("current_password", "").strip()
    new_password     = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    if not current_password:
        return fail("Mot de passe actuel requis.")

    if len(new_password) < 12:
        return fail("Le nouveau mot de passe doit faire au moins 12 caractères.")

    if new_password != confirm_password:
        return fail("Les deux mots de passe ne correspondent pas.")

    if not change_user_password(user, current_password, new_password):
        log_event("PASSWORD_CHANGE_FAILED", user_id=user.id,
                  status="401", details="wrong current password")
        return fail("Le mot de passe actuel est incorrect.", status=401)

    log_event("PASSWORD_CHANGED", user_id=user.id,
              status="200", details="success")

    if wants_json:
        return {"ok": True, "redirect": url_for("client.profile")}

    flash("Votre mot de passe a été modifié.", "success")
    return redirect(url_for("client.profile"))