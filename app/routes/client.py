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
    """Fournit `layout` et `user` à tous les templates de ce blueprint
    (utilisés par la sidebar/topbar communes dans base_users.html)."""
    return {"layout": "client", "user": current_user}


def current_client():
    """Alias conservé pour lisibilité : renvoie l'utilisateur connecté."""
    return current_user


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@bp.route("/")
def dashboard():
    user = current_client()
    contracts = contract_service.list_contracts_for_user(user)

    # Catégorisation pour la démo
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
    return render_template("client/contract_detail.html",
                           active="client-contracts",
                           breadcrumb="Contract detail",
                           contract=view)


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
def _slug(s):
    """Nettoie une chaîne pour un nom de fichier."""
    import re, unicodedata
    s = unicodedata.normalize("NFKD", str(s or ""))
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = re.sub(r"[^\w\s-]", "", s).strip()
    s = re.sub(r"[\s_]+", "_", s)
    return s or "—"


@bp.route("/contracts/<int:contract_id>/download")
def download_contract(contract_id):
    """Télécharge le PDF avec un nom intelligent."""
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
    """Affiche le PDF en inline (aperçu navigateur)."""
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
# Sign (AJAX)
# ---------------------------------------------------------------------------
@bp.route("/contracts/<int:contract_id>/sign", methods=["POST"])
def sign_contract(contract_id):
    user = current_client()
    wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )

    result = contract_service.sign_contract(contract_id, user)

    if wants_json:
        if result["ok"]:
            return {"ok": True,
                    "redirect": url_for("client.contract_detail",
                                        contract_id=contract_id)}
        return {"ok": False, "error": result["error"]}, 400

    flash("Contrat signé." if result["ok"] else result["error"],
          "success" if result["ok"] else "error")
    return redirect(url_for("client.contract_detail", contract_id=contract_id))

@bp.route("/contracts/<int:contract_id>/verify-signature")
def verify_signature(contract_id):
    """Vérifie la signature RSA-PSS d'un contrat signé (AJAX)."""
    user = current_client()

    # Charge d'abord le contrat pour vérifier que le user y a accès
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
@bp.route("/profile")
def profile():
    """Page profil (partagée avec l'employé via templates/profile.html)."""
    user = current_client()

    all_contracts = contract_service.list_contracts_for_user(user)
    stats = {
        "total":   len(all_contracts),
        "pending": sum(1 for c in all_contracts
                       if c.status in ("SHARED", "VALIDATED")),
        "signed":  sum(1 for c in all_contracts if c.status == "SIGNED"),
    }

    return render_template(
        "profile.html",              # ← chemin unique
        active="client-profile",
        breadcrumb="Profile",
        profile_user=user,
        stats=stats,
    )
@bp.route("/profile/update", methods=["POST"])
def update_profile():
    """Met à jour username + email."""
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
    """Change le mot de passe du client connecté."""
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