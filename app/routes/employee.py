import re
from datetime import datetime
from io import BytesIO

from app.routes.client import current_client
from app.services import contract_service
from app.extensions import db

from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, send_file, abort)
from flask_login import current_user

from app.models import User, Contract
from app.security import log_event
from app.security.authorization import require_role
from app.auth.services import change_user_password


bp = Blueprint("employee", __name__, url_prefix="/employee")


@bp.before_request
def _guard():
    """Tout /employee exige un utilisateur connecté avec le rôle MANAGER."""
    return require_role("MANAGER")


@bp.context_processor
def _inject_layout():
    """Fournit `layout` et `user` à tous les templates de ce blueprint
    (utilisés par la sidebar/topbar communes dans base_users.html)."""
    return {"layout": "employee", "user": current_user}


def current_employee():
    """Alias conservé pour lisibilité : renvoie l'utilisateur connecté."""
    return current_user


# ---------------------------------------------------------------------------
@bp.route("/")
def dashboard():
    user = current_employee()
    contracts = contract_service.list_contracts_for_user(user)
    review_queue = [c for c in contracts if c.status in ("SHARED", "VALIDATED")]
    drafts       = [c for c in contracts if c.status == "DRAFT"]
    return render_template("employee/dashboard.html",
                           active="dashboard", breadcrumb="Overview",
                           review_queue=review_queue, drafts=drafts)


@bp.route("/contracts")
def contracts():
    user = current_employee()
    query  = request.args.get("q", "").strip()
    status = request.args.get("status", "ALL")
    items  = contract_service.list_contracts_for_user(user, q=query, status=status)
    clients = User.query.filter_by(role="CLIENT").order_by(User.username).all()
    return render_template("employee/contracts.html",
                           active="contracts", breadcrumb="Contracts",
                           contracts=items, clients=clients,
                           query=query, status=status)


@bp.route("/contracts/create", methods=["POST"])
def create_contract():
    form = request.form
    file = request.files.get("document")

    wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )

    def fail(user_msg, log_detail, event="INVALID_INPUT", status=400):
        log_event(event, status=str(status), details=log_detail)
        if wants_json:
            return {"ok": False, "error": user_msg}, status
        flash(user_msg, "error")
        return redirect(url_for("employee.contracts"))

    # -----------------------------------------------------------------------
    # 1. TITRE — whitelist + longueur
    # -----------------------------------------------------------------------
    title = form.get("title", "").strip()

    # Whitelist : lettres, chiffres, espaces, ponctuation courante. Pas de ;, --, <, >, etc.
    if not re.match(r"^[a-zA-Z0-9À-ÿ\s\-_'.,()&]+$", title):
        return fail("Le titre contient des caractères non autorisés.",
                    f"title rejected suspicious chars value={title[:50]!r}")

    if not (2 <= len(title) <= 120):
        return fail("Veuillez vérifier les informations du contrat.",
                    f"title invalid len={len(title)}")

    # -----------------------------------------------------------------------
    # 2. TYPE — whitelist
    # -----------------------------------------------------------------------
    ctype = form.get("contract_type", "").strip()
    if ctype not in {"SERVICE_AGREEMENT", "NDA", "SUPPLY",
                     "LEASE", "PARTNERSHIP", "OTHER"}:
        return fail("Veuillez vérifier les informations du contrat.",
                    f"contract_type invalid value={ctype!r}")

    # -----------------------------------------------------------------------
    # 3. DESCRIPTION — whitelist + longueur
    # -----------------------------------------------------------------------
    desc = form.get("description", "").strip()

    if not re.match(r"^[a-zA-Z0-9À-ÿ\s\-_'.,()&!?;:]+$", desc):
        return fail("La description contient des caractères non autorisés.",
                    f"description rejected suspicious chars value={desc[:50]!r}")

    if not (10 <= len(desc) <= 500):
        return fail("Veuillez vérifier les informations du contrat.",
                    f"description invalid len={len(desc)}")

    # -----------------------------------------------------------------------
    # 4. DATES — parsing strict
    # -----------------------------------------------------------------------
    def parse_date(s):
        try:
            return datetime.strptime(s, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            return None

    start = parse_date(form.get("start_date", ""))
    end   = parse_date(form.get("end_date", ""))

    if not start or not end:
        return fail("Veuillez vérifier les dates du contrat.",
                    "dates missing")
    if end <= start:
        return fail("La date d'expiration doit être postérieure à la date de début.",
                    f"dates incoherent start={start} end={end}")

    # -----------------------------------------------------------------------
    # 5. FICHIER — présence + MIME + magic number + taille
    # -----------------------------------------------------------------------
    if not file or file.filename == "":
        return fail("Seuls les fichiers PDF sont acceptés.",
                    "file missing", event="INVALID_UPLOAD")

    header = file.stream.read(8)
    file.stream.seek(0)

    if file.mimetype != "application/pdf":
        return fail("Seuls les fichiers PDF sont acceptés.",
                    f"file rejected mime={file.mimetype!r} "
                    f"filename={file.filename!r} header_hex={header[:4].hex()}",
                    event="INVALID_UPLOAD")

    if header[:4] != b"%PDF":
        return fail("Seuls les fichiers PDF sont acceptés.",
                    f"file rejected magic={header[:4]!r} hex={header[:4].hex()}",
                    event="INVALID_UPLOAD")

    file.stream.seek(0, 2)
    real_size = file.stream.tell()
    file.stream.seek(0)

    if real_size == 0:
        return fail("Seuls les fichiers PDF sont acceptés.",
                    "file empty", event="INVALID_UPLOAD")

    # -----------------------------------------------------------------------
    # 6. CLIENT — optionnel mais validé si renseigné
    # -----------------------------------------------------------------------
    email = form.get("client", "").strip().lower()
    if email:
        client = User.query.filter_by(email=email).first()
        if not client:
            return fail("Le client sélectionné est introuvable.",
                        f"client not found email={email!r}",
                        event="CLIENT_NOT_FOUND")

    # -----------------------------------------------------------------------
    # 7. CRÉATION — via ORM (requête paramétrée)
    # -----------------------------------------------------------------------
    user = current_employee()
    view = contract_service.create_contract(form, file, user)

    if wants_json:
        return {"ok": True,
                "redirect": url_for("employee.contract_detail",
                                    contract_id=view.id),
                "contract_id": view.id}

    return redirect(url_for("employee.contract_detail", contract_id=view.id))


@bp.route("/contracts/<int:contract_id>")
def contract_detail(contract_id):
    user = current_employee()
    view = contract_service.load_contract(contract_id, user)
    if not view:
        abort(404)
    shares  = contract_service.list_permissions(contract_id)
    clients = User.query.filter_by(role="CLIENT").order_by(User.username).all()
    return render_template("employee/contract_detail.html",
                           active="contract-detail",
                           breadcrumb="Contract detail",
                           contract=view, shares=shares, clients=clients)


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
    user = current_employee()
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
    user = current_employee()
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


@bp.route("/contracts/<int:contract_id>/share", methods=["POST"])
def share_contract(contract_id):
    user = current_employee()
    wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )
    email = request.form.get("email", "").strip().lower()
    raw   = request.form.get("permissions", "")
    perms = [p.strip() for p in raw.split(",") if p.strip()]

    result = contract_service.share_contract(contract_id, user, email, perms)

    if wants_json:
        if result["ok"]:
            return {"ok": True,
                    "redirect": url_for("employee.contract_detail",
                                        contract_id=contract_id)}
        return {"ok": False, "error": result["error"]}, 400

    flash(result["error"] or "Contrat partagé.",
          "error" if not result["ok"] else "success")
    return redirect(url_for("employee.contract_detail", contract_id=contract_id))


@bp.route("/contracts/<int:contract_id>/revoke", methods=["POST"])
def revoke_permission(contract_id):
    user = current_employee()
    email = request.form.get("email", "").strip().lower()

    wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )

    result = contract_service.revoke_permission(contract_id, user, email)

    if wants_json:
        if result["ok"]:
            return {"ok": True,
                    "redirect": url_for("employee.contract_detail",
                                        contract_id=contract_id)}
        return {"ok": False, "error": result["error"]}, 400

    flash("Permissions retirées." if result["ok"] else result["error"],
          "success" if result["ok"] else "error")
    return redirect(url_for("employee.contract_detail", contract_id=contract_id))


@bp.route("/contracts/<int:contract_id>/update", methods=["POST"])
def update_contract(contract_id):
    user = current_employee()

    wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )

    result = contract_service.update_contract(
        contract_id, user,
        title         = request.form.get("title"),
        contract_type = request.form.get("contract_type"),
        description   = request.form.get("description"),
        client_email  = request.form.get("client"),
        start_date    = request.form.get("start_date"),
        end_date      = request.form.get("end_date"),
    )

    if wants_json:
        if result["ok"]:
            return {"ok": True,
                    "redirect": url_for("employee.contract_detail",
                                        contract_id=contract_id)}
        return {"ok": False, "error": result["error"]}, 400

    flash(result["error"] or "Contrat mis à jour.",
          "error" if not result["ok"] else "success")
    return redirect(url_for("employee.contract_detail", contract_id=contract_id))


@bp.route("/profile")
def profile():
    """Page profil (partagée avec le client via templates/profile.html)."""
    user = current_employee()

    all_contracts = contract_service.list_contracts_for_user(user)
    stats = {
        "total":     len(all_contracts),
        "drafts":    sum(1 for c in all_contracts if c.status == "DRAFT"),
        "shared":    sum(1 for c in all_contracts if c.status == "SHARED"),
        "validated": sum(1 for c in all_contracts if c.status == "VALIDATED"),
        "signed":    sum(1 for c in all_contracts if c.status == "SIGNED"),
    }

    return render_template(
        "profile.html",
        active="profile",
        breadcrumb="Profile",
        profile_user=user,
        stats=stats,
    )


@bp.route("/profile/update", methods=["POST"])
def update_profile():
    """Met à jour username + email."""
    user = current_employee()

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
        return redirect(url_for("employee.profile"))

    # Validation
    if not (2 <= len(username) <= 64):
        return fail("Le nom doit faire entre 2 et 64 caractères.")
    if not email or "@" not in email or len(email) > 120:
        return fail("Email invalide.")

    # Unicité
    conflict = User.query.filter(
        User.id != user.id,
        (User.email == email) | (User.username == username)
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
    return redirect(url_for("employee.profile"))


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