from urllib.parse import urljoin, urlparse

from flask import Blueprint, flash, redirect, render_template, url_for

from app.models import User

from .forms import RegistrationForm
from .services import create_pending_user
from datetime import datetime, timedelta
from flask_login import login_required
from datetime import datetime, timedelta

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from flask_login import (
    current_user,
    login_user,
    logout_user,
)

from app.models import User
from app.security.rate_limit import (
    clear_failed_logins,
    is_login_blocked,
    register_failed_login,
)

from .forms import LoginForm, RegistrationForm
from .services import (
    authenticate_user,
    create_pending_user,
)

auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth",
)


# ---------------------------------------------------------------------------
# Aiguillage vers la bonne interface selon le rôle de l'utilisateur.
# C'est ici que "login" se relie aux autres espaces (client / employee /
# admin) : chaque rôle a son propre tableau de bord.
# ---------------------------------------------------------------------------
_ROLE_HOME_ENDPOINT = {
    "ADMIN": "admin.users",
    "MANAGER": "employee.dashboard",
    "CLIENT": "client.dashboard",
}


def _redirect_after_login(user):
    endpoint = _ROLE_HOME_ENDPOINT.get(user.role, "auth.dashboard")
    return redirect(url_for(endpoint))


def _is_safe_redirect_url(request, target):
    """Empêche les redirections ouvertes : `next` ne peut pointer que
    vers une URL du même site."""
    if not target:
        return False
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return (
        redirect_url.scheme in ("http", "https")
        and host_url.netloc == redirect_url.netloc
    )


@auth_bp.route("/register", methods=["GET", "POST"])
def register():

    form = RegistrationForm()

    if form.validate_on_submit():

        username = form.username.data.strip()
        email = form.email.data.strip().lower()

        existing_username = User.query.filter_by(
            username=username
        ).first()

        if existing_username:
            flash(
                "Ce nom d'utilisateur est déjà utilisé.",
                "danger",
            )
            return render_template(
                "auth/register.html",
                form=form,
            )

        existing_email = User.query.filter_by(
            email=email
        ).first()

        if existing_email:
            flash(
                "Cette adresse email est déjà utilisée.",
                "danger",
            )
            return render_template(
                "auth/register.html",
                form=form,
            )

        create_pending_user(
            username=username,
            email=email,
            password=form.password.data,
        )

        return redirect(
            url_for("auth.registration_success")
        )

    return render_template(
        "auth/register.html",
        form=form,
    )


@auth_bp.route("/registration-success")
def registration_success():
    return render_template(
        "auth/registration_success.html"
    )

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return _redirect_after_login(current_user)

    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data

        client_ip = request.remote_addr or "unknown"

        rate_limit_key = f"{client_ip}:{email}"

        if is_login_blocked(rate_limit_key):
            flash(
                "Trop de tentatives. Veuillez réessayer dans quelques instants.",
                "danger",
            )
            return render_template(
                "auth/login.html",
                form=form,
            ), 429

        user = authenticate_user(email, password)

        if user is None:
            register_failed_login(rate_limit_key)

            flash(
                "Email ou mot de passe invalide.",
                "danger",
            )

            return render_template(
                "auth/login.html",
                form=form,
            ), 401

        if user.status != "ACTIVE":
            flash(
                "Votre compte n'est pas encore actif.",
                "warning",
            )

            return render_template(
                "auth/login.html",
                form=form,
            ), 403

        clear_failed_logins(rate_limit_key)

        # Session fixation mitigation:
        # remove any existing session data before authentication.
        session.clear()

        login_user(
            user,
            remember=False,
            fresh=True,
        )

        session.permanent = True
        session["login_at"] = datetime.utcnow().isoformat()
        session["last_activity"] = datetime.utcnow().isoformat()

        user.last_login_at = datetime.utcnow()

        from app import db

        db.session.commit()

        next_url = request.args.get("next")
        if next_url and _is_safe_redirect_url(request, next_url):
            return redirect(next_url)

        return _redirect_after_login(user)

    return render_template(
        "auth/login.html",
        form=form,
    )

@auth_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "auth/dashboard.html",
        user=current_user,
    )


@auth_bp.before_app_request
def enforce_session_timeout():
    if not current_user.is_authenticated:
        return None

    now = datetime.utcnow()

    login_at_raw = session.get("login_at")
    last_activity_raw = session.get("last_activity")

    if not login_at_raw or not last_activity_raw:
        logout_user()
        session.clear()

        flash(
            "Votre session a expiré. Veuillez vous reconnecter.",
            "warning",
        )

        return redirect(url_for("auth.login"))

    try:
        login_at = datetime.fromisoformat(login_at_raw)
        last_activity = datetime.fromisoformat(last_activity_raw)
    except ValueError:
        logout_user()
        session.clear()

        return redirect(url_for("auth.login"))

    # Absolute lifetime: 8 hours
    if now - login_at > timedelta(hours=8):
        logout_user()
        session.clear()

        flash(
            "Votre session a expiré. Veuillez vous reconnecter.",
            "warning",
        )

        return redirect(url_for("auth.login"))

    # Inactivity timeout: 15 minutes
    if now - last_activity > timedelta(minutes=15):
        logout_user()
        session.clear()

        flash(
            "Votre session a expiré après une période d'inactivité.",
            "warning",
        )

        return redirect(url_for("auth.login"))

    session["last_activity"] = now.isoformat()

    return None

@auth_bp.post("/logout")
@login_required
def logout():
    logout_user()
    session.clear()

    flash(
        "Vous avez été déconnecté.",
        "success",
    )

    return redirect(url_for("auth.login"))