from datetime import datetime, timedelta, timezone

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
    login_required,
    login_user,
    logout_user,
)

from app import db
from app.models import User

from app.security.audit import log_security_event
from app.security.audit_events import (
    USER_REGISTERED,

    LOGIN_SUCCESS,
    LOGIN_FAILED,
    LOGOUT,

    SESSION_CREATED,
    SESSION_EXPIRED,
    SESSION_INVALID,

    PASSWORD_CHANGED,
    PASSWORD_CHANGE_FAILED,

    MFA_SETUP_STARTED,
    MFA_SETUP_SUCCESS,
    MFA_SETUP_FAILED,

    MFA_LOGIN_REQUIRED,
    MFA_LOGIN_SUCCESS,
    MFA_LOGIN_FAILED,

    MFA_RECOVERY_USED,

    BRUTE_FORCE,
)

from app.security.rate_limit import (
    clear_failed_logins,
    is_login_blocked,
    register_failed_login,
)

from .forms import (
    RegistrationForm,
    LoginForm,
    ChangePasswordForm,
)

from .services import (
    authenticate_user,
    create_pending_user,
    change_user_password,
)

from .mfa import (
    generate_mfa_secret,
    generate_provisioning_uri,
    generate_recovery_codes,
    verify_totp,
    verify_recovery_code,
    generate_qr_code_data_uri,
)


auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth",
)


# ==========================================================
# REGISTER
# ==========================================================

@auth_bp.route("/register", methods=["GET", "POST"])
def register():

    form = RegistrationForm()

    if form.validate_on_submit():

        username = form.username.data.strip()
        email = form.email.data.strip().lower()

        # --------------------------------------------------
        # DUPLICATE USERNAME
        # --------------------------------------------------

        existing_username = User.query.filter_by(
            username=username
        ).first()

        if existing_username:

            flash(
                "Ce nom d'utilisateur est déjà utilisé.",
                "danger",
            )

            log_security_event(
                USER_REGISTERED,
                status="FAILURE",
                details={
                    "reason": "duplicate_username",
                },
            )

            return render_template(
                "auth/register.html",
                form=form,
            )

        # --------------------------------------------------
        # DUPLICATE EMAIL
        # --------------------------------------------------

        existing_email = User.query.filter_by(
            email=email
        ).first()

        if existing_email:

            flash(
                "Cette adresse email est déjà utilisée.",
                "danger",
            )

            log_security_event(
                USER_REGISTERED,
                status="FAILURE",
                details={
                    "reason": "duplicate_email",
                },
            )

            return render_template(
                "auth/register.html",
                form=form,
            )

        # --------------------------------------------------
        # CREATE USER
        # --------------------------------------------------

        user = create_pending_user(
            username=username,
            email=email,
            password=form.password.data,
        )

        # --------------------------------------------------
        # SECURITY LOG
        # --------------------------------------------------

        log_security_event(
            USER_REGISTERED,
            user_id=user.id,
            status="SUCCESS",
            details={
                "role": user.role,
                "status": user.status,
            },
        )

        return redirect(
            url_for("auth.registration_success")
        )

    return render_template(
        "auth/register.html",
        form=form,
    )


# ==========================================================
# REGISTRATION SUCCESS
# ==========================================================

@auth_bp.route("/registration-success")
def registration_success():

    return render_template(
        "auth/registration_success.html"
    )


# ==========================================================
# LOGIN
# ==========================================================

@auth_bp.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:

        return redirect(
            url_for("auth.dashboard")
        )

    form = LoginForm()

    if form.validate_on_submit():

        email = form.email.data.strip().lower()
        password = form.password.data

        client_ip = request.remote_addr or "unknown"

        rate_limit_key = f"{client_ip}:{email}"

        # ==================================================
        # BRUTE FORCE PROTECTION
        # ==================================================

        if is_login_blocked(rate_limit_key):

            log_security_event(
                BRUTE_FORCE,
                status="DENIED",
                details={
                    "reason": "login_rate_limit",
                },
            )

            flash(
                "Trop de tentatives. Veuillez réessayer dans quelques instants.",
                "danger",
            )

            return render_template(
                "auth/login.html",
                form=form,
            ), 429

        # ==================================================
        # AUTHENTICATION
        # ==================================================

        user = authenticate_user(
            email,
            password,
        )

        # --------------------------------------------------
        # INVALID CREDENTIALS
        # --------------------------------------------------

        if user is None:

            register_failed_login(
                rate_limit_key
            )

            log_security_event(
                LOGIN_FAILED,
                status="FAILURE",
                details={
                    "reason": "invalid_credentials",
                },
            )

            flash(
                "Email ou mot de passe invalide.",
                "danger",
            )

            return render_template(
                "auth/login.html",
                form=form,
            ), 401

        # ==================================================
        # ACCOUNT STATUS
        # ==================================================

        if user.status != "ACTIVE":

            log_security_event(
                LOGIN_FAILED,
                user_id=user.id,
                status="DENIED",
                details={
                    "reason": "inactive_account",
                    "account_status": user.status,
                },
            )

            flash(
                "Votre compte n'est pas encore actif.",
                "warning",
            )

            return render_template(
                "auth/login.html",
                form=form,
            ), 403

        # ==================================================
        # MFA REQUIRED
        # ==================================================

        if user.mfa_enabled:

            session.clear()

            session["mfa_pending_user_id"] = user.id

            session["mfa_pending_at"] = (
                datetime.now(timezone.utc).isoformat()
            )

            clear_failed_logins(
                rate_limit_key
            )

            log_security_event(
                MFA_LOGIN_REQUIRED,
                user_id=user.id,
                status="INFO",
                details={
                    "method": "TOTP",
                },
            )

            return redirect(
                url_for("auth.mfa_login")
            )

        # ==================================================
        # SUCCESSFUL PASSWORD AUTHENTICATION
        # ==================================================

        clear_failed_logins(
            rate_limit_key
        )

        # ==================================================
        # SESSION FIXATION PROTECTION
        # ==================================================

        session.clear()

        login_user(
            user,
            remember=False,
            fresh=True,
        )

        # ==================================================
        # SESSION TIMESTAMPS
        # ==================================================

        session.permanent = True

        now = datetime.now(timezone.utc)

        session["login_at"] = now.isoformat()

        session["last_activity"] = now.isoformat()

        # ==================================================
        # LAST LOGIN
        # ==================================================

        user.last_login_at = now

        db.session.commit()

        # ==================================================
        # SECURITY LOGS
        # ==================================================

        log_security_event(
            LOGIN_SUCCESS,
            user_id=user.id,
            status="SUCCESS",
            details={
                "method": "password",
                "mfa": False,
            },
        )

        log_security_event(
            SESSION_CREATED,
            user_id=user.id,
            status="SUCCESS",
            details={
                "authentication": "password",
                "mfa": False,
                "session_lifetime_hours": 8,
                "inactivity_timeout_minutes": 15,
            },
        )

        return redirect(
            url_for("auth.dashboard")
        )

    return render_template(
        "auth/login.html",
        form=form,
    )


# ==========================================================
# MFA LOGIN
# ==========================================================

@auth_bp.route(
    "/mfa/login",
    methods=["GET", "POST"],
)
def mfa_login():

    user_id = session.get(
        "mfa_pending_user_id"
    )

    pending_at = session.get(
        "mfa_pending_at"
    )

    # --------------------------------------------------
    # NO MFA CHALLENGE
    # --------------------------------------------------

    if not user_id or not pending_at:

        return redirect(
            url_for("auth.login")
        )

    # --------------------------------------------------
    # PARSE MFA TIMESTAMP
    # --------------------------------------------------

    try:

        pending_time = datetime.fromisoformat(
            pending_at
        )

    except (ValueError, TypeError):

        session.clear()

        return redirect(
            url_for("auth.login")
        )

    # --------------------------------------------------
    # MFA CHALLENGE TIMEOUT
    # --------------------------------------------------

    now = datetime.now(timezone.utc)

    if now - pending_time > timedelta(
        minutes=5
    ):

        session.clear()

        flash(
            "La vérification MFA a expiré.",
            "warning",
        )

        return redirect(
            url_for("auth.login")
        )

    # --------------------------------------------------
    # LOAD USER
    # --------------------------------------------------

    user = db.session.get(
        User,
        int(user_id),
    )

    if not user:

        session.clear()

        return redirect(
            url_for("auth.login")
        )

    # --------------------------------------------------
    # ACCOUNT MUST STILL BE ACTIVE
    # --------------------------------------------------

    if user.status != "ACTIVE":

        session.clear()

        return redirect(
            url_for("auth.login")
        )

    # --------------------------------------------------
    # MFA MUST STILL BE ENABLED
    # --------------------------------------------------

    if not user.mfa_enabled:

        session.clear()

        return redirect(
            url_for("auth.login")
        )

    # ==================================================
    # VERIFY MFA
    # ==================================================

    if request.method == "POST":

        code = request.form.get(
            "code",
            "",
        ).strip()

        if not verify_totp(
            user.mfa_secret,
            code,
        ):

            log_security_event(
                MFA_LOGIN_FAILED,
                user_id=user.id,
                status="FAILURE",
                details={
                    "method": "TOTP",
                    "reason": "invalid_code",
                },
            )

            flash(
                "Code MFA invalide.",
                "danger",
            )

            return render_template(
                "auth/mfa_login.html"
            ), 401

        # ==================================================
        # MFA SUCCESS
        # ==================================================

        session.clear()

        login_user(
            user,
            remember=False,
            fresh=True,
        )

        now = datetime.now(timezone.utc)

        session.permanent = True

        session["login_at"] = now.isoformat()

        session["last_activity"] = now.isoformat()

        user.last_login_at = now

        db.session.commit()

        # --------------------------------------------------
        # MFA SUCCESS LOG
        # --------------------------------------------------

        log_security_event(
            MFA_LOGIN_SUCCESS,
            user_id=user.id,
            status="SUCCESS",
            details={
                "method": "TOTP",
            },
        )

        # --------------------------------------------------
        # COMPLETE LOGIN LOG
        # --------------------------------------------------

        log_security_event(
            LOGIN_SUCCESS,
            user_id=user.id,
            status="SUCCESS",
            details={
                "method": "password+TOTP",
                "mfa": True,
            },
        )

        # --------------------------------------------------
        # SESSION CREATED LOG
        # --------------------------------------------------

        log_security_event(
            SESSION_CREATED,
            user_id=user.id,
            status="SUCCESS",
            details={
                "authentication": "password+TOTP",
                "mfa": True,
                "session_lifetime_hours": 8,
                "inactivity_timeout_minutes": 15,
            },
        )

        return redirect(
            url_for("auth.dashboard")
        )

    return render_template(
        "auth/mfa_login.html"
    )


# ==========================================================
# DASHBOARD
# ==========================================================

@auth_bp.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "auth/dashboard.html",
        user=current_user,
    )


# ==========================================================
# SESSION TIMEOUT ENFORCEMENT
# ==========================================================

@auth_bp.before_app_request
def enforce_session_timeout():

    # --------------------------------------------------
    # NO AUTHENTICATED USER
    # --------------------------------------------------

    if not current_user.is_authenticated:

        return None

    now = datetime.now(timezone.utc)

    login_at_raw = session.get(
        "login_at"
    )

    last_activity_raw = session.get(
        "last_activity"
    )

    # ==================================================
    # SESSION DATA INTEGRITY
    # ==================================================

    if not login_at_raw or not last_activity_raw:

        user_id = current_user.id

        log_security_event(
            SESSION_INVALID,
            user_id=user_id,
            status="DENIED",
            details={
                "reason": "missing_session_metadata",
            },
        )

        logout_user()

        session.clear()

        flash(
            "Votre session a expiré. Veuillez vous reconnecter.",
            "warning",
        )

        return redirect(
            url_for("auth.login")
        )

    # ==================================================
    # PARSE SESSION TIMESTAMPS
    # ==================================================

    try:

        login_at = datetime.fromisoformat(
            login_at_raw
        )

        last_activity = datetime.fromisoformat(
            last_activity_raw
        )

        if login_at.tzinfo is None:

            login_at = login_at.replace(
                tzinfo=timezone.utc
            )

        if last_activity.tzinfo is None:

            last_activity = last_activity.replace(
                tzinfo=timezone.utc
            )

    except (ValueError, TypeError):

        user_id = current_user.id

        log_security_event(
            SESSION_INVALID,
            user_id=user_id,
            status="DENIED",
            details={
                "reason": "invalid_session_metadata",
            },
        )

        logout_user()

        session.clear()

        flash(
            "Votre session est invalide. Veuillez vous reconnecter.",
            "warning",
        )

        return redirect(
            url_for("auth.login")
        )

    # ==================================================
    # ABSOLUTE SESSION TIMEOUT
    # ==================================================

    if now - login_at > timedelta(
        hours=8
    ):

        user_id = current_user.id

        log_security_event(
            SESSION_EXPIRED,
            user_id=user_id,
            status="DENIED",
            details={
                "reason": "absolute_timeout",
                "limit_hours": 8,
            },
        )

        logout_user()

        session.clear()

        flash(
            "Votre session a expiré. Veuillez vous reconnecter.",
            "warning",
        )

        return redirect(
            url_for("auth.login")
        )

    # ==================================================
    # IGNORE STATIC FILES
    # ==================================================

    if request.endpoint == "static":

        return None

    # ==================================================
    # INACTIVITY TIMEOUT
    # ==================================================

    if now - last_activity > timedelta(
        minutes=15
    ):

        user_id = current_user.id

        log_security_event(
            SESSION_EXPIRED,
            user_id=user_id,
            status="DENIED",
            details={
                "reason": "inactivity_timeout",
                "limit_minutes": 15,
            },
        )

        logout_user()

        session.clear()

        flash(
            "Votre session a expiré après une période d'inactivité.",
            "warning",
        )

        return redirect(
            url_for("auth.login")
        )

    # ==================================================
    # FORCE PASSWORD CHANGE
    # ==================================================

    if (
        current_user.must_change_password
        and request.endpoint != "auth.change_password"
        and request.endpoint != "auth.logout"
    ):

        return redirect(
            url_for("auth.change_password")
        )

    # ==================================================
    # UPDATE LAST ACTIVITY
    # ==================================================

    session["last_activity"] = now.isoformat()

    return None


# ==========================================================
# LOGOUT
# ==========================================================

@auth_bp.post("/logout")
@login_required
def logout():

    user_id = current_user.id

    # --------------------------------------------------
    # SECURITY LOG
    # --------------------------------------------------

    log_security_event(
        LOGOUT,
        user_id=user_id,
        status="SUCCESS",
        details={
            "reason": "user_logout",
        },
    )

    logout_user()

    session.clear()

    flash(
        "Vous avez été déconnecté.",
        "success",
    )

    return redirect(
        url_for("auth.login")
    )


# ==========================================================
# CHANGE PASSWORD
# ==========================================================

@auth_bp.route(
    "/change-password",
    methods=["GET", "POST"],
)
@login_required
def change_password():

    form = ChangePasswordForm()

    if form.validate_on_submit():

        # --------------------------------------------------
        # VERIFY CURRENT PASSWORD
        # --------------------------------------------------

        if not change_user_password(
            current_user,
            form.current_password.data,
            form.new_password.data,
        ):

            log_security_event(
                PASSWORD_CHANGE_FAILED,
                user_id=current_user.id,
                status="FAILURE",
                details={
                    "reason": "invalid_current_password",
                },
            )

            flash(
                "Le mot de passe actuel est incorrect.",
                "danger",
            )

            return render_template(
                "auth/change_password.html",
                form=form,
            ), 401

        # --------------------------------------------------
        # SUCCESS
        # --------------------------------------------------

        log_security_event(
            PASSWORD_CHANGED,
            user_id=current_user.id,
            status="SUCCESS",
            details={
                "method": "authenticated_user",
            },
        )

        flash(
            "Votre mot de passe a été modifié avec succès.",
            "success",
        )

        return redirect(
            url_for("auth.dashboard")
        )

    return render_template(
        "auth/change_password.html",
        form=form,
    )


# ==========================================================
# MFA SETUP
# ==========================================================

@auth_bp.route(
    "/mfa/setup",
    methods=["GET"],
)
@login_required
def mfa_setup():

    if current_user.mfa_enabled:

        flash(
            "La MFA est déjà activée.",
            "info",
        )

        return redirect(
            url_for("auth.dashboard")
        )

    # --------------------------------------------------
    # GENERATE MFA SECRET
    # --------------------------------------------------

    secret = generate_mfa_secret()

    session["mfa_setup_secret"] = secret

    # --------------------------------------------------
    # SECURITY LOG
    # --------------------------------------------------

    log_security_event(
        MFA_SETUP_STARTED,
        user_id=current_user.id,
        status="INFO",
        details={
            "method": "TOTP",
        },
    )

    provisioning_uri = generate_provisioning_uri(
        secret,
        current_user.email,
    )

    qr_code = generate_qr_code_data_uri(
        provisioning_uri,
    )

    return render_template(
        "auth/mfa_setup.html",
        provisioning_uri=provisioning_uri,
        secret=secret,
        qr_code=qr_code,
    )


# ==========================================================
# MFA SETUP VERIFY
# ==========================================================

@auth_bp.route(
    "/mfa/setup/verify",
    methods=["GET", "POST"],
)
@login_required
def mfa_setup_verify():

    if current_user.mfa_enabled:

        return redirect(
            url_for("auth.dashboard")
        )

    secret = session.get(
        "mfa_setup_secret"
    )

    if not secret:

        flash(
            "La configuration MFA a expiré. Recommencez.",
            "warning",
        )

        return redirect(
            url_for("auth.mfa_setup")
        )

    if request.method == "POST":

        code = request.form.get(
            "code",
            "",
        ).strip()

        # --------------------------------------------------
        # INVALID TOTP
        # --------------------------------------------------

        if not verify_totp(
            secret,
            code,
        ):

            log_security_event(
                MFA_SETUP_FAILED,
                user_id=current_user.id,
                status="FAILURE",
                details={
                    "method": "TOTP",
                    "reason": "invalid_code",
                },
            )

            flash(
                "Code MFA invalide.",
                "danger",
            )

            return render_template(
                "auth/mfa_verify.html"
            ), 401

        # --------------------------------------------------
        # ENABLE MFA
        # --------------------------------------------------

        current_user.mfa_secret = secret

        current_user.mfa_enabled = True

        db.session.commit()

        # --------------------------------------------------
        # MFA SETUP SUCCESS
        # --------------------------------------------------

        log_security_event(
            MFA_SETUP_SUCCESS,
            user_id=current_user.id,
            status="SUCCESS",
            details={
                "method": "TOTP",
            },
        )

        # --------------------------------------------------
        # REMOVE TEMPORARY SECRET
        # --------------------------------------------------

        session.pop(
            "mfa_setup_secret",
            None,
        )

        # --------------------------------------------------
        # GENERATE RECOVERY CODES
        # --------------------------------------------------

        recovery_codes = generate_recovery_codes(
            current_user.id
        )

        return render_template(
            "auth/mfa_recovery_codes.html",
            recovery_codes=recovery_codes,
        )

    return render_template(
        "auth/mfa_verify.html"
    )