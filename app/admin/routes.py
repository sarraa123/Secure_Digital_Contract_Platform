from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    url_for,
)

from flask_login import current_user

from app.models import User
from app.security.authorization import admin_required
from app.security.audit import log_security_event

from app.security.audit_events import (
    ACCOUNT_APPROVED,
    ACCOUNT_REJECTED,
    USER_CREATED,
    PRIVILEGE_CHANGE,
    ACCESS_GRANTED,
    ACCESS_DENIED,
)

from .forms import ManagerCreationForm
from .services import (
    approve_user,
    create_manager,
    reject_user,
)


admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
)


# ==========================================================
# ADMIN - LIST USERS
# ==========================================================

@admin_bp.route("/users")
@admin_required
def users():
    """
    Display pending users for administrators.

    Security logging:
    - ACCESS_GRANTED when an authenticated ADMIN accesses
      the administration users page.
    """

    log_security_event(
        ACCESS_GRANTED,
        user_id=current_user.id,
        status="SUCCESS",
        details={
            "resource": "admin_users",
            "action": "view_pending_users",
            "role": current_user.role,
        },
    )

    pending_users = (
        User.query
        .filter_by(status="PENDING")
        .order_by(User.created_at.asc())
        .all()
    )

    return render_template(
        "admin/users.html",
        users=pending_users,
    )


# ==========================================================
# ADMIN - APPROVE USER
# ==========================================================

@admin_bp.post("/users/<int:user_id>/approve")
@admin_required
def approve(user_id):
    """
    Approve a pending user account.

    Security logging:
    - ACCOUNT_APPROVED SUCCESS
    - ACCOUNT_APPROVED FAILURE when target does not exist
    - ACCOUNT_APPROVED FAILURE when service rejects the operation
    """

    user = User.query.get(user_id)

    # ------------------------------------------------------
    # Target user does not exist
    # ------------------------------------------------------

    if user is None:

        log_security_event(
            ACCOUNT_APPROVED,
            user_id=current_user.id,
            status="FAILURE",
            details={
                "action": "approve_user",
                "target_user_id": user_id,
                "reason": "target_user_not_found",
                "actor_role": current_user.role,
            },
        )

        abort(404)

    # ------------------------------------------------------
    # Save useful information before the service modifies
    # the user
    # ------------------------------------------------------

    target_username = user.username
    target_email = user.email
    previous_status = user.status

    # ------------------------------------------------------
    # Approve user
    # ------------------------------------------------------

    try:
        approve_user(user)

    except ValueError as error:

        log_security_event(
            ACCOUNT_APPROVED,
            user_id=current_user.id,
            status="FAILURE",
            details={
                "action": "approve_user",
                "target_user_id": user.id,
                "target_username": target_username,
                "target_email": target_email,
                "previous_status": previous_status,
                "reason": str(error),
                "actor_role": current_user.role,
            },
        )

        abort(400)

    # ------------------------------------------------------
    # Successful approval
    # ------------------------------------------------------

    log_security_event(
        ACCOUNT_APPROVED,
        user_id=current_user.id,
        status="SUCCESS",
        details={
            "action": "approve_user",
            "target_user_id": user.id,
            "target_username": target_username,
            "target_email": target_email,
            "previous_status": previous_status,
            "new_status": "ACTIVE",
            "actor_role": current_user.role,
        },
    )

    return redirect(url_for("admin.users"))


# ==========================================================
# ADMIN - REJECT USER
# ==========================================================

@admin_bp.post("/users/<int:user_id>/reject")
@admin_required
def reject(user_id):
    """
    Reject a pending user account.

    Security logging:
    - ACCOUNT_REJECTED SUCCESS
    - ACCOUNT_REJECTED FAILURE when target does not exist
    - ACCOUNT_REJECTED FAILURE when service rejects the operation
    """

    user = User.query.get(user_id)

    # ------------------------------------------------------
    # Target user does not exist
    # ------------------------------------------------------

    if user is None:

        log_security_event(
            ACCOUNT_REJECTED,
            user_id=current_user.id,
            status="FAILURE",
            details={
                "action": "reject_user",
                "target_user_id": user_id,
                "reason": "target_user_not_found",
                "actor_role": current_user.role,
            },
        )

        abort(404)

    # ------------------------------------------------------
    # Save useful information before modification
    # ------------------------------------------------------

    target_username = user.username
    target_email = user.email
    previous_status = user.status

    # ------------------------------------------------------
    # Reject user
    # ------------------------------------------------------

    try:
        reject_user(user)

    except ValueError as error:

        log_security_event(
            ACCOUNT_REJECTED,
            user_id=current_user.id,
            status="FAILURE",
            details={
                "action": "reject_user",
                "target_user_id": user.id,
                "target_username": target_username,
                "target_email": target_email,
                "previous_status": previous_status,
                "reason": str(error),
                "actor_role": current_user.role,
            },
        )

        abort(400)

    # ------------------------------------------------------
    # Successful rejection
    # ------------------------------------------------------

    log_security_event(
        ACCOUNT_REJECTED,
        user_id=current_user.id,
        status="SUCCESS",
        details={
            "action": "reject_user",
            "target_user_id": user.id,
            "target_username": target_username,
            "target_email": target_email,
            "previous_status": previous_status,
            "new_status": "REJECTED",
            "actor_role": current_user.role,
        },
    )

    return redirect(url_for("admin.users"))


# ==========================================================
# ADMIN - CREATE MANAGER
# ==========================================================

@admin_bp.route("/managers/create", methods=["GET", "POST"])
@admin_required
def create_manager_account():
    """
    Create a MANAGER account.

    Security logging:
    - ACCESS_GRANTED for the manager creation page
    - USER_CREATED SUCCESS/FAILURE
    - PRIVILEGE_CHANGE SUCCESS when a MANAGER is created
    """

    # ------------------------------------------------------
    # Log access to manager creation functionality
    # ------------------------------------------------------

    log_security_event(
        ACCESS_GRANTED,
        user_id=current_user.id,
        status="SUCCESS",
        details={
            "resource": "admin_manager_creation",
            "action": "access_manager_creation",
            "role": current_user.role,
        },
    )

    form = ManagerCreationForm()

    # ------------------------------------------------------
    # Form submitted and valid
    # ------------------------------------------------------

    if form.validate_on_submit():

        try:
            manager = create_manager(
                username=form.username.data,
                email=form.email.data,
                temporary_password=form.temporary_password.data,
            )

        except ValueError as error:

            # --------------------------------------------------
            # Creation failed
            # --------------------------------------------------

            log_security_event(
                USER_CREATED,
                user_id=current_user.id,
                status="FAILURE",
                details={
                    "action": "create_manager",
                    "target_role": "MANAGER",
                    "target_username": form.username.data,
                    "target_email": form.email.data,
                    "reason": str(error),
                    "actor_role": current_user.role,
                },
            )

            flash(str(error), "danger")

            return render_template(
                "admin/create_manager.html",
                form=form,
            ), 400

        # ------------------------------------------------------
        # Extract target information safely
        # ------------------------------------------------------

        manager_id = getattr(manager, "id", None)
        manager_username = getattr(
            manager,
            "username",
            form.username.data,
        )
        manager_email = getattr(
            manager,
            "email",
            form.email.data,
        )

        # ------------------------------------------------------
        # USER_CREATED
        # ------------------------------------------------------

        log_security_event(
            USER_CREATED,
            user_id=current_user.id,
            status="SUCCESS",
            details={
                "action": "create_manager",
                "target_user_id": manager_id,
                "target_username": manager_username,
                "target_email": manager_email,
                "target_role": "MANAGER",
                "actor_role": current_user.role,
            },
        )

        # ------------------------------------------------------
        # PRIVILEGE_CHANGE
        #
        # Creating a MANAGER creates an account with elevated
        # privileges compared with a normal CLIENT.
        # ------------------------------------------------------

        log_security_event(
            PRIVILEGE_CHANGE,
            user_id=current_user.id,
            status="SUCCESS",
            details={
                "action": "create_manager",
                "target_user_id": manager_id,
                "target_username": manager_username,
                "new_role": "MANAGER",
                "reason": "manager_account_created",
                "actor_role": current_user.role,
            },
        )

        flash(
            "Le compte gestionnaire a été créé avec succès.",
            "success",
        )

        return redirect(url_for("admin.users"))

    # ------------------------------------------------------
    # GET request or invalid form
    # ------------------------------------------------------

    return render_template(
        "admin/create_manager.html",
        form=form,
    )