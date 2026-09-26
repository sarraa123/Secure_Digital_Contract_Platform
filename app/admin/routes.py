from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    url_for,
)

from app.models import User
from app.security.authorization import admin_required

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


@admin_bp.route("/users")
@admin_required
def users():
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


@admin_bp.post("/users/<int:user_id>/approve")
@admin_required
def approve(user_id):
    user = User.query.get(user_id)

    if user is None:
        abort(404)

    try:
        approve_user(user)
    except ValueError:
        abort(400)

    return redirect(url_for("admin.users"))


@admin_bp.post("/users/<int:user_id>/reject")
@admin_required
def reject(user_id):
    user = User.query.get(user_id)

    if user is None:
        abort(404)

    try:
        reject_user(user)
    except ValueError:
        abort(400)

    return redirect(url_for("admin.users"))


@admin_bp.route("/managers/create", methods=["GET", "POST"])
@admin_required
def create_manager_account():

    form = ManagerCreationForm()

    if form.validate_on_submit():

        try:
            create_manager(
                username=form.username.data,
                email=form.email.data,
                temporary_password=form.temporary_password.data,
            )

        except ValueError as error:
            flash(str(error), "danger")
            return render_template(
                "admin/create_manager.html",
                form=form,
            ), 400

        flash(
            "Le compte gestionnaire a été créé avec succès.",
            "success",
        )

        return redirect(url_for("admin.users"))

    return render_template(
        "admin/create_manager.html",
        form=form,
    )