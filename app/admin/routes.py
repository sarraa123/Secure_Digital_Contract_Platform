from flask import Blueprint, abort, redirect, render_template, url_for

from app.models import User
from app.security.authorization import admin_required

from .services import approve_user, reject_user


admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
)


@admin_bp.route("/users")
@admin_required
def users():
    pending_users = User.query.filter_by(
        status="PENDING"
    ).order_by(
        User.created_at.asc()
    ).all()

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

    return redirect(
        url_for("admin.users")
    )


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

    return redirect(
        url_for("admin.users")
    )