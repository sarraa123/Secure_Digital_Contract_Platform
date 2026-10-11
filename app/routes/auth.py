from flask import Blueprint

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/logout")
def logout():
    return "Logout (stub)"