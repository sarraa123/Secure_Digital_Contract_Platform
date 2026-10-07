"""
API JSON pour les notifications in-app (cloche).
Accessible à tout utilisateur connecté (client, manager, admin).
"""
from flask import Blueprint, jsonify, request, url_for
from flask_login import current_user, login_required

from app.services import notification_service

bp = Blueprint("notifications", __name__, url_prefix="/api/notifications")


@bp.route("/count")
@login_required
def count():
    """Retourne le nombre de notifications non lues."""
    n = notification_service.unread_count(current_user.id)
    return jsonify({"count": n})


@bp.route("/list")
@login_required
def list_notifications():
    """Retourne les 20 dernières notifications."""
    items = notification_service.list_for_user(current_user.id, limit=20)
    return jsonify({
        "notifications": [
            {
                "id":         n.id,
                "title":      n.title,
                "message":    n.message,
                "link":       n.link,
                "event_type": n.event_type,
                "is_read":    n.is_read,
                "created_at": n.created_at.isoformat() + "Z"
                              if n.created_at else None,
            }
            for n in items
        ]
    })


@bp.route("/<int:notif_id>/read", methods=["POST"])
@login_required
def mark_read(notif_id):
    ok = notification_service.mark_as_read(notif_id, current_user.id)
    return jsonify({"ok": ok})


@bp.route("/read-all", methods=["POST"])
@login_required
def mark_all_read():
    count = notification_service.mark_all_as_read(current_user.id)
    return jsonify({"ok": True, "count": count})