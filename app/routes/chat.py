"""
Routes HTTP pour le chat par contrat.

Endpoints :
  GET  /api/contracts/<id>/messages              → liste messages
  POST /api/contracts/<id>/messages              → envoyer un message
  POST /api/contracts/<id>/messages/read         → marquer comme lus
  GET  /api/contracts/<id>/messages/count        → nombre non lus
"""
from flask import Blueprint, jsonify, request , send_file
from flask_login import current_user, login_required

from app.services import chat_service

from io import BytesIO

bp = Blueprint("chat", __name__, url_prefix="/api/contracts")


# =========================================================================
#  GET /api/contracts/<id>/messages
# =========================================================================
@bp.route("/<int:contract_id>/messages", methods=["GET"])
@login_required
def list_messages(contract_id):
    """Liste tous les messages d'un contrat."""
    messages = chat_service.list_messages(contract_id, current_user, limit=200)

    return jsonify({
        "ok": True,
        "contract_id": contract_id,
        "locked": chat_service.is_chat_locked(contract_id),
        "messages": messages,
        "current_user_id": current_user.id,
    })


# =========================================================================
#  POST /api/contracts/<id>/messages
# =========================================================================
@bp.route("/<int:contract_id>/messages", methods=["POST"])
@login_required
def send_message(contract_id):
    """Envoie un message dans le chat d'un contrat."""
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()

    if not content:
        return jsonify({"ok": False, "error": "Message vide."}), 400

    result = chat_service.send_message(contract_id, current_user, content)

    if result["ok"]:
        return jsonify({
            "ok":         True,
            "message_id": result["message_id"],
            "created_at": result["created_at"],
            "sender_name": current_user.username,
            "sender_role": current_user.role,
            "content":    content,
        })

    return jsonify({"ok": False, "error": result["error"]}), 400


# =========================================================================
#  POST /api/contracts/<id>/messages/read
# =========================================================================
@bp.route("/<int:contract_id>/messages/read", methods=["POST"])
@login_required
def mark_read(contract_id):
    """Marque tous les messages comme lus."""
    result = chat_service.mark_as_read(contract_id, current_user)
    return jsonify(result)


# =========================================================================
#  GET /api/contracts/<id>/messages/count
# =========================================================================
@bp.route("/<int:contract_id>/messages/count", methods=["GET"])
@login_required
def unread_count(contract_id):
    """Nombre de messages non lus."""
    count = chat_service.unread_count(contract_id, current_user)
    return jsonify({"ok": True, "count": count})


# =========================================================================
#  POST /api/contracts/<id>/messages/upload-pdf
#  Upload d'un PDF dans le chat
# =========================================================================

@bp.route("/<int:contract_id>/messages/upload-pdf", methods=["POST"])
@login_required
def upload_pdf(contract_id):
    """Upload d'un PDF dans le chat (multipart/form-data)."""
    from app.services import chat_service

    file = request.files.get("document")
    if not file or not file.filename:
        return jsonify({"ok": False, "error": "Aucun fichier."}), 400

    pdf_bytes = file.read()

    result = chat_service.send_pdf_message(
        contract_id, current_user, file.filename, pdf_bytes)

    if not result["ok"]:
        return jsonify({"ok": False, "error": result["error"]}), 400

    return jsonify({
        "ok":           True,
        "message_id":   result["message_id"],
        "filename":     result["filename"],
        "created_at":   result["created_at"],
        "sender_id":    current_user.id,
        "sender_name":  current_user.username,
        "sender_role":  current_user.role,
        "content":      result["content"],
        "message_type": "pdf",
    })


# =========================================================================
#  GET /api/contracts/messages/<id>/download
#  Téléchargement du PDF d'un message
# =========================================================================
@bp.route("/messages/<int:message_id>/download", methods=["GET"])
@login_required
def download_pdf(message_id):
    """Télécharge le PDF joint à un message (déchiffré)."""
    from app.services import chat_service

    pdf_bytes, filename = chat_service.get_pdf_bytes(message_id, current_user)
    if not pdf_bytes:
        return jsonify({"ok": False, "error": "PDF introuvable."}), 404

    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename or f"document_{message_id}.pdf",
    )