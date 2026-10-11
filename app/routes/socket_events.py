"""
Événements WebSocket pour le chat temps réel.

Chaque client rejoint une room "contract_<id>" pour recevoir
les messages en temps réel.

Sécurité :
  - Authentification via session Flask-Login
  - Vérification RBAC à chaque événement
  - Chiffrement AES-GCM pour les messages
"""
from flask import request
from flask_login import current_user
from flask_socketio import join_room, leave_room, emit, disconnect

from app.extensions import db
from app.models import User, Contract
from app.services import chat_service


def init_socket_events(socketio):
    """Enregistre tous les événements WebSocket."""

    # =====================================================================
    #  Helpers internes
    # =====================================================================
    def _get_current_user():
        """Récupère l'utilisateur connecté (via Flask-Login)."""
        try:
            if current_user and current_user.is_authenticated:
                return current_user
        except Exception:
            pass
        return None

    def _room_name(contract_id):
        return f"contract_{contract_id}"

    # =====================================================================
    #  Événement : join_chat
    #  Rejoindre la room d'un contrat
    # =====================================================================
    @socketio.on("join_chat")
    def on_join_chat(data):
        user = _get_current_user()
        if not user:
            emit("error", {"message": "Non authentifié."})
            return

        try:
            contract_id = int(data.get("contract_id"))
        except (TypeError, ValueError):
            emit("error", {"message": "contract_id invalide."})
            return

        # Vérifier l'accès
        if not chat_service._user_can_access(contract_id, user):
            emit("error", {"message": "Accès non autorisé."})
            return

        room = _room_name(contract_id)
        join_room(room)

        # Confirmer au client
        emit("joined", {
            "contract_id": contract_id,
            "room":        room,
            "user_name":   user.username,
        })

        # Informer les autres qu'un utilisateur a rejoint
        emit("user_joined", {
            "user_id":   user.id,
            "user_name": user.username,
        }, room=room, skip_sid=request.sid)


    # =====================================================================
    #  Événement : leave_chat
    # =====================================================================
    @socketio.on("leave_chat")
    def on_leave_chat(data):
        user = _get_current_user()
        if not user:
            return

        try:
            contract_id = int(data.get("contract_id"))
        except (TypeError, ValueError):
            return

        room = _room_name(contract_id)
        leave_room(room)

        emit("user_left", {
            "user_id":   user.id,
            "user_name": user.username,
        }, room=room)


    # =====================================================================
    #  Événement : send_message
    #  Envoi d'un message + diffusion à la room
    # =====================================================================
    @socketio.on("send_message")
    def on_send_message(data):
        user = _get_current_user()
        if not user:
            emit("error", {"message": "Non authentifié."})
            return

        try:
            contract_id = int(data.get("contract_id"))
        except (TypeError, ValueError):
            emit("error", {"message": "contract_id invalide."})
            return

        content = (data.get("content") or "").strip()
        if not content:
            emit("error", {"message": "Message vide."})
            return

        # Utiliser le service (chiffrement + RBAC + verrouillage)
        result = chat_service.send_message(contract_id, user, content)

        if not result.get("ok"):
            emit("error", {"message": result.get("error", "Erreur.")})
            return

        # Diffuser à tous les membres de la room
        room = _room_name(contract_id)
        emit("new_message", {
            "id":            result["message_id"],
            "contract_id":   contract_id,
            "sender_id":     user.id,
            "sender_role":   user.role,
            "sender_name":   user.username,
            "content":       content,
            "message_type":  "text",
            "created_at":    result["created_at"],
        }, room=room)


    # =====================================================================
    #  Événement : typing
    #  Indicateur "X est en train d'écrire…"
    # =====================================================================
    @socketio.on("typing")
    def on_typing(data):
        user = _get_current_user()
        if not user:
            return

        try:
            contract_id = int(data.get("contract_id"))
        except (TypeError, ValueError):
            return

        is_typing = bool(data.get("is_typing"))

        room = _room_name(contract_id)
        emit("user_typing", {
            "user_id":    user.id,
            "user_name":  user.username,
            "is_typing":  is_typing,
        }, room=room, skip_sid=request.sid)


    # =====================================================================
    #  Événement : mark_read
    # =====================================================================
    @socketio.on("mark_read")
    def on_mark_read(data):
        user = _get_current_user()
        if not user:
            return

        try:
            contract_id = int(data.get("contract_id"))
        except (TypeError, ValueError):
            return

        result = chat_service.mark_as_read(contract_id, user)

        # Notifier la room (les autres voient "lu")
        room = _room_name(contract_id)
        emit("messages_read", {
            "user_id":  user.id,
            "count":    result.get("updated", 0),
        }, room=room)


    # =====================================================================
    #  Déconnexion
    # =====================================================================
    @socketio.on("disconnect")
    def on_disconnect():
        # Flask-SocketIO nettoie automatiquement les rooms
        pass