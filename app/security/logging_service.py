"""
Logging de sécurité unifié.
ATTENTION : ne jamais passer de contenu métier en clair dans details.
Accepte : IDs, types d'événement, raisons courtes.
"""
import json
from flask import request

from app.extensions import db
from app.models import SecurityEvent


def log_event(event_type: str, user_id=None, status="OK", details=None):
    """
    Enregistre un événement de sécurité.
    - Si `details` est un dict, il est sérialisé en JSON.
    - Si c'est déjà une string, elle est conservée telle quelle.
    """
    if details is None:
        details = {}

    if not isinstance(details, str):
        details = json.dumps(details, ensure_ascii=False, default=str)

    db.session.add(SecurityEvent(
        event_type=event_type,
        user_id=user_id,
        ip_address=request.remote_addr if request else None,
        endpoint=request.path if request else None,
        status=status,
        details=details,
    ))
    db.session.commit()