from flask import request

from app.extensions import db
from app.models import SecurityEvent


def log_event(event_type: str, user_id=None, status="OK", details=None):
    """
    ATTENTION : ne jamais passer de contenu metier en clair dans details.
    Accepte : IDs, types d'evenement, raisons courtes.
    """
    db.session.add(SecurityEvent(
        event_type=event_type,
        user_id=user_id,
        ip_address=request.remote_addr if request else None,
        endpoint=request.path if request else None,
        status=status,
        details=details,
    ))
    db.session.commit()
