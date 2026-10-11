import json
from datetime import datetime, timezone

from flask import request

from app import db
from app.models import SecurityEvent


def log_security_event(
    event_type,
    user_id=None,
    status="INFO",
    details=None,
    ip_address=None,
    endpoint=None,
):
    """
    Enregistre un événement de sécurité dans security_events.

    IMPORTANT :
    Ne jamais envoyer de mot de passe, hash, secret MFA,
    code TOTP, recovery code ou cookie de session dans details.
    """

    if ip_address is None:
        ip_address = request.remote_addr or "unknown"

    if endpoint is None:
        endpoint = request.endpoint

    if details is None:
        details = {}

    serialized_details = json.dumps(
        details,
        ensure_ascii=False,
        default=str,
    )

    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        event_type=event_type,
        user_id=user_id,
        ip_address=ip_address,
        endpoint=endpoint,
        status=status,
        details=serialized_details,
    )

    db.session.add(event)
    db.session.commit()

    return event