"""
Moteur de détection SOC.
Analyse les SecurityEvent récents et crée des SOCAlert
selon des règles prédéfinies.

Appelé :
  - À la demande via /soc/detection/run
  - Optionnellement en tâche de fond (APScheduler)
"""
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import func

from app.extensions import db
from app.models import SecurityEvent, SOCAlert
from app.security import log_event
from app.security.audit_events import SOC_ALERT_CREATED


# ==========================================================
# Règles de détection
# ==========================================================
RULES = [
    {
        "name": "brute_force_login",
        "severity": "HIGH",
        "event_type": "LOGIN_FAILED",
        "threshold": 5,
        "window_minutes": 5,
        "group_by": ["ip_address", "user_id"],
        "title": "Tentative de force brute",
        "description": "Trop d'échecs de connexion en peu de temps.",
    },
    {
        "name": "mfa_failure_burst",
        "severity": "MEDIUM",
        "event_type": "MFA_LOGIN_FAILED",
        "threshold": 3,
        "window_minutes": 5,
        "group_by": ["user_id"],
        "title": "Échecs MFA répétés",
        "description": "Plusieurs codes MFA invalides en peu de temps.",
    },
    {
        "name": "unauthorized_access_spike",
        "severity": "HIGH",
        "event_type": "UNAUTHORIZED_ACCESS",
        "threshold": 10,
        "window_minutes": 10,
        "group_by": ["user_id"],
        "title": "Tentatives d'accès non autorisé",
        "description": "Nombre anormal d'accès refusés.",
    },
    {
        "name": "integrity_failure",
        "severity": "CRITICAL",
        "event_type": "INTEGRITY_FAILURE",
        "threshold": 1,
        "window_minutes": 60,
        "group_by": [],
        "title": "Échec d'intégrité détecté",
        "description": "Un document a été altéré — action immédiate requise.",
    },
    {
        "name": "session_hijack_suspect",
        "severity": "HIGH",
        "event_type": "SESSION_INVALID",
        "threshold": 5,
        "window_minutes": 15,
        "group_by": ["user_id"],
        "title": "Sessions invalides répétées",
        "description": "Possibles tentatives de détournement de session.",
    },
]


# ==========================================================
# Exécution
# ==========================================================
def run_detection() -> dict:
    """
    Exécute toutes les règles et crée les alertes correspondantes.
    Évite les doublons : une alerte active récente pour la même
    règle + même cible n'est pas recréée.
    """
    results = []

    for rule in RULES:
        created = _run_rule(rule)
        results.append({"rule": rule["name"], "alerts_created": created})

    return {"ok": True, "rules": results}


def _run_rule(rule: dict) -> int:
    """
    Exécute une règle. Retourne le nombre d'alertes créées.
    """
    window_start = datetime.now(timezone.utc) - timedelta(
        minutes=rule["window_minutes"]
    )

    base_query = SecurityEvent.query.filter(
        SecurityEvent.timestamp >= window_start,
        SecurityEvent.event_type == rule["event_type"],
    )

    group_by = rule.get("group_by", [])

    # Cas 1 : pas de groupement
    if not group_by:
        count = base_query.count()
        if count >= rule["threshold"]:
            if _should_alert(rule["name"], user_id=None, ip=None):
                _create_alert(
                    rule=rule,
                    user_id=None,
                    ip_address=None,
                    event_count=count,
                    window_start=window_start,
                )
                return 1
        return 0

    # Cas 2 : groupement par IP + user
    group_cols = []
    if "ip_address" in group_by:
        group_cols.append(SecurityEvent.ip_address)
    if "user_id" in group_by:
        group_cols.append(SecurityEvent.user_id)

    rows = (
        db.session.query(*group_cols, func.count(SecurityEvent.id))
        .filter(
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.event_type == rule["event_type"],
        )
        .group_by(*group_cols)
        .having(func.count(SecurityEvent.id) >= rule["threshold"])
        .all()
    )

    created = 0
    for row in rows:
        *targets, count = row
        user_id = None
        ip = None
        for i, col in enumerate(group_cols):
            if col.key == "ip_address":
                ip = targets[i]
            elif col.key == "user_id":
                user_id = targets[i]

        if _should_alert(rule["name"], user_id=user_id, ip=ip):
            _create_alert(
                rule=rule,
                user_id=user_id,
                ip_address=ip,
                event_count=count,
                window_start=window_start,
            )
            created += 1

    return created


def _should_alert(rule_name: str, user_id, ip, cooldown_minutes: int = 30) -> bool:
    """
    Évite les doublons : pas de nouvelle alerte si une alerte active
    existe déjà pour cette règle + cible dans la fenêtre de cooldown.
    """
    since = datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)

    q = SOCAlert.query.filter(
        SOCAlert.rule_name == rule_name,
        SOCAlert.created_at >= since,
        SOCAlert.status.in_(["NEW", "TRIAGED", "INVESTIGATING"]),
    )
    if user_id is not None:
        q = q.filter(SOCAlert.user_id == user_id)
    else:
        q = q.filter(SOCAlert.user_id.is_(None))

    if ip is not None:
        q = q.filter(SOCAlert.ip_address == ip)
    else:
        q = q.filter(SOCAlert.ip_address.is_(None))

    return q.first() is None


def _create_alert(rule, user_id, ip_address, event_count, window_start):
    """Crée une SOCAlert + événement SOC_ALERT_CREATED."""
    now = datetime.now(timezone.utc)

    alert = SOCAlert(
        rule_name=rule["name"],
        severity=rule["severity"],
        status="NEW",
        user_id=user_id,
        ip_address=ip_address,
        title=rule["title"],
        description=rule["description"],
        event_count=event_count,
        details=json.dumps({
            "threshold": rule["threshold"],
            "window_minutes": rule["window_minutes"],
        }),
        first_seen=window_start,
        last_seen=now,
    )
    db.session.add(alert)
    db.session.commit()

    log_event(
        SOC_ALERT_CREATED,
        user_id=user_id,
        status="WARNING",
        details={
            "rule": rule["name"],
            "severity": rule["severity"],
            "alert_id": alert.id,
            "event_count": event_count,
        },
    )

    return alert