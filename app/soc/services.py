"""
Agrégations et statistiques pour le SOC.

Point clé : les utilisateurs sont classés par SCORE DE RISQUE pondéré,
et non par simple comptage d'événements.
"""
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, desc

from app.extensions import db
from app.models import SecurityEvent, SOCAlert, User


# ==========================================================
# Pondération par type d'événement
# ==========================================================
SEVERITY_WEIGHTS = {
    # --- CRITIQUE (10) ---
    "INTEGRITY_FAILURE":        10,
    "SESSION_HIJACK":           10,
    "LOG_TAMPERING":            10,

    # --- HAUTE (5) ---
    "BRUTE_FORCE":              5,
    "UNAUTHORIZED_ACCESS":      5,
    "PRIVILEGE_CHANGE":         5,
    "SUSPICIOUS_ACTIVITY":      5,

    # --- MOYENNE (3) ---
    "LOGIN_FAILED":             3,
    "ACCOUNT_SUSPENDED":        3,

    # --- BASSE (1) ---
    "MFA_LOGIN_FAILED":         1,
    "MFA_SETUP_FAILED":         1,
    "PASSWORD_CHANGE_FAILED":   1,
    "SESSION_INVALID":          1,
    "SESSION_EXPIRED":          1,
}

# Poids par défaut si l'événement n'est pas listé
DEFAULT_WEIGHT = 1

# Seuil minimal pour apparaître dans "Utilisateurs à risque"
MIN_RISK_SCORE = 3


# ==========================================================
# IPs locales à ignorer dans le classement (bruit localhost)
# ==========================================================
IGNORED_IPS = {
    "127.0.0.1",
    "::1",
    "localhost",
    "0.0.0.0",
}


# ==========================================================
# KPIs du dashboard
# ==========================================================
def get_dashboard_kpis(hours: int = 24) -> dict:
    """Calcule les indicateurs clés sur les dernières N heures."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    base = SecurityEvent.query.filter(SecurityEvent.timestamp >= since)

    total_events = base.count()

    by_status = dict(
        db.session.query(
            SecurityEvent.status, func.count(SecurityEvent.id)
        )
        .filter(SecurityEvent.timestamp >= since)
        .group_by(SecurityEvent.status)
        .all()
    )

    failed_logins = base.filter(
        SecurityEvent.event_type == "LOGIN_FAILED"
    ).count()

    brute_force = base.filter(
        SecurityEvent.event_type == "BRUTE_FORCE"
    ).count()

    unauth = base.filter(
        SecurityEvent.event_type == "UNAUTHORIZED_ACCESS"
    ).count()

    mfa_failures = base.filter(
        SecurityEvent.event_type.in_(
            ["MFA_LOGIN_FAILED", "MFA_SETUP_FAILED"]
        )
    ).count()

    integrity_failures = base.filter(
        SecurityEvent.event_type == "INTEGRITY_FAILURE"
    ).count()

    session_expired = base.filter(
        SecurityEvent.event_type.in_(["SESSION_EXPIRED", "SESSION_INVALID"])
    ).count()

    open_alerts = SOCAlert.query.filter(
        SOCAlert.status.in_(["NEW", "TRIAGED", "INVESTIGATING"])
    ).count()

    critical_alerts = SOCAlert.query.filter_by(
        severity="CRITICAL",
        status="NEW",
    ).count()

    return {
        "window_hours": hours,
        "total_events": total_events,
        "by_status": by_status,
        "failed_logins": failed_logins,
        "brute_force": brute_force,
        "unauthorized": unauth,
        "mfa_failures": mfa_failures,
        "integrity_failures": integrity_failures,
        "session_expired": session_expired,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
    }


# ==========================================================
# Top IPs — exclut les IPs locales
# ==========================================================
def get_top_ips(limit: int = 10, hours: int = 24) -> list:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = (
        db.session.query(
            SecurityEvent.ip_address,
            func.count(SecurityEvent.id).label("cnt"),
        )
        .filter(
            SecurityEvent.timestamp >= since,
            SecurityEvent.ip_address.isnot(None),
            SecurityEvent.ip_address != "unknown",
            ~SecurityEvent.ip_address.in_(IGNORED_IPS),   # ← exclusion localhost
            SecurityEvent.status.in_(["FAILURE", "DENIED", "CRITICAL"]),
        )
        .group_by(SecurityEvent.ip_address)
        .order_by(desc("cnt"))
        .limit(limit)
        .all()
    )
    return [{"ip": r[0], "count": r[1]} for r in rows]


# ==========================================================
# Top Event Types
# ==========================================================
def get_top_event_types(limit: int = 10, hours: int = 24) -> list:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = (
        db.session.query(
            SecurityEvent.event_type,
            func.count(SecurityEvent.id).label("cnt"),
        )
        .filter(SecurityEvent.timestamp >= since)
        .group_by(SecurityEvent.event_type)
        .order_by(desc("cnt"))
        .limit(limit)
        .all()
    )
    return [{"event_type": r[0], "count": r[1]} for r in rows]


# ==========================================================
# TOP USERS — Score de risque pondéré
# ==========================================================
def get_top_users(limit: int = 10, hours: int = 24) -> list:
    """
    Retourne les utilisateurs classés par SCORE DE RISQUE pondéré.

    Principe :
      - Chaque type d'événement a un poids (voir SEVERITY_WEIGHTS)
      - On somme les poids de tous les événements à risque d'un utilisateur
      - On exclut les comptes ADMIN (utilisateurs de confiance)
      - On filtre les scores < MIN_RISK_SCORE (évite le bruit)
    """
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # --- 1. Récupérer tous les événements à risque
    events = (
        SecurityEvent.query
        .filter(
            SecurityEvent.timestamp >= since,
            SecurityEvent.user_id.isnot(None),
            SecurityEvent.status.in_(["FAILURE", "DENIED", "CRITICAL"]),
        )
        .all()
    )

    # --- 2. Agréger par utilisateur
    users_data: dict[int, dict] = {}

    for e in events:
        uid = e.user_id
        if uid is None:
            continue

        weight = SEVERITY_WEIGHTS.get(e.event_type, DEFAULT_WEIGHT)

        if uid not in users_data:
            users_data[uid] = {
                "score": 0,
                "event_count": 0,
                "events_breakdown": {},
            }

        users_data[uid]["score"] += weight
        users_data[uid]["event_count"] += 1
        users_data[uid]["events_breakdown"][e.event_type] = (
            users_data[uid]["events_breakdown"].get(e.event_type, 0) + 1
        )

    # --- 3. Filtrer : score suffisant + exclure ADMIN
    results = []
    for uid, data in users_data.items():
        if data["score"] < MIN_RISK_SCORE:
            continue

        user = db.session.get(User, uid)
        if not user:
            continue

        if user.role == "ADMIN":
            continue

        top_events = dict(
            sorted(
                data["events_breakdown"].items(),
                key=lambda x: x[1],
                reverse=True,
            )[:3]
        )

        results.append({
            "user_id": uid,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "score": data["score"],
            "event_count": data["event_count"],
            "top_events": top_events,
        })

    # --- 4. Trier par score décroissant
    results.sort(key=lambda x: x["score"], reverse=True)

    return results[:limit]


# ==========================================================
# Timeline utilisateur
# ==========================================================
def get_user_timeline(user_id: int, limit: int = 200) -> list:
    events = (
        SecurityEvent.query
        .filter_by(user_id=user_id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [_serialize_event(e) for e in events]


def _serialize_event(e: SecurityEvent) -> dict:
    details = None
    if e.details:
        try:
            details = json.loads(e.details)
        except Exception:
            details = {"raw": e.details}

    return {
        "id": e.id,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "event_type": e.event_type,
        "status": e.status,
        "user_id": e.user_id,
        "ip_address": e.ip_address,
        "endpoint": e.endpoint,
        "details": details,
    }