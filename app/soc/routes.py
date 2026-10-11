"""
Routes du SOC (Security Operations Center).
Accessibles uniquement aux ADMIN.
"""
from datetime import datetime, timezone
import csv
import io

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, Response, abort, jsonify,
)
from flask_login import current_user

from app.extensions import db
from app.models import SecurityEvent, SOCAlert, User
from app.security import log_security_event
from app.security.authorization import admin_required
from app.security.audit_events import (
    SOC_ACCESSED, SOC_DASHBOARD_VIEWED, SOC_EVENTS_QUERIED,
    SOC_EVENT_VIEWED, SOC_EVENTS_EXPORTED,
    SOC_ALERT_VIEWED, SOC_ALERT_TRIAGED, SOC_ALERT_RESOLVED,
    SOC_ALERT_FALSE_POSITIVE, SOC_USER_TIMELINE_VIEWED,
)

from . import services
from .detection import run_detection
from .forms import EventFilterForm, AlertFilterForm


soc_bp = Blueprint(
    "soc",
    __name__,
    url_prefix="/soc",
)


# ==========================================================
# Guard : ADMIN uniquement + log d'accès
# ==========================================================
@soc_bp.before_request
@admin_required
def _log_soc_access():
    log_security_event(
        SOC_ACCESSED,
        user_id=current_user.id,
        status="SUCCESS",
        details={
            "endpoint": request.endpoint,
            "method": request.method,
        },
    )
    return None


# ==========================================================
# 1. DASHBOARD
# ==========================================================
@soc_bp.route("/dashboard")
def dashboard():
    hours = int(request.args.get("hours", 24))

    kpis = services.get_dashboard_kpis(hours=hours)
    top_ips = services.get_top_ips(limit=10, hours=hours)
    top_events = services.get_top_event_types(limit=10, hours=hours)
    top_users = services.get_top_users(limit=10, hours=hours)

    recent_alerts = (
        SOCAlert.query
        .order_by(SOCAlert.created_at.desc())
        .limit(10)
        .all()
    )

    log_security_event(
        SOC_DASHBOARD_VIEWED,
        user_id=current_user.id,
        status="SUCCESS",
        details={"window_hours": hours},
    )

    return render_template(
        "soc/dashboard.html",
        active="soc-dashboard",          # ← AJOUT ICI
        kpis=kpis,
        top_ips=top_ips,
        top_events=top_events,
        top_users=top_users,
        recent_alerts=recent_alerts,
        hours=hours,
    )


# ==========================================================
# 2. EVENTS — liste filtrée
# ==========================================================
@soc_bp.route("/events")
def events():
    form = EventFilterForm(request.args, meta={"csrf": False})

    q = SecurityEvent.query

    if form.event_type.data:
        q = q.filter(SecurityEvent.event_type.ilike(f"%{form.event_type.data}%"))

    if form.user_id.data and form.user_id.data.isdigit():
        q = q.filter(SecurityEvent.user_id == int(form.user_id.data))

    if form.ip_address.data:
        q = q.filter(SecurityEvent.ip_address == form.ip_address.data)

    if form.status.data:
        q = q.filter(SecurityEvent.status == form.status.data)

    if form.date_from.data:
        q = q.filter(SecurityEvent.timestamp >= form.date_from.data)

    if form.date_to.data:
        q = q.filter(SecurityEvent.timestamp <= form.date_to.data)

    page = request.args.get("page", 1, type=int)
    per_page = 50

    pagination = q.order_by(SecurityEvent.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # ✅ NOUVEAU : dict des filtres SANS 'page' (pour la pagination)
    filters_without_page = {
        k: v for k, v in request.args.items() if k != "page"
    }

    log_security_event(
        SOC_EVENTS_QUERIED,
        user_id=current_user.id,
        status="SUCCESS",
        details={
            "filters": {
                "event_type": form.event_type.data,
                "status": form.status.data,
                "has_ip": bool(form.ip_address.data),
                "has_user": bool(form.user_id.data),
            },
            "page": page,
        },
    )

    return render_template(
        "soc/events.html",
        active="soc-events",
        form=form,
        pagination=pagination,
        events=pagination.items,
        filters_without_page=filters_without_page,   # ✅ AJOUT
    )
# ==========================================================
# 3. EVENT DETAIL
# ==========================================================
@soc_bp.route("/events/<int:event_id>")
def event_detail(event_id):
    event = db.session.get(SecurityEvent, event_id)
    if not event:
        abort(404)

    log_security_event(
        SOC_EVENT_VIEWED,
        user_id=current_user.id,
        status="SUCCESS",
        details={"event_id": event_id},
    )

    return render_template(
        "soc/event_detail.html",
        active="soc-events",             # ← AJOUT ICI (même onglet que la liste)
        event=event,
    )


# ==========================================================
# 4. EXPORT CSV
# ==========================================================
@soc_bp.route("/events/export")
def events_export():
    form = EventFilterForm(request.args, meta={"csrf": False})
    q = SecurityEvent.query

    if form.event_type.data:
        q = q.filter(SecurityEvent.event_type.ilike(f"%{form.event_type.data}%"))
    if form.status.data:
        q = q.filter(SecurityEvent.status == form.status.data)
    if form.ip_address.data:
        q = q.filter(SecurityEvent.ip_address == form.ip_address.data)
    if form.user_id.data and form.user_id.data.isdigit():
        q = q.filter(SecurityEvent.user_id == int(form.user_id.data))

    events = q.order_by(SecurityEvent.timestamp.desc()).limit(5000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "timestamp", "event_type", "status",
        "user_id", "ip_address", "endpoint", "details",
    ])
    for e in events:
        writer.writerow([
            e.id,
            e.timestamp.isoformat() if e.timestamp else "",
            e.event_type,
            e.status,
            e.user_id or "",
            e.ip_address or "",
            e.endpoint or "",
            (e.details or "").replace("\n", " ")[:500],
        ])

    log_security_event(
        SOC_EVENTS_EXPORTED,
        user_id=current_user.id,
        status="SUCCESS",
        details={"count": len(events)},
    )

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                f"attachment; filename=soc_events_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
        },
    )


# ==========================================================
# 5. ALERTS — liste filtrée
# ==========================================================
@soc_bp.route("/alerts")
def alerts():
    form = AlertFilterForm(request.args, meta={"csrf": False})

    q = SOCAlert.query

    if form.severity.data:
        q = q.filter(SOCAlert.severity == form.severity.data)
    if form.status.data:
        q = q.filter(SOCAlert.status == form.status.data)

    alerts = q.order_by(SOCAlert.created_at.desc()).limit(200).all()

    return render_template(
        "soc/alerts.html",
        active="soc-alerts",             # ← AJOUT ICI
        form=form,
        alerts=alerts,
    )


# ==========================================================
# 6. ALERT DETAIL
# ==========================================================
@soc_bp.route("/alerts/<int:alert_id>")
def alert_detail(alert_id):
    alert = db.session.get(SOCAlert, alert_id)
    if not alert:
        abort(404)

    # Événements liés (même IP / même user dans la fenêtre)
    related_events = []
    if alert.user_id or alert.ip_address:
        q = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= alert.first_seen,
            SecurityEvent.timestamp <= alert.last_seen,
        )
        if alert.user_id:
            q = q.filter(SecurityEvent.user_id == alert.user_id)
        if alert.ip_address:
            q = q.filter(SecurityEvent.ip_address == alert.ip_address)
        related_events = q.order_by(SecurityEvent.timestamp.asc()).limit(100).all()

    log_security_event(
        SOC_ALERT_VIEWED,
        user_id=current_user.id,
        status="SUCCESS",
        details={"alert_id": alert_id},
    )

    return render_template(
        "soc/alert_detail.html",
        active="soc-alerts",             # ← AJOUT ICI (même onglet que la liste)
        alert=alert,
        related_events=related_events,
    )


# ==========================================================
# 7. ALERT ACTIONS (POST)
# ==========================================================
@soc_bp.route("/alerts/<int:alert_id>/status", methods=["POST"])
def alert_update_status(alert_id):
    alert = db.session.get(SOCAlert, alert_id)
    if not alert:
        abort(404)

    new_status = request.form.get("status", "").strip().upper()
    allowed = {"NEW", "TRIAGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}

    if new_status not in allowed:
        flash("Statut invalide.", "danger")
        return redirect(url_for("soc.alert_detail", alert_id=alert_id))

    alert.status = new_status

    if new_status == "RESOLVED":
        alert.resolved_at = datetime.now(timezone.utc)
        alert.resolved_by = current_user.id

    db.session.commit()

    event_map = {
        "TRIAGED": SOC_ALERT_TRIAGED,
        "RESOLVED": SOC_ALERT_RESOLVED,
        "FALSE_POSITIVE": SOC_ALERT_FALSE_POSITIVE,
    }
    log_security_event(
        event_map.get(new_status, SOC_ALERT_TRIAGED),
        user_id=current_user.id,
        status="SUCCESS",
        details={"alert_id": alert_id, "new_status": new_status},
    )

    flash(f"Alerte marquée comme {new_status}.", "success")
    return redirect(url_for("soc.alert_detail", alert_id=alert_id))


# ==========================================================
# 8. USER TIMELINE
# ==========================================================
@soc_bp.route("/users/<int:user_id>/timeline")
def user_timeline(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    timeline = services.get_user_timeline(user_id, limit=200)

    log_security_event(
        SOC_USER_TIMELINE_VIEWED,
        user_id=current_user.id,
        status="SUCCESS",
        details={"target_user_id": user_id},
    )

    return render_template(
        "soc/user_timeline.html",
        active="soc-events",             # ← AJOUT ICI (accessible depuis les events)
        target_user=user,
        timeline=timeline,
    )


# ==========================================================
# 9. MANUAL DETECTION RUN
# ==========================================================
@soc_bp.route("/detection/run", methods=["POST"])
def detection_run():
    result = run_detection()
    flash(
        f"Détection exécutée. "
        f"{sum(r['alerts_created'] for r in result['rules'])} alerte(s) créée(s).",
        "success",
    )
    return redirect(url_for("soc.alerts"))