"""Affiche l'état de la base : users, contrats déchiffrés, événements."""
from app import create_app
from app.models import Contract, SecurityEvent, User
from app.services.contract_service import list_contracts_for_user

app = create_app()


def show_users():
    print("══════════ USERS ══════════")
    for u in User.query.order_by(User.id).all():
        print(f"  [{u.id}] {u.username:20s} {u.email:30s} {u.role}")
    print()


def show_contracts():
    print("══════════ CONTRACTS (déchiffrés côté serveur) ══════════")
    manager = User.query.filter_by(email="manager@secure.local").first()
    if not manager:
        print("  (aucun manager — base non seedée)")
        return
    items = list_contracts_for_user(manager)
    if not items:
        print("  (aucun contrat)")
        print()
        return
    for c in items:
        print(f"  [{c.id}] {c.title}")
        print(f"      status    : {c.status}")
        print(f"      owner     : {c.owner_name}")
        print(f"      client    : {c.client_name}")
        print(f"      type      : {c.contract_type}")
        print(f"      dates     : {c.start_date_str} → {c.end_date_str}")
        print(f"      version   : {c.version}")
        print(f"      integrity : {c.integrity}")
        print()


def show_events():
    print("══════════ SECURITY EVENTS ══════════")
    events = (SecurityEvent.query
              .order_by(SecurityEvent.id.desc())
              .limit(20).all())
    if not events:
        print("  (aucun événement)")
        print()
        return
    for e in events:
        ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "—"
        print(f"  {ts}  {e.event_type:20s} {e.status:4s}  {e.details or ''}")
    print()


if __name__ == "__main__":
    with app.app_context():
        show_users()
        show_contracts()
        show_events()
