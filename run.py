from flask import request

from app import create_app, db
from app.models.user import User

app = create_app()
# ---------------------------------------------------------------------------
# Contexte global : layout + utilisateur courant (mock)
# ---------------------------------------------------------------------------
@app.context_processor
def inject_layout():
    path = request.path

    if path.startswith("/client"):
        layout = "client"
        u = User.query.filter_by(email="alice@partner.com").first()
    else:
        layout = "employee"
        u = User.query.filter_by(email="manager@secure.local").first()

    if not u:
        u = User.query.first()

    if not u:
        return {
            "layout": layout,
            "user": {"name": "Anonyme", "role": "—",
                     "email": "—", "initials": "??"},
        }

    initials = "".join(p[0] for p in u.username.split())[:2].upper()
    return {
        "layout": layout,
        "user": {
            "name":     u.username,
            "role":     u.role,
            "email":    u.email,
            "initials": initials,
        },
    }

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Crée les tables si elles n'existent pas
    app.run(debug=True)