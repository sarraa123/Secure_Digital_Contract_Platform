"""
Modèle d'alerte SOC.
Une alerte est créée par le moteur de détection à partir
d'un ensemble d'événements de sécurité corrélés.
"""
from datetime import datetime, timezone

from app.extensions import db


class SOCAlert(db.Model):
    __tablename__ = "soc_alerts"

    id = db.Column(db.Integer, primary_key=True)

    # Règle déclenchée
    rule_name = db.Column(db.String(80), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)
    # LOW | MEDIUM | HIGH | CRITICAL

    # Cycle de vie
    status = db.Column(db.String(20), nullable=False, default="NEW", index=True)
    # NEW | TRIAGED | INVESTIGATING | RESOLVED | FALSE_POSITIVE

    # Acteurs concernés (nullable : une attaque peut cibler plusieurs users)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)

    # Résumé
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # Statistiques
    event_count = db.Column(db.Integer, nullable=False, default=1)

    # Détails techniques (JSON sérialisé)
    details = db.Column(db.Text, nullable=True)

    # Fenêtre temporelle
    first_seen = db.Column(db.DateTime(timezone=True), nullable=False)
    last_seen = db.Column(db.DateTime(timezone=True), nullable=False)

    # Résolution
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # Traçabilité
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # Relations
    user = db.relationship("User", foreign_keys=[user_id],
                           backref="soc_alerts")
    resolver = db.relationship("User", foreign_keys=[resolved_by])

    def __repr__(self):
        return (f"<SOCAlert {self.rule_name} severity={self.severity} "
                f"status={self.status}>")