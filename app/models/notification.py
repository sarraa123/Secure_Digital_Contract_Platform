from datetime import datetime
from app.extensions import db


class Notification(db.Model):
    """
    Notification in-app destinée à un utilisateur.

    Champs :
      - user_id        : destinataire
      - event_type     : ex. "contract.signed", "contract.shared"
      - title          : titre court
      - message        : texte descriptif
      - link           : URL relative (ex: /client/contracts/4)
      - contract_id    : contrat concerné (optionnel)
      - actor_id       : utilisateur à l'origine (optionnel)
      - read_at        : NULL si non lue, datetime si lue
      - created_at     : date de création
    """
    __tablename__ = "notifications"

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"),
                            nullable=False, index=True)
    event_type  = db.Column(db.String(50), nullable=False)
    title       = db.Column(db.String(200), nullable=False)
    message     = db.Column(db.Text, nullable=True)
    link        = db.Column(db.String(300), nullable=True)
    contract_id = db.Column(db.Integer, db.ForeignKey("contracts.id"),
                            nullable=True)
    actor_id    = db.Column(db.Integer, db.ForeignKey("users.id"),
                            nullable=True)
    read_at     = db.Column(db.DateTime, nullable=True, index=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow,
                            nullable=False, index=True)

    # Relations
    user  = db.relationship("User", foreign_keys=[user_id],
                            backref="notifications")
    actor = db.relationship("User", foreign_keys=[actor_id])

    @property
    def is_read(self) -> bool:
        return self.read_at is not None

    def __repr__(self):
        return f"<Notification id={self.id} user={self.user_id} type={self.event_type}>"