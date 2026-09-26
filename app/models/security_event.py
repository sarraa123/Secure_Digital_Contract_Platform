from datetime import datetime
from app.extensions import db


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id         = db.Column(db.Integer, primary_key=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    event_type = db.Column(db.String(40), nullable=False)
    user_id    = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(45))
    endpoint   = db.Column(db.String(200))
    status     = db.Column(db.String(20))
    details    = db.Column(db.Text)