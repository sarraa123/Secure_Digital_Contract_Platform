from datetime import datetime, timezone

from app import db


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    event_type = db.Column(
        db.String(100),
        nullable=False
    )

    action = db.Column(
        db.String(255),
        nullable=False
    )

    status = db.Column(
        db.String(20),
        nullable=False
    )

    ip_address = db.Column(
        db.String(45),
        nullable=True
    )

    user_agent = db.Column(
        db.String(500),
        nullable=True
    )

    details = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    user = db.relationship(
        "User",
        backref=db.backref("audit_logs", lazy=True)
    )

    def __repr__(self):
        return (
            f"<AuditLog "
            f"id={self.id} "
            f"event_type={self.event_type} "
            f"status={self.status}>"
        )