from datetime import datetime, timezone

from app import db


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    event_type = db.Column(
        db.String(100),
        nullable=False,
        index=True,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    ip_address = db.Column(
        db.String(45),
        nullable=True,
        index=True,
    )

    endpoint = db.Column(
        db.String(255),
        nullable=True,
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        index=True,
    )

    details = db.Column(
        db.Text,
        nullable=True,
    )

    user = db.relationship(
        "User",
        backref=db.backref(
            "security_events",
            lazy=True,
        ),
    )

    def __repr__(self):
        return (
            f"<SecurityEvent "
            f"{self.event_type} "
            f"user_id={self.user_id} "
            f"status={self.status}>"
        )