from datetime import datetime, timezone

from app import db


class MFARecoveryCode(db.Model):
    __tablename__ = "mfa_recovery_codes"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    code_hash = db.Column(
        db.String(255),
        nullable=False
    )

    used_at = db.Column(
        db.DateTime,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    user = db.relationship(
        "User",
        backref=db.backref(
            "mfa_recovery_codes",
            lazy=True
        )
    )