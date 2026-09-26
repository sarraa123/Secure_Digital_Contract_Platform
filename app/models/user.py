from datetime import datetime, timezone

from flask_login import UserMixin

from app import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(255),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="CLIENT"
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="PENDING"
    )

    must_change_password = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
        onupdate=lambda: datetime.now(timezone.utc)
    )

    last_login_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True
    )

    # --- Signature numérique RSA (CDC CRYP-08) ---
    private_key_encrypted = db.Column(
        db.LargeBinary,
        nullable=True
    )
    public_key_pem = db.Column(
        db.Text,
        nullable=True
    )

    def __repr__(self):
        return f"<User {self.username}>"

    @property
    def has_signing_keys(self) -> bool:
        return bool(self.private_key_encrypted and self.public_key_pem)

    # --- Affichage (sidebar / topbar communes client & employé) ---
    @property
    def name(self) -> str:
        return self.username

    @property
    def initials(self) -> str:
        parts = self.username.split()
        if len(parts) >= 2:
            return (parts[0][0] + parts[-1][0]).upper()
        if self.username:
            return self.username[:2].upper()
        return "?"