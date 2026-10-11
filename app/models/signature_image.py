from datetime import datetime
from app.extensions import db


class SignatureImage(db.Model):
    """
    Image de la signature manuscrite (dessin sur canvas).
    - Chiffrée en AES-256-GCM
    - Liée 1-1 à une ligne de la table `signatures`
    - ✅ CASCADE : si la Signature est supprimée, l'image l'est aussi
    """
    __tablename__ = "signature_images"

    id              = db.Column(db.Integer, primary_key=True)
    signature_id    = db.Column(
        db.Integer,
        db.ForeignKey("signatures.id", ondelete="CASCADE"),   # ✅ AJOUT
        nullable=False,
        unique=True,
        index=True,
    )
    encrypted_image = db.Column(db.LargeBinary, nullable=False)
    image_mime      = db.Column(db.String(30), nullable=False, default="image/png")
    image_hash      = db.Column(db.String(64), nullable=False)
    width           = db.Column(db.Integer, nullable=True)
    height          = db.Column(db.Integer, nullable=True)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    signature = db.relationship(
        "Signature",
        backref=db.backref(
            "signature_image",
            uselist=False,
            cascade="all, delete-orphan",
            passive_deletes=True,      # ✅ AJOUT
        ),
    )

    def __repr__(self):
        return f"<SignatureImage id={self.id} signature={self.signature_id}>"