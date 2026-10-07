from datetime import datetime

from app.extensions import db


class SignatureImage(db.Model):
    """
    Image de la signature manuscrite (dessin sur canvas).
    - Chiffrée en AES-256-GCM (même clé que les contrats)
    - Le hash SHA-256 du PNG CLAIR est stocké pour vérification d'intégrité
    - Liée 1-1 à une ligne de la table `signatures`
    """
    __tablename__ = "signature_images"

    id              = db.Column(db.Integer, primary_key=True)
    signature_id    = db.Column(db.Integer,
                                db.ForeignKey("signatures.id"),
                                nullable=False, unique=True, index=True)
    encrypted_image = db.Column(db.LargeBinary, nullable=False)
    image_mime      = db.Column(db.String(30), nullable=False, default="image/png")
    image_hash      = db.Column(db.String(64), nullable=False)
    width           = db.Column(db.Integer, nullable=True)
    height          = db.Column(db.Integer, nullable=True)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    signature = db.relationship(
        "Signature",
        backref=db.backref("signature_image", uselist=False,
                           cascade="all, delete-orphan"),
    )

    def __repr__(self):
        return f"<SignatureImage id={self.id} signature={self.signature_id}>"