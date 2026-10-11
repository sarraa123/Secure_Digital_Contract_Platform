from datetime import datetime
from app.extensions import db


class Signature(db.Model):
    """
    Signature cryptographique RSA-PSS-SHA256 d'un contrat.
    Stockage séparé du blob métadonnées.

    ✅ CASCADE : si le contrat est supprimé, la signature l'est aussi.
    """
    __tablename__ = "signatures"

    id            = db.Column(db.Integer, primary_key=True)
    contract_id   = db.Column(
        db.Integer,
        db.ForeignKey("contracts.id", ondelete="CASCADE"),   # ✅ AJOUT
        nullable=False,
        index=True,
    )
    signer_id     = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
    )
    document_hash = db.Column(db.String(64), nullable=False)
    signature     = db.Column(db.Text, nullable=False)
    algorithm     = db.Column(db.String(40), nullable=False,
                              default="RSA-PSS-SHA256")
    signed_at     = db.Column(db.DateTime, default=datetime.utcnow,
                              nullable=False)

    contract = db.relationship(
        "Contract",
        backref=db.backref("signatures",
                           cascade="all, delete-orphan",
                           passive_deletes=True),      # ✅ AJOUT
    )
    signer   = db.relationship("User")

    def __repr__(self):
        return (f"<Signature id={self.id} contract={self.contract_id} "
                f"signer={self.signer_id} algo={self.algorithm}>")