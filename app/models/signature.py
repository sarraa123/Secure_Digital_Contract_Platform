from datetime import datetime
from app.extensions import db


class Signature(db.Model):
    """
    Signature cryptographique RSA-PSS-SHA256 d'un contrat.

    Stockage SÉPARÉ du blob métadonnées pour éviter le bug "signature dans
    le blob signé" : la signature doit porter sur un contenu qui ne sera
    plus modifié après.

    Références CDC :
    - CRYP-02 : intégrité cryptographique
    - CRYP-08 : anti-répudiation
    """
    __tablename__ = "signatures"

    id            = db.Column(db.Integer, primary_key=True)
    contract_id   = db.Column(db.Integer,
                              db.ForeignKey("contracts.id"),
                              nullable=False, index=True)
    signer_id     = db.Column(db.Integer,
                              db.ForeignKey("users.id"),
                              nullable=False)

    # Hash SHA-256 du contenu signé (encrypted_metadata + encrypted_file)
    document_hash = db.Column(db.String(64), nullable=False)

    # Signature RSA-PSS en Base64
    signature     = db.Column(db.Text, nullable=False)

    # Algorithme utilisé (traçabilité)
    algorithm     = db.Column(db.String(40), nullable=False,
                              default="RSA-PSS-SHA256")

    signed_at     = db.Column(db.DateTime, default=datetime.utcnow,
                              nullable=False)

    # Relations
    contract = db.relationship("Contract", backref="signatures")
    signer   = db.relationship("User")

    def __repr__(self):
        return (f"<Signature id={self.id} contract={self.contract_id} "
                f"signer={self.signer_id} algo={self.algorithm}>")