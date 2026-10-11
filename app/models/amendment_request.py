from datetime import datetime
from app.extensions import db


class AmendmentRequest(db.Model):
    """
    Demande de modification d'un contrat signé (avenant).

    Cycle de vie :
      PENDING      → demande créée, en attente de négociation
      NEGOTIATING  → discussion en cours
      AGREED       → résumé IA validé par le manager
      APPLIED      → avenant créé (nouveau contrat lié)
      REJECTED     → refusé par le manager
    """
    __tablename__ = "amendment_requests"

    id                     = db.Column(db.Integer, primary_key=True)
    original_contract_id   = db.Column(
        db.Integer,
        db.ForeignKey("contracts.id"),
        nullable=False,
        index=True,
    )
    amendment_contract_id  = db.Column(
        db.Integer,
        db.ForeignKey("contracts.id"),
        nullable=True,
        index=True,
    )
    requested_by           = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
    )
    status                 = db.Column(
        db.String(20),
        nullable=False,
        default="PENDING",
    )
    encrypted_summary      = db.Column(db.LargeBinary, nullable=True)
    encrypted_modifications = db.Column(db.LargeBinary, nullable=True)
    created_at             = db.Column(db.DateTime, default=datetime.utcnow,
                                       nullable=False, index=True)
    resolved_at            = db.Column(db.DateTime, nullable=True)

    # Relations
    original_contract = db.relationship(
        "Contract",
        foreign_keys=[original_contract_id],
        backref=db.backref("amendment_requests", lazy="dynamic"),
    )
    amendment_contract = db.relationship(
        "Contract",
        foreign_keys=[amendment_contract_id],
    )
    requester = db.relationship("User", foreign_keys=[requested_by])

    def __repr__(self):
        return f"<AmendmentRequest id={self.id} " \
               f"original={self.original_contract_id} " \
               f"status={self.status}>"