from datetime import datetime
from app.extensions import db


class Contract(db.Model):
    """
    Toutes les données métier sont dans encrypted_metadata.
    Seul id + version + timestamps techniques restent en clair.

    Nouveaux champs (Phase 2) :
      - parent_contract_id : si ce contrat est un avenant, pointe vers l'original
      - is_amendment       : True si c'est un avenant (flag rapide)
    """
    __tablename__ = "contracts"

    id                 = db.Column(db.Integer, primary_key=True)
    encrypted_metadata = db.Column(db.LargeBinary, nullable=False)
    encrypted_file     = db.Column(db.LargeBinary, nullable=False)
    integrity_hash     = db.Column(db.String(64), nullable=False)
    version            = db.Column(db.Integer, default=1)
    created_at         = db.Column(db.DateTime, default=datetime.utcnow,
                                   index=True)
    updated_at         = db.Column(db.DateTime, default=datetime.utcnow,
                                   onupdate=datetime.utcnow)

    # --- Avenants (Phase 2) ---
    parent_contract_id = db.Column(
        db.Integer,
        db.ForeignKey("contracts.id"),
        nullable=True,
        index=True,
    )
    is_amendment = db.Column(db.Boolean, default=False, nullable=False)

    # Relation self-referencing
    parent = db.relationship(
        "Contract",
        remote_side=[id],
        backref=db.backref("amendments", lazy="dynamic"),
    )

    def __repr__(self):
        return f"<Contract id={self.id} v{self.version} " \
               f"amendment={self.is_amendment}>"