from datetime import datetime
from app.extensions import db


class ContractMessage(db.Model):
    """
    Message dans le chat d'un contrat.

    Le contenu est chiffré AES-256-GCM (comme les métadonnées contrat).
    Peut contenir un PDF joint (chiffré AES-GCM).

    Champs :
      - contract_id         : contrat concerné
      - sender_id           : utilisateur qui a envoyé (NULL si système)
      - sender_role         : "CLIENT" | "MANAGER" | "ADMIN" | "SYSTEM"
      - encrypted_content   : contenu chiffré (AES-GCM)
      - message_type        : "text" | "system" | "pdf"
      - read_by             : liste JSON d'IDs utilisateurs qui ont lu
      - created_at          : date d'envoi
      - attachment_encrypted: PDF chiffré joint (optionnel)
      - attachment_filename : nom du fichier PDF original
      - attachment_hash     : SHA-256 du PDF clair (vérification intégrité)
    """
    __tablename__ = "contract_messages"

    id                = db.Column(db.Integer, primary_key=True)
    contract_id       = db.Column(
        db.Integer,
        db.ForeignKey("contracts.id"),
        nullable=False,
        index=True,
    )
    sender_id         = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True,  # Nullable pour les messages système
    )
    sender_role       = db.Column(db.String(20), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    message_type      = db.Column(db.String(20), nullable=False, default="text")
    read_by           = db.Column(db.Text, nullable=True)  # JSON encodé
    created_at        = db.Column(db.DateTime, default=datetime.utcnow,
                                  nullable=False, index=True)

    # --- PDF joint (nouveau) ---
    attachment_encrypted = db.Column(db.LargeBinary, nullable=True)
    attachment_filename  = db.Column(db.String(255), nullable=True)
    attachment_hash      = db.Column(db.String(64), nullable=True)

    # Relations
    contract = db.relationship(
        "Contract",
        backref=db.backref("messages", lazy="dynamic",
                           cascade="all, delete-orphan"),
    )
    sender = db.relationship("User", foreign_keys=[sender_id])

    def __repr__(self):
        return f"<ContractMessage id={self.id} contract={self.contract_id} " \
               f"role={self.sender_role} type={self.message_type}>"