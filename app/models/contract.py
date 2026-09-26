from datetime import datetime
from app.extensions import db


class Contract(db.Model):
    """
    Toutes les données métier sont dans encrypted_metadata.
    Seul id + version + timestamps techniques restent en clair.
    """
    __tablename__ = "contracts"

    id                 = db.Column(db.Integer, primary_key=True)
    encrypted_metadata = db.Column(db.LargeBinary, nullable=False)
    encrypted_file     = db.Column(db.LargeBinary, nullable=False)
    integrity_hash     = db.Column(db.String(64), nullable=False)
    version            = db.Column(db.Integer, default=1)
    created_at         = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at         = db.Column(db.DateTime, default=datetime.utcnow,
                                   onupdate=datetime.utcnow)