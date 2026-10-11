from datetime import datetime
from app.extensions import db


class ContractPermission(db.Model):
    __tablename__ = "contract_permissions"

    id          = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer,
                            db.ForeignKey("contracts.id"),
                            nullable=False)
    user_id     = db.Column(db.Integer,
                            db.ForeignKey("users.id"),
                            nullable=False)
    permission  = db.Column(db.String(20), nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)