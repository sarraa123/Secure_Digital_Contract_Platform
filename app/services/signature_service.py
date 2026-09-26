"""
Service de signature cryptographique RSA-PSS-SHA256.

- La signature porte sur le **contenu signé** :
  `encrypted_metadata + encrypted_file`
  (on signe tout le contrat chiffré — cohérent avec "on chiffre tout")

- La signature est stockée dans la table `signatures`, PAS dans le blob.
  Cela évite que la modification du blob (pour y ajouter la signature)
  n'invalide la signature elle-même.

- La clé privée du signataire reste chiffrée en base, jamais exposée.

Références CDC :
- CRYP-02 : intégrité
- CRYP-05 : RSA-3072
- CRYP-08 : anti-répudiation
"""
import base64
import hashlib
from datetime import datetime

from cryptography.exceptions import InvalidSignature

from app.extensions import db
from app.models import User, Signature
from app.services.crypto_service import (
    load_private_key, load_public_key,
    SIGNATURE_ALGORITHM,
    _PSS_PADDING,
)
from cryptography.hazmat.primitives import hashes


# =========================================================================
#  Hachage du contenu signé
# =========================================================================
def _signed_content(model) -> bytes:
    """
    Retourne les octets qui vont être signés / vérifiés :
    concaténation du blob métadonnées chiffré et du fichier chiffré.
    """
    return model.encrypted_metadata + model.encrypted_file


def _document_hash(data: bytes) -> str:
    """SHA-256 hexadécimal du contenu signé."""
    return hashlib.sha256(data).hexdigest()


# =========================================================================
#  Création d'une signature
# =========================================================================
def create_signature(contract_model, signer: User) -> Signature:
    """
    Crée et persiste une signature RSA-PSS sur le contrat chiffré.
    Lève une exception si la clé privée n'est pas disponible.
    """
    private_key = load_private_key(signer)

    data = _signed_content(contract_model)
    doc_hash = _document_hash(data)

    # Signature RSA-PSS-SHA256 sur le contenu signé
    signature_bytes = private_key.sign(data, _PSS_PADDING, hashes.SHA256())

    sig = Signature(
        contract_id   = contract_model.id,
        signer_id     = signer.id,
        document_hash = doc_hash,
        signature     = base64.b64encode(signature_bytes).decode("ascii"),
        algorithm     = SIGNATURE_ALGORITHM,
        signed_at     = datetime.utcnow(),
    )
    db.session.add(sig)
    db.session.commit()

    return sig


# =========================================================================
#  Vérification d'une signature
# =========================================================================
def verify_signature_for_contract(contract_model) -> dict:
    """
    Vérifie la signature stockée pour ce contrat.

    Retourne :
    {
        "ok": bool,
        "reason": str,
        "signer": User | None,
        "signature": Signature | None,
    }

    Raisons possibles :
      - "no_signature"        : aucune signature en base
      - "document_modified"   : le hash actuel ne correspond pas
      - "invalid_signature"   : la signature RSA-PSS ne vérifie pas
      - "signer_not_found"    : utilisateur inconnu
      - "verified"            : tout est OK
    """
    sig = (Signature.query
           .filter_by(contract_id=contract_model.id)
           .order_by(Signature.signed_at.desc())
           .first())

    if not sig:
        return {"ok": False, "reason": "no_signature",
                "signer": None, "signature": None}

    signer = db.session.get(User, sig.signer_id)
    if not signer or not signer.public_key_pem:
        return {"ok": False, "reason": "signer_not_found",
                "signer": signer, "signature": sig}

    # 1. Le hash du contenu actuel doit correspondre
    current_data = _signed_content(contract_model)
    current_hash = _document_hash(current_data)

    if current_hash != sig.document_hash:
        return {"ok": False, "reason": "document_modified",
                "signer": signer, "signature": sig}

    # 2. La signature RSA-PSS doit vérifier
    try:
        public_key = load_public_key(signer)
        public_key.verify(
            base64.b64decode(sig.signature),
            current_data,
            _PSS_PADDING,
            hashes.SHA256(),
        )
        return {"ok": True, "reason": "verified",
                "signer": signer, "signature": sig}
    except InvalidSignature:
        return {"ok": False, "reason": "invalid_signature",
                "signer": signer, "signature": sig}
    except Exception:
        return {"ok": False, "reason": "invalid_signature",
                "signer": signer, "signature": sig}