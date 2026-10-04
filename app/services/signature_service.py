"""
Service de signature cryptographique RSA-PSS-SHA256.
- La signature porte sur `encrypted_metadata + encrypted_file`.
- La signature est stockée dans la table `signatures`, PAS dans le blob.
- L'image manuscrite (si fournie) est stockée dans `signature_images`.

Références CDC :
- CRYP-02 : intégrité
- CRYP-05 : RSA-3072
- CRYP-08 : anti-répudiation
"""
import base64
import hashlib
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

from app.extensions import db
from app.models import User, Signature, SignatureImage
from app.services import signature_image_service
from app.services.crypto_service import (
    load_private_key, load_public_key,
    SIGNATURE_ALGORITHM,
    _PSS_PADDING,
)


# =========================================================================
#  Hachage du contenu signé
# =========================================================================
def _signed_content(model) -> bytes:
    """Contenu signé : encrypted_metadata + encrypted_file."""
    return model.encrypted_metadata + model.encrypted_file


def _document_hash(data: bytes) -> str:
    """SHA-256 hexadécimal du contenu signé."""
    return hashlib.sha256(data).hexdigest()


# =========================================================================
#  Création d'une signature
# =========================================================================
def create_signature(contract_model, signer: User,
                     png_bytes: bytes = None) -> Signature:
    """
    Crée et persiste une signature RSA-PSS sur le contrat chiffré.
    Si `png_bytes` est fourni, crée en plus une SignatureImage chiffrée.
    """
    private_key = load_private_key(signer)

    data = _signed_content(contract_model)
    doc_hash = _document_hash(data)

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
    db.session.flush()   # pour avoir sig.id

    if png_bytes:
        w, h = signature_image_service._png_dimensions(png_bytes)
        img = SignatureImage(
            signature_id    = sig.id,
            encrypted_image = signature_image_service.encrypt_image(png_bytes),
            image_mime      = "image/png",
            image_hash      = signature_image_service.sha256_hex(png_bytes),
            width           = w,
            height          = h,
        )
        db.session.add(img)

    db.session.commit()
    return sig


# =========================================================================
#  Vérification d'une signature
# =========================================================================
def verify_signature_for_contract(contract_model) -> dict:
    """
    Vérifie la signature stockée pour ce contrat.
    Vérifie aussi l'intégrité de l'image si présente.

    Raisons possibles :
      - "no_signature"
      - "document_modified"
      - "invalid_signature"
      - "signer_not_found"
      - "image_integrity_failed"
      - "verified"
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

    current_data = _signed_content(contract_model)
    current_hash = _document_hash(current_data)
    if current_hash != sig.document_hash:
        return {"ok": False, "reason": "document_modified",
                "signer": signer, "signature": sig}

    # Intégrité de l'image si présente
    if sig.signature_image is not None:
        try:
            png = signature_image_service.decrypt_image(
                sig.signature_image.encrypted_image)
            if signature_image_service.sha256_hex(png) != sig.signature_image.image_hash:
                return {"ok": False, "reason": "image_integrity_failed",
                        "signer": signer, "signature": sig}
        except Exception:
            return {"ok": False, "reason": "image_integrity_failed",
                    "signer": signer, "signature": sig}

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