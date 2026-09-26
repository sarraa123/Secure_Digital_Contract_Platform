"""
Signature numérique RSA-3072 + PSS + SHA-256.

- Chaque utilisateur a une paire de clés RSA générée à la création.
- La clé privée est stockée CHIFFRÉE (AES-GCM) en base.
- La clé publique est stockée en clair (partageable).
- La signature utilise RSA-PSS (padding probabiliste, sûr).

Références CDC :
- CRYP-05 : clés distinctes, taille 3072 bits
- CRYP-06 : comparaison à temps constant (via cryptography)
- CRYP-08 : anti-répudiation
"""
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from app.extensions import db
from app.services.encryption_service import (
    encrypt_contract_data, decrypt_contract_data,
)


# ---------------------------------------------------------------------------
#  Paramètres cryptographiques
# ---------------------------------------------------------------------------
RSA_KEY_SIZE   = 3072
RSA_PUBLIC_EXP = 65537
SIGNATURE_ALGORITHM = "RSA-PSS-SHA256"

_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


# =========================================================================
#  1. Génération de paire de clés
# =========================================================================
def generate_keypair() -> tuple:
    """
    Génère une paire RSA-3072.
    Retourne (private_key_encrypted_blob, public_key_pem).
    """
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXP,
        key_size=RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Chiffrer la clé privée avant stockage
    private_encrypted = encrypt_contract_data({"pem": private_pem})

    return private_encrypted, public_pem


# =========================================================================
#  2. Chargement des clés
# =========================================================================
def load_private_key(user):
    """Déchiffre et recharge la clé privée RSA depuis la base."""
    if not user.private_key_encrypted:
        raise ValueError(f"L'utilisateur {user.email} n'a pas de clé privée.")
    data = decrypt_contract_data(user.private_key_encrypted)
    return serialization.load_pem_private_key(
        data["pem"].encode("utf-8"), password=None)


def load_public_key(user):
    """Recharge la clé publique RSA d'un utilisateur."""
    if not user.public_key_pem:
        raise ValueError(f"L'utilisateur {user.email} n'a pas de clé publique.")
    return serialization.load_pem_public_key(user.public_key_pem.encode("utf-8"))


# =========================================================================
#  3. Signature RSA-PSS
# =========================================================================
def sign_data(user, data: bytes) -> dict:
    """
    Signe `data` avec la clé privée RSA du user (PSS + SHA-256).
    Retourne un dict prêt à stocker.
    """
    private_key = load_private_key(user)
    signature = private_key.sign(data, _PSS_PADDING, hashes.SHA256())

    return {
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "signature_value":     base64.b64encode(signature).decode("ascii"),
        "signed_by_id":        user.id,
        "signed_by_email":     user.email,
    }


def verify_signature(public_key_pem: str, data: bytes, signature_b64: str) -> bool:
    """
    Vérifie qu'une signature RSA-PSS correspond à `data` + clé publique.
    Retourne True/False (jamais d'exception).
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"))
        public_key.verify(
            base64.b64decode(signature_b64),
            data,
            _PSS_PADDING,
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# =========================================================================
#  4. Rétrocompatibilité (anciens noms)
# =========================================================================
def sign_contract_blob(user, encrypted_metadata: bytes, encrypted_file: bytes) -> dict:
    data = encrypted_metadata + encrypted_file
    return sign_data(user, data)


def verify_contract_signature(signer_public_key_pem: str,
                              encrypted_metadata: bytes,
                              encrypted_file: bytes,
                              signature_b64: str) -> bool:
    return verify_signature(
        signer_public_key_pem,
        encrypted_metadata + encrypted_file,
        signature_b64,
    )


# =========================================================================
#  5. Vérification d'un contrat signé (helper)
# =========================================================================
def check_contract_signature(metadata: dict, model, user_lookup) -> dict:
    sig = metadata.get("signature")
    if not sig:
        return {"ok": False, "reason": "no_signature", "signer": None}

    signer_id = sig.get("signed_by_id")
    if not signer_id:
        return {"ok": False, "reason": "no_signer_id", "signer": None}

    signer = user_lookup(signer_id)
    if not signer or not signer.public_key_pem:
        return {"ok": False, "reason": "signer_not_found", "signer": None}

    valid = verify_signature(
        signer.public_key_pem,
        model.encrypted_metadata + model.encrypted_file,
        sig["signature_value"],
    )
    return {
        "ok": valid,
        "reason": "verified" if valid else "invalid_signature",
        "signer": signer,
    }