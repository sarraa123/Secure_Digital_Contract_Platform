"""
HMAC-SHA256 calculé sur (encrypted_metadata || encrypted_file).
Toute altération d'un des deux blobs casse la signature.
"""
from app.config import Config
from app.crypto_utils import hmac_sha256, hmac_verify


def _combined(enc_meta: bytes, enc_file: bytes) -> bytes:
    # Séparateur non ambigu + longueur de la metadata en préfixe
    # Empêche les attaques par concaténation (meta1||file vs meta2||file)
    return len(enc_meta).to_bytes(8, "big") + enc_meta + enc_file


def compute_signature(enc_meta: bytes, enc_file: bytes) -> str:
    return hmac_sha256(_combined(enc_meta, enc_file), Config.INTEGRITY_KEY)


def verify_signature(enc_meta: bytes, enc_file: bytes, expected_hex: str) -> bool:
    return hmac_verify(_combined(enc_meta, enc_file),
                       expected_hex, Config.INTEGRITY_KEY)