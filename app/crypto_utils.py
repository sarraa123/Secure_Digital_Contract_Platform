import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aes_gcm_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-GCM. Retourne nonce(12) || ciphertext+tag."""
    if len(key) != 32:
        raise ValueError("La clé AES doit faire 32 octets.")
    nonce = os.urandom(12)                     # CRYP-03
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def aes_gcm_decrypt(blob: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("La clé AES doit faire 32 octets.")
    if len(blob) < 12 + 16:
        raise ValueError("Blob chiffré trop court.")
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


def hmac_sha256(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_verify(data: bytes, expected_hex: str, key: bytes) -> bool:
    return hmac.compare_digest(hmac_sha256(data, key), expected_hex)  # CRYP-06