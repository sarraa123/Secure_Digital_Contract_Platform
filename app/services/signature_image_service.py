"""
Chiffrement / déchiffrement de l'image de signature manuscrite.
- Format accepté : PNG UNIQUEMENT (magic number vérifié)
- Taille max : 500 Ko
- Dimensions max : 2000 x 1000
- Chiffrement : AES-256-GCM (même clé que les contrats)
- Hash SHA-256 du PNG clair stocké séparément
"""
import base64
import hashlib
import re

from app.crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt
from app.config import Config


MAX_IMAGE_BYTES = 500 * 1024
MAX_WIDTH       = 2000
MAX_HEIGHT      = 1000
PNG_MAGIC       = b"\x89PNG\r\n\x1a\n"


def _png_dimensions(data: bytes):
    """Lit width/height depuis le chunk IHDR d'un PNG."""
    if len(data) < 24 or data[12:16] != b"IHDR":
        return None, None
    return (int.from_bytes(data[16:20], "big"),
            int.from_bytes(data[20:24], "big"))


_DATA_URL_RE = re.compile(r"^data:image/png;base64,(?P<b64>.+)$", re.DOTALL)


def decode_png_from_client(raw: str):
    """
    Accepte data URL ou base64 brut. Retourne (png_bytes, erreur).
    """
    if not raw or not isinstance(raw, str):
        return None, "Image manquante."

    raw = raw.strip()
    m = _DATA_URL_RE.match(raw)
    b64 = m.group("b64") if m else raw
    b64 = re.sub(r"\s+", "", b64)

    try:
        data = base64.b64decode(b64, validate=True)
    except Exception:
        return None, "Encodage base64 invalide."

    return data, ""


def validate_png(data: bytes):
    if not data:
        return False, "Image vide."
    if len(data) > MAX_IMAGE_BYTES:
        return False, f"Image trop volumineuse (max {MAX_IMAGE_BYTES // 1024} Ko)."
    if not data.startswith(PNG_MAGIC):
        return False, "Format invalide : PNG attendu."

    w, h = _png_dimensions(data)
    if w is None or h is None:
        return False, "PNG illisible (IHDR manquant)."
    if w == 0 or h == 0:
        return False, "Dimensions invalides."
    if w > MAX_WIDTH or h > MAX_HEIGHT:
        return False, f"Dimensions trop grandes (max {MAX_WIDTH}x{MAX_HEIGHT})."

    return True, ""


def encrypt_image(png_bytes: bytes) -> bytes:
    return aes_gcm_encrypt(png_bytes, Config.CONTRACT_ENCRYPTION_KEY)


def decrypt_image(blob: bytes) -> bytes:
    return aes_gcm_decrypt(blob, Config.CONTRACT_ENCRYPTION_KEY)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()