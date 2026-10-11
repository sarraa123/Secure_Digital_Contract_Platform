"""
Chiffrement/déchiffrement des données métier du contrat.
- Toutes les métadonnées (title, description, dates, owner_id, status…) → 1 BLOB
- Le PDF → 1 BLOB
"""
import json
from datetime import date, datetime
from app.config import Config
from app.crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt


def _json_default(o):
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    raise TypeError(f"Type non sérialisable : {type(o)}")


def encrypt_contract_data(metadata: dict) -> bytes:
    """Chiffre un dict de métadonnées en JSON puis AES-256-GCM."""
    payload = json.dumps(metadata, ensure_ascii=False,
                         default=_json_default).encode("utf-8")
    return aes_gcm_encrypt(payload, Config.CONTRACT_ENCRYPTION_KEY)


def decrypt_contract_data(blob: bytes) -> dict:
    """Déchiffre et désérialise les métadonnées."""
    payload = aes_gcm_decrypt(blob, Config.CONTRACT_ENCRYPTION_KEY)
    return json.loads(payload.decode("utf-8"))


def encrypt_contract_file(content: bytes) -> bytes:
    return aes_gcm_encrypt(content, Config.CONTRACT_ENCRYPTION_KEY)


def decrypt_contract_file(blob: bytes) -> bytes:
    return aes_gcm_decrypt(blob, Config.CONTRACT_ENCRYPTION_KEY)