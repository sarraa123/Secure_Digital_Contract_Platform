"""
Génération de certificats X.509 auto-signés pour les utilisateurs Veridoc.

Chaque utilisateur possède :
  - une paire de clés RSA-3072 (déjà existante dans `users`)
  - un certificat X.509 auto-signé contenant son identité (nom, email)
  - la clé privée reste chiffrée AES-GCM (jamais exposée)
  - le certificat (PEM) est stocké en clair, il n'est pas secret

Ce certificat N'EST PAS signé par une CA : il est auto-signé.
Il sert de preuve d'identité vérifiable pour les certificats PDF de signature.
"""
import datetime
import hashlib

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

from app.extensions import db


# ---------------------------------------------------------------------------
#  Génération
# ---------------------------------------------------------------------------
def generate_x509_for_user(user) -> str:
    """
    Génère un certificat X.509 auto-signé pour `user`.
    Suppose que la paire de clés RSA existe déjà.

    Effets de bord :
      - remplit `user.x509_certificate_pem` (PEM texte)
      - commit la session

    Retourne le PEM du certificat.
    """
    from app.services.crypto_service import load_private_key

    if not user.has_signing_keys:
        raise ValueError(
            f"L'utilisateur {user.email} n'a pas de paire de clés RSA."
        )

    private_key = load_private_key(user)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, user.username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, user.email),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Veridoc"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
    ])

    now = datetime.datetime.utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(user.email)]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    user.x509_certificate_pem = cert_pem
    db.session.commit()

    return cert_pem


# ---------------------------------------------------------------------------
#  Empreintes / métadonnées
# ---------------------------------------------------------------------------
def fingerprint_sha256(cert_pem: str) -> str:
    """Empreinte SHA-256 du DER du certificat (hex)."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def parse_certificate_info(cert_pem: str) -> dict:
    """Retourne les infos lisibles du certificat pour affichage."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    email = cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
    org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)

    return {
        "serial":             format(cert.serial_number, "x"),
        "subject_cn":         cn[0].value if cn else "—",
        "subject_email":      email[0].value if email else "—",
        "issuer_org":         org[0].value if org else "—",
        "not_valid_before":   cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "not_valid_after":    cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "fingerprint_sha256": fingerprint_sha256(cert_pem),
    }