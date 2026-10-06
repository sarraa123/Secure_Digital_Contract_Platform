import secrets
import string

import pyotp

from argon2 import PasswordHasher

from app import db
from app.models import MFARecoveryCode
import base64
from io import BytesIO

import qrcode

password_hasher = PasswordHasher()


ISSUER_NAME = "Secure Digital Contract Platform"


def generate_mfa_secret() -> str:
    return pyotp.random_base32()


def build_totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(
        secret,
        digits=6,
        interval=30
    )


def generate_provisioning_uri(
    secret: str,
    email: str
) -> str:

    totp = build_totp(secret)

    return totp.provisioning_uri(
        name=email,
        issuer_name=ISSUER_NAME
    )


def verify_totp(
    secret: str,
    code: str
) -> bool:

    if not secret:
        return False

    if not code:
        return False

    code = code.strip()

    if len(code) != 6:
        return False

    if not code.isdigit():
        return False

    totp = build_totp(secret)

    return totp.verify(
        code,
        valid_window=1
    )


def generate_recovery_code() -> str:

    alphabet = string.ascii_uppercase + string.digits

    part1 = "".join(
        secrets.choice(alphabet)
        for _ in range(4)
    )

    part2 = "".join(
        secrets.choice(alphabet)
        for _ in range(4)
    )

    return f"{part1}-{part2}"


def generate_recovery_codes(
    user_id: int,
    count: int = 8
) -> list[str]:

    plain_codes = []

    for _ in range(count):

        code = generate_recovery_code()

        code_hash = password_hasher.hash(code)

        recovery_code = MFARecoveryCode(
            user_id=user_id,
            code_hash=code_hash,
        )

        db.session.add(recovery_code)

        plain_codes.append(code)

    db.session.commit()

    return plain_codes


def verify_recovery_code(
    user_id: int,
    code: str
) -> bool:

    if not code:
        return False

    code = code.strip().upper()

    recovery_codes = MFARecoveryCode.query.filter_by(
        user_id=user_id,
        used_at=None
    ).all()

    for recovery_code in recovery_codes:

        try:

            valid = password_hasher.verify(
                recovery_code.code_hash,
                code
            )

        except Exception:
            valid = False

        if valid:

            from datetime import datetime, timezone

            recovery_code.used_at = datetime.now(
                timezone.utc
            )

            db.session.commit()

            return True

    return False


def generate_qr_code_data_uri(
    provisioning_uri: str
) -> str:

    qr = qrcode.QRCode(
        version=1,
        box_size=8,
        border=4,
    )

    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    image = qr.make_image()

    buffer = BytesIO()

    image.save(
        buffer,
        format="PNG"
    )

    encoded = base64.b64encode(
        buffer.getvalue()
    ).decode("utf-8")

    return (
        "data:image/png;base64,"
        + encoded
    )