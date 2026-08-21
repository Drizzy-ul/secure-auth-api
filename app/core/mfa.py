"""Multi-Factor Authentication (MFA) with TOTP and hashed emergency backup codes."""

import base64
import io
import secrets
import string
from typing import List, Optional, Tuple

import bcrypt
import pyotp
import qrcode
import qrcode.image.svg

from app.config import settings


def generate_totp_secret() -> str:
    """Generate a random base32 encoded TOTP secret key (160 bits)."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, account_name: str, issuer_name: Optional[str] = None) -> str:
    """Generate the standard otpauth:// URI for authenticator applications."""
    issuer = issuer_name or settings.MFA_ISSUER_NAME
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=account_name, issuer_name=issuer)


def generate_qr_code_png_base64(provisioning_uri: str) -> str:
    """Generate a high-contrast PNG QR Code as a base64 Data URL."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64_str = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64_str}"


def generate_qr_code_svg(provisioning_uri: str) -> str:
    """Generate a lightweight, scalable SVG representation of the QR code."""
    qr = qrcode.QRCode(
        image_factory=qrcode.image.svg.SvgPathImage,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image()
    buffer = io.BytesIO()
    img.save(buffer)
    return buffer.getvalue().decode("utf-8")


def verify_totp_code(secret: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a 6-digit TOTP code against the secret key.
    valid_window=1 allows ±30 seconds clock drift tolerance.
    """
    if not secret or not code:
        return False
    # Strip any spaces or dashes from user input
    cleaned_code = code.strip().replace(" ", "").replace("-", "")
    if not cleaned_code.isdigit() or len(cleaned_code) != 6:
        return False
        
    totp = pyotp.TOTP(secret)
    return totp.verify(cleaned_code, valid_window=valid_window)


def generate_backup_codes(count: Optional[int] = None) -> List[str]:
    """
    Generate single-use cryptographically random emergency recovery codes.
    Format: XXXX-XXXX (8 uppercase alphanumeric characters separated by hyphen)
    """
    total = count or settings.MFA_BACKUP_CODE_COUNT
    charset = string.ascii_uppercase + string.digits
    # Exclude ambiguous characters (0, O, 1, I)
    unambiguous_charset = "".join(c for c in charset if c not in ("0", "O", "1", "I"))

    codes = []
    for _ in range(total):
        part1 = "".join(secrets.choice(unambiguous_charset) for _ in range(4))
        part2 = "".join(secrets.choice(unambiguous_charset) for _ in range(4))
        codes.append(f"{part1}-{part2}")
    return codes


def hash_backup_code(code: str) -> str:
    """Hash a backup recovery code using bcrypt before persisting in the database."""
    cleaned = code.strip().upper()
    salt = bcrypt.gensalt(rounds=10)
    return bcrypt.hashpw(cleaned.encode("utf-8"), salt).decode("utf-8")


def verify_backup_code(plain_code: str, hashed_code: str) -> bool:
    """Verify an entered backup code against a stored hash in constant time."""
    try:
        cleaned = plain_code.strip().upper()
        return bcrypt.checkpw(cleaned.encode("utf-8"), hashed_code.encode("utf-8"))
    except Exception:
        return False
