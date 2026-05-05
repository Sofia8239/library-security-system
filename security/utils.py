import hashlib
import os
import re
import json
import base64
import hmac
try:
    from cryptography.fernet import Fernet
    HAS_FERNET = True
except ImportError:
    HAS_FERNET = False


def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hash password with salt using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hashed, salt

def verify_password(password: str, hashed: bytes, salt: bytes) -> bool:
    """Verify password against hash."""
    return hash_password(password, salt)[0] == hashed

def _sign(payload: bytes, key: str) -> str:
    digest = hmac.new(key.encode('utf-8'), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8')


def encrypt_data(data: dict, key: str) -> str:
    """Encrypt personal data using Fernet if available, else HMAC."""
    if HAS_FERNET:
        fernet = Fernet(key.encode('utf-8'))
        payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
        encrypted = fernet.encrypt(payload)
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')
    else:
        # Fallback to HMAC
        payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
        signature = _sign(payload, key)
        return base64.urlsafe_b64encode(payload).decode('utf-8') + '.' + signature


def decrypt_data(encrypted: str, key: str) -> dict:
    """Decrypt personal data using Fernet if available, else HMAC."""
    if HAS_FERNET:
        fernet = Fernet(key.encode('utf-8'))
        encrypted_bytes = base64.urlsafe_b64decode(encrypted.encode('utf-8'))
        decrypted = fernet.decrypt(encrypted_bytes)
        return json.loads(decrypted.decode('utf-8'))
    else:
        # Fallback to HMAC
        if '.' not in encrypted:
            raise ValueError('Invalid encrypted payload')
        payload_b64, signature = encrypted.rsplit('.', 1)
        payload = base64.urlsafe_b64decode(payload_b64.encode('utf-8'))
        expected = _sign(payload, key)
        if not hmac.compare_digest(signature, expected):
            raise ValueError('Invalid signature')
        return json.loads(payload.decode('utf-8'))

def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None

def validate_phone(phone: str) -> bool:
    """Validate phone format (simple)."""
    pattern = r'^\+?\d{10,15}$'
    return re.match(pattern, phone) is not None

def validate_date(date: str) -> bool:
    """Validate date format YYYY-MM-DD."""
    pattern = r'^\d{4}-\d{2}-\d{2}$'
    return re.match(pattern, date) is not None


def sanitize_input(value: str) -> str:
    """Sanitize a user input string to reduce injection/XSS risk."""
    if not isinstance(value, str):
        return ''
    value = value.strip()
    value = re.sub(r'[<>"\']', '', value)
    value = re.sub(r'(--)|(\b(or|and|select|insert|delete|drop|update|union|shutdown)\b)', '', value, flags=re.IGNORECASE)
    return value