import hashlib
import os
import re
import json
import base64
from cryptography.fernet import Fernet

ENCRYPTION_KEY = base64.urlsafe_b64encode(b'a' * 32)
cipher = Fernet(ENCRYPTION_KEY)

def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hash password with salt using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hashed, salt

def verify_password(password: str, hashed: bytes, salt: bytes) -> bool:
    """Verify password against hash."""
    return hash_password(password, salt)[0] == hashed

def encrypt_data(data: dict, key: str) -> str:
    """Encrypt personal data."""
    cipher = Fernet(key.encode())
    json_data = json.dumps(data)
    return cipher.encrypt(json_data.encode()).decode()

def decrypt_data(encrypted: str, key: str) -> dict:
    """Decrypt personal data."""
    cipher = Fernet(key.encode())
    decrypted = cipher.decrypt(encrypted.encode())
    return json.loads(decrypted.decode())

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