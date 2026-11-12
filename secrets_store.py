import os
from cryptography.fernet import Fernet, InvalidToken


def _fernet():
    secret = os.getenv('APP_SECRET', '')
    if not secret:
        raise RuntimeError('Set APP_SECRET to encrypt provider API keys')
    raw = secret.encode()
    key = __import__('hashlib').sha256(raw).digest()
    return Fernet(__import__('base64').urlsafe_b64encode(key))


def encrypt(value):
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value):
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError('APP_SECRET does not match the key encryption secret') from exc
        
