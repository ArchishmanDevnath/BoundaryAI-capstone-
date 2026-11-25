import hashlib


def check_password(stored_hash, password):
    return stored_hash == hashlib.sha256(password.encode()).hexdigest()
