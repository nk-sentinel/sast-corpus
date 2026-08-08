import hashlib


def fingerprint(value):
    return hashlib.sha256(value.encode()).hexdigest()
