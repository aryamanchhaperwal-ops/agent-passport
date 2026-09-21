import secrets
import string
import hashlib

def generate_api_key() -> tuple[str, str, str]:
    """Generates (raw_key, prefix, key_hash)"""
    # format: ap_<12 char prefix>_<48 char secret>
    prefix = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    secret = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(48))
    
    raw_key = f"ap_{prefix}_{secret}"
    key_hash = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
    
    return raw_key, prefix, key_hash

def verify_api_key(raw_key: str, key_hash: str) -> bool:
    return hashlib.sha256(raw_key.encode('utf-8')).hexdigest() == key_hash

def parse_prefix(raw_key: str) -> str | None:
    parts = raw_key.split('_')
    if len(parts) == 3 and parts[0] == "ap":
        return parts[1]
    return None
