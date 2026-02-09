import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

import pyaes

APP_ID = "wireguard.sysadmin"
APP_HOME = Path(os.environ.get("WIREGUARD_APP_HOME", "/home/phablet"))
CONFIG_DIR = APP_HOME / ".local" / "share" / APP_ID
PROFILES_DIR = CONFIG_DIR / "profiles"


def available():
    return True


def _secret_path(profile_name):
    return PROFILES_DIR / profile_name / "secret.json"


def secret_exists(profile_name):
    return _secret_path(profile_name).exists()


def _derive_keys(password, salt, meta):
    pwd = (password or "").encode()
    kdf = (meta or {}).get("kdf") or "scrypt"
    if kdf == "scrypt":
        n = int((meta or {}).get("n") or 2 ** 14)
        r = int((meta or {}).get("r") or 8)
        p = int((meta or {}).get("p") or 1)
        try:
            key = hashlib.scrypt(pwd, salt=salt, n=n, r=r, p=p, dklen=64)
            return key[:32], key[32:], {"kdf": "scrypt", "n": n, "r": r, "p": p}
        except Exception:
            pass
    # fallback to PBKDF2-HMAC
    iters = int((meta or {}).get("iters") or 200000)
    key = hashlib.pbkdf2_hmac("sha256", pwd, salt, iters, dklen=64)
    return key[:32], key[32:], {"kdf": "pbkdf2", "iters": iters}


def _hmac_data(meta, salt, nonce, ct):
    parts = [meta.get("kdf", "")]
    if meta.get("kdf") == "scrypt":
        parts += [str(meta.get("n", "")), str(meta.get("r", "")), str(meta.get("p", ""))]
    if meta.get("kdf") == "pbkdf2":
        parts += [str(meta.get("iters", ""))]
    meta_bytes = "|".join(parts).encode()
    return meta_bytes + b"|" + salt + nonce + ct


def set_private_key(profile_name, private_key, password):
    if not password:
        return False, "Password is required to store private key"
    try:
        PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    secret_file = _secret_path(profile_name)
    salt = os.urandom(16)
    enc_key, mac_key, meta = _derive_keys(password, salt, {"kdf": "scrypt"})
    nonce = os.urandom(16)
    counter = pyaes.Counter(int.from_bytes(nonce, "big"))
    aes = pyaes.AESModeOfOperationCTR(enc_key, counter=counter)
    ct = aes.encrypt((private_key or "").encode())
    mac = hmac.new(mac_key, _hmac_data(meta, salt, nonce, ct), hashlib.sha256).digest()
    blob = {
        "v": 1,
        "kdf": meta.get("kdf"),
        "n": meta.get("n"),
        "r": meta.get("r"),
        "p": meta.get("p"),
        "iters": meta.get("iters"),
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
        "hmac": base64.b64encode(mac).decode(),
    }
    try:
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        secret_file.write_text(json.dumps(blob))
        try:
            os.chmod(secret_file, 0o600)
        except Exception:
            pass
    except Exception as e:
        return False, str(e)
    return True, None


def get_private_key(profile_name, password, return_error=False):
    if not password:
        return (None, "NO_PASSWORD") if return_error else None
    secret_file = _secret_path(profile_name)
    if not secret_file.exists():
        return (None, "MISSING") if return_error else None
    try:
        blob = json.loads(secret_file.read_text())
        salt = base64.b64decode(blob.get("salt", ""))
        nonce = base64.b64decode(blob.get("nonce", ""))
        ct = base64.b64decode(blob.get("ct", ""))
        mac = base64.b64decode(blob.get("hmac", ""))
    except Exception:
        return (None, "CORRUPT") if return_error else None
    meta = {
        "kdf": blob.get("kdf") or "scrypt",
        "n": blob.get("n"),
        "r": blob.get("r"),
        "p": blob.get("p"),
        "iters": blob.get("iters"),
    }
    enc_key, mac_key, _ = _derive_keys(password, salt, meta)
    expected = hmac.new(mac_key, _hmac_data(meta, salt, nonce, ct), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        return (None, "BAD_PASSWORD") if return_error else None
    try:
        counter = pyaes.Counter(int.from_bytes(nonce, "big"))
        aes = pyaes.AESModeOfOperationCTR(enc_key, counter=counter)
        pt = aes.decrypt(ct)
        return (pt.decode(errors="ignore").strip(), None) if return_error else pt.decode(errors="ignore").strip()
    except Exception:
        return (None, "DECRYPT_FAILED") if return_error else None


def delete_private_key(profile_name):
    secret_file = _secret_path(profile_name)
    try:
        if secret_file.exists():
            secret_file.unlink()
    except Exception as e:
        return False, str(e)
    return True, None
