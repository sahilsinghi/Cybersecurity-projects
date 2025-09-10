from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib

KEYS_DIR = Path("./keys")
KEYS_DIR.mkdir(exist_ok=True)

def generate_rsa_keypair(username: str):
    """Generate and save a 3072-bit RSA keypair for the given user."""
    priv_path = KEYS_DIR / f"{username}.priv.pem"
    pub_path  = KEYS_DIR / f"{username}.pub.pem"

    if priv_path.exists() and pub_path.exists():
        print(f"Keys already exist for {username}")
        return priv_path, pub_path

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()

    # Save private key
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Save public key
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"Generated keys for {username}")
    return priv_path, pub_path

def fingerprint(pub_path: Path) -> str:
    """Return a short fingerprint of a public key (SHA256)."""
    data = pub_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    return ":".join(digest[i:i+4] for i in range(0, 32, 4))

# --- E2EE helpers: RSA (OAEP) + AES-GCM ---
import os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def load_public_key_pem(path):
    data = Path(path).read_bytes()
    return serialization.load_pem_public_key(data)

def load_private_key_pem(path):
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)

def hybrid_encrypt(pubkey_pem_path: str, plaintext: str, aad: bytes = b"") -> dict:
    """Encrypt plaintext for recipient (RSA-OAEP + AES-GCM). Returns dict of b64 strings."""
    # 1) random AES-256 key
    aes_key = os.urandom(32)
    # 2) AEAD encrypt
    nonce = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    # 3) RSA encrypt the AES key
    pub = load_public_key_pem(pubkey_pem_path)
    enc_key = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return {"nonce": _b64e(nonce), "ciphertext": _b64e(ct), "ekey": _b64e(enc_key)}

def hybrid_decrypt(privkey_pem_path: str, nonce_b64: str, ct_b64: str, ekey_b64: str, aad: bytes = b"") -> str:
    """Decrypt dict produced by hybrid_encrypt using our RSA private key."""
    priv = load_private_key_pem(privkey_pem_path)
    aes_key = priv.decrypt(
        _b64d(ekey_b64),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    pt = AESGCM(aes_key).decrypt(_b64d(nonce_b64), _b64d(ct_b64), aad)
    return pt.decode("utf-8")
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from cryptography.hazmat.primitives import hashes

def sign_message(privkey_pem_path: str, message: str) -> str:
    priv = load_private_key_pem(privkey_pem_path)
    sig = priv.sign(
        message.encode("utf-8"),
        asy_padding.PSS(
            mgf=asy_padding.MGF1(hashes.SHA256()),
            salt_length=asy_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return _b64e(sig)

def verify_signature(pubkey_pem_path: str, message: str, signature_b64: str) -> bool:
    pub = load_public_key_pem(pubkey_pem_path)
    sig = _b64d(signature_b64)
    try:
        pub.verify(
            sig,
            message.encode("utf-8"),
            asy_padding.PSS(
                mgf=asy_padding.MGF1(hashes.SHA256()),
                salt_length=asy_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
