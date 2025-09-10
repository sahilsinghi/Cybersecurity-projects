import json, base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def b64d(x): return base64.b64decode(x.encode())

# Load Bob’s private key
priv = serialization.load_pem_private_key(
    Path("keys/bob.priv.pem").read_bytes(),
    password=None
)

# Load JSON
data = json.load(open("messages.json"))
m = data["messages"][0]   # take first message

print("Encrypted message from:", m["from"], "to:", m["to"])

# Step 1: Decrypt AES session key
aes_key = priv.decrypt(
    b64d(m["ekey"]),
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(), label=None)
)

# Step 2: Decrypt ciphertext
aesgcm = AESGCM(aes_key)
aad = f"{m['from']}->{m['to']}".encode()
plaintext = aesgcm.decrypt(b64d(m["nonce"]), b64d(m["ciphertext"]), aad)

print("Decrypted plaintext:", plaintext.decode())

