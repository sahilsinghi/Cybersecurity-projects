import os
import requests
from pathlib import Path
from crypto_utils import (
    hybrid_encrypt, hybrid_decrypt,
    sign_message, verify_signature
)

BASE_URL = "http://127.0.0.1:5000"
HEADERS = {"X-API-Key": os.environ.get("CHAT_API_TOKEN", "")}

def register_key(username: str) -> None:
    """Ensure the server has this user's public key (idempotent)."""
    pub_path = Path(f"keys/{username}.pub.pem")
    pub_pem = pub_path.read_text()
    r = requests.post(
        f"{BASE_URL}/register_key",
        json={"username": username, "public_key": pub_pem},
        headers=HEADERS,
        timeout=10
    )
    # 200 = newly registered, 409 = already registered with same key
    if r.status_code not in (200, 409):
        r.raise_for_status()

def get_pubkey(username: str) -> Path:
    """Fetch username's public key from the server and cache it locally for crypto helpers."""
    r = requests.get(f"{BASE_URL}/get_key/{username}", headers=HEADERS, timeout=10)
    r.raise_for_status()
    pub_pem = r.json()["public_key"].encode("utf-8")
    p = Path(f"keys/_cache_{username}.pub.pem")
    p.write_bytes(pub_pem)
    return p

def send_secure(sender: str, to: str, plaintext: str) -> None:
    """Encrypt plaintext to `to` and send; also attach sender's RSA signature."""
    # Bind context to prevent mixups (used as AEAD AAD)
    aad = f"{sender}->{to}".encode("utf-8")

    # Fetch recipient public key, then hybrid encrypt (AES-GCM + RSA-OAEP for key)
    pub_path = get_pubkey(to)
    blob = hybrid_encrypt(str(pub_path), plaintext, aad=aad)  # -> dict with nonce,ciphertext,ekey (b64)

    # Sign the original plaintext with sender's private key (PSS+SHA256)
    sig = sign_message(f"keys/{sender}.priv.pem", plaintext)

    payload = {"from": sender, "to": to, "signature": sig, **blob}
    r = requests.post(f"{BASE_URL}/send", json=payload, headers=HEADERS, timeout=10)
    r.raise_for_status()
    print("Send secure response:", r.json())

def fetch_and_decrypt(user: str) -> None:
    """Fetch messages for `user`, decrypt if secure, and verify signature if present."""
    r = requests.get(f"{BASE_URL}/messages", params={"user": user}, headers=HEADERS, timeout=10)
    r.raise_for_status()
    msgs = r.json().get("messages", [])
    if not msgs:
        print("No messages for", user)
        return

    priv_path = Path(f"keys/{user}.priv.pem")
    for m in msgs:
        if {"ciphertext", "nonce", "ekey"} <= set(m.keys()):
            # Secure message path
            sender = m.get("from", "?")
            aad = f"{sender}->{user}".encode("utf-8")
            pt = hybrid_decrypt(str(priv_path), m["nonce"], m["ciphertext"], m["ekey"], aad=aad)

            sig = m.get("signature")
            if sig:
                pub_path = get_pubkey(sender)
                ok = verify_signature(str(pub_path), pt, sig)
                if ok:
                    print(f"[secure+signed] {sender} -> {user}: {pt} (✔ authentic)")
                else:
                    print(f"[secure] {sender} -> {user}: {pt} (❌ signature invalid)")
            else:
                print(f"[secure] {sender} -> {user}: {pt}")
        else:
            # Plaintext fallback (from earlier steps)
            print(f"[plain ] {m.get('from','?')} -> {user}: {m.get('message')}")

def main():
    # Ensure both users' public keys are registered on the server (survives restarts)
    register_key("alice")
    register_key("bob")

    # demo: alice -> bob
    send_secure("alice", "bob", "Hello Bob (E2EE + Signed)! 🔐✍️")
    fetch_and_decrypt("bob")

if __name__ == "__main__":
    main()

