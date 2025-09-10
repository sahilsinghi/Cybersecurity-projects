# chat_cli.py — tiny interactive E2EE chat (works with your server.py)
import os, sys, time, threading, base64
from pathlib import Path
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asy_pad
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_URL = "http://127.0.0.1:5000"
HEADERS  = {"X-API-Key": os.environ.get("CHAT_API_TOKEN", "")}

def b64e(b: bytes) -> str: return base64.b64encode(b).decode()
def b64d(s: str) -> bytes: return base64.b64decode(s.encode())

def load_priv(user: str):
    p = Path(f"keys/{user}.priv.pem").read_bytes()
    return serialization.load_pem_private_key(p, password=None)

def load_pub_pem_from_server(user: str) -> bytes:
    r = requests.get(f"{BASE_URL}/get_key/{user}", headers=HEADERS, timeout=10)
    r.raise_for_status()
    return r.json()["public_key"].encode()

def register_key(user: str):
    pub_pem = Path(f"keys/{user}.pub.pem").read_text()
    r = requests.post(f"{BASE_URL}/register_key",
                      json={"username": user, "public_key": pub_pem},
                      headers=HEADERS, timeout=10)
    if r.status_code not in (200, 409):
        r.raise_for_status()

def ensure_keys(user: str):
    # keys already generated earlier by your scripts; if not, error out clearly
    priv = Path(f"keys/{user}.priv.pem")
    pub  = Path(f"keys/{user}.pub.pem")
    if not (priv.exists() and pub.exists()):
        print(f"[!] keys for '{user}' not found under ./keys/. Run your keygen step first.")
        sys.exit(1)

def hybrid_encrypt(recipient_pub_pem: bytes, plaintext: str, aad: bytes=b"") -> dict:
    aes = os.urandom(32); nonce = os.urandom(12)
    ct  = AESGCM(aes).encrypt(nonce, plaintext.encode(), aad)
    pub = serialization.load_pem_public_key(recipient_pub_pem)
    ekey = pub.encrypt(aes, asy_pad.OAEP(mgf=asy_pad.MGF1(hashes.SHA256()),
                                         algorithm=hashes.SHA256(), label=None))
    return {"nonce": b64e(nonce), "ciphertext": b64e(ct), "ekey": b64e(ekey)}

def hybrid_decrypt(priv, nonce_b64, ct_b64, ekey_b64, aad: bytes=b""):
    aes = priv.decrypt(b64d(ekey_b64),
                       asy_pad.OAEP(mgf=asy_pad.MGF1(hashes.SHA256()),
                                    algorithm=hashes.SHA256(), label=None))
    pt = AESGCM(aes).decrypt(b64d(nonce_b64), b64d(ct_b64), aad)
    return pt.decode()

def sign(priv, msg: str) -> str:
    sig = priv.sign(msg.encode(),
                    asy_pad.PSS(mgf=asy_pad.MGF1(hashes.SHA256()),
                                salt_length=asy_pad.PSS.MAX_LENGTH),
                    hashes.SHA256())
    return b64e(sig)

def verify(pub_pem: bytes, msg: str, sig_b64: str) -> bool:
    pub = serialization.load_pem_public_key(pub_pem)
    try:
        pub.verify(b64d(sig_b64), msg.encode(),
                   asy_pad.PSS(mgf=asy_pad.MGF1(hashes.SHA256()),
                               salt_length=asy_pad.PSS.MAX_LENGTH),
                   hashes.SHA256())
        return True
    except Exception:
        return False

def send_secure(sender: str, to: str, text: str):
    aad = f"{sender}->{to}".encode()
    recip_pub = load_pub_pem_from_server(to)
    blob = hybrid_encrypt(recip_pub, text, aad=aad)
    sig  = sign(load_priv(sender), text)
    payload = {"from": sender, "to": to, "signature": sig, **blob}
    r = requests.post(f"{BASE_URL}/send", json=payload, headers=HEADERS, timeout=10)
    r.raise_for_status()

def fetch_messages(user: str):
    r = requests.get(f"{BASE_URL}/messages", params={"user": user},
                     headers=HEADERS, timeout=10)
    r.raise_for_status()
    return r.json().get("messages", [])

def printer(me: str, seen: set, stop_evt: threading.Event):
    priv = load_priv(me)
    while not stop_evt.is_set():
        try:
            msgs = fetch_messages(me)
            for m in msgs:
                uid = (m.get("nonce"), m.get("ciphertext"))
                if uid in seen:
                    continue
                if {"ciphertext","nonce","ekey"} <= set(m.keys()):
                    frm = m.get("from","?")
                    aad = f"{frm}->{me}".encode()
                    pt  = hybrid_decrypt(priv, m["nonce"], m["ciphertext"], m["ekey"], aad=aad)
                    ok  = False
                    if "signature" in m:
                        try:
                            s_pub = load_pub_pem_from_server(frm)
                            ok = verify(s_pub, pt, m["signature"])
                        except Exception:
                            ok = False
                    tag = "✔ authentic" if ok else "signature ?"
                    print(f"\r[{frm} → {me}] {pt}  ({tag})")
                else:
                    print(f"\r[{m.get('from','?')} → {me}] {m.get('message')}")
                seen.add(uid)
        except Exception:
            pass
        time.sleep(2)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 chat_cli.py <me> <to>")
        sys.exit(1)
    me, to = sys.argv[1], sys.argv[2]

    if not HEADERS["X-API-Key"]:
        print("[!] Set CHAT_API_TOKEN in this terminal before running.")
        sys.exit(1)

    ensure_keys(me)
    ensure_keys(to)  # only to make sure both exist locally (you created both earlier)
    # (Re)register both keys on every run (safe if already present)
    register_key(me)
    register_key(to)

    print(f"Connected. You are '{me}'. Chatting with '{to}'.")
    print("Type to send. Commands: /quit")
    seen = set()
    stop_evt = threading.Event()
    t = threading.Thread(target=printer, args=(me, seen, stop_evt), daemon=True)
    t.start()
    try:
        while True:
            msg = input("> ").strip()
            if msg in {"", None}:
                continue
            if msg == "/quit":
                break
            send_secure(me, to, msg)
            print("(sent)")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        stop_evt.set()
        print("\nbye.")

if __name__ == "__main__":
    main()
