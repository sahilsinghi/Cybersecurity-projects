# server.py — Secure Chat (private, token-protected)
from flask import Flask, request, jsonify
import os
from time import time

app = Flask(__name__)

# Privacy / access control
API_TOKEN = os.environ.get("CHAT_API_TOKEN", "")

@app.before_request
def require_api_key():
    # Allow health root unprotected (so you can curl /)
    if request.endpoint == "home":
        return
    if not API_TOKEN:
        return jsonify({"error": "server missing CHAT_API_TOKEN"}), 500
    if request.headers.get("X-API-Key") != API_TOKEN:
        return jsonify({"error": "unauthorized"}), 401

# In-memory "database"
MESSAGES = []     # each: {from,to, ...payload..., ts}
PUBLIC_KEYS = {}  # username -> PEM string (public key)

# Routes
@app.route("/")
def home():
    return "✅ Secure Chat Server is running!"

@app.route("/register_key", methods=["POST"])
def register_key():
    data = request.get_json(force=True)
    username = data.get("username")
    public_key = data.get("public_key")
    if not username or not public_key:
        return jsonify({"error": "username and public_key required"}), 400

    # do not overwrite an existing different key
    if username in PUBLIC_KEYS and PUBLIC_KEYS[username] != public_key:
        return jsonify({"error": "public key already registered"}), 409

    PUBLIC_KEYS[username] = public_key
    return jsonify({"ok": True})

@app.route("/get_key/<username>", methods=["GET"])
def get_key(username):
    pk = PUBLIC_KEYS.get(username)
    if not pk:
        return jsonify({"error": "user not found"}), 404
    return jsonify({"username": username, "public_key": pk})

@app.route("/send", methods=["POST"])
def send_message():
    data = request.get_json(force=True)
    sender = data.get("from")
    to = data.get("to")
    if not sender or not to:
        return jsonify({"error": "from and to required"}), 400

    # --- SECURE MODE: ciphertext payload present ---
    if all(k in data for k in ("ciphertext", "nonce", "ekey")):
        msg = {
            "from": sender,
            "to": to,
            "ciphertext": data["ciphertext"],
            "nonce": data["nonce"],
            "ekey": data["ekey"],
            "ts": time(),
        }
        # optional digital signature
        if "signature" in data:
            msg["signature"] = data["signature"]
        MESSAGES.append(msg)
        return jsonify({"ok": True, "mode": "secure", "count": len(MESSAGES)})

    # --- PLAINTEXT FALLBACK (from early step) ---
    text = data.get("message")
    if not text:
        return jsonify({"error": "message or ciphertext required"}), 400
    msg = {"from": sender, "to": to, "message": text, "ts": time()}
    if "signature" in data:
        msg["signature"] = data["signature"]
    MESSAGES.append(msg)
    return jsonify({"ok": True, "mode": "plain", "count": len(MESSAGES)})

@app.route("/messages", methods=["GET"])
def get_messages():
    user = request.args.get("user")
    if not user:
        return jsonify({"error": "user query parameter required"}), 400
    msgs = [m for m in MESSAGES if m["to"] == user]
    return jsonify({"messages": msgs})

# Run (LOCAL ONLY)
if __name__ == "__main__":
    # Localhost only (private app). Use 0.0.0.0 if you intentionally want LAN access.
    app.run(host="127.0.0.1", port=5000)

