from flask import Flask, request, render_template, session, jsonify, redirect, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
import sqlite3
from cryptography.fernet import Fernet, InvalidToken
import base64
import secrets
import json
import re
import math
import hashlib
import requests
import pandas as pd
import joblib
from argon2.low_level import hash_secret_raw, Type
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
limiter = Limiter(app=app, key_func=get_remote_address)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

model = joblib.load("password_health_model.pkl")

with open("wordlist.txt", "r") as f:
    wordlist = [word.strip() for word in f.read().splitlines()]  # Strip whitespace from words

def derive_key(mnemonic: str, salt: bytes) -> bytes:
    # Normalize mnemonic: single spaces, no leading/trailing spaces
    normalized_mnemonic = " ".join(word.strip() for word in mnemonic.split())
    hashed = hash_secret_raw(
        secret=normalized_mnemonic.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=64*1024,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    key = base64.urlsafe_b64encode(hashed)
    logger.debug(f"Derived key: {key.decode()} for mnemonic: '{normalized_mnemonic}' with salt: {salt.hex()}")
    return key

def encrypt_data(data: str, key: bytes) -> bytes:
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    logger.debug(f"Encrypted vault: {encrypted.hex()}")
    return encrypted

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data).decode()
    logger.debug(f"Decrypted vault: {decrypted}")
    return decrypted

def init_db():
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt BLOB, vault BLOB)")
    conn.commit()
    conn.close()

def create_user(username: str, salt: bytes, encrypted_vault: bytes):
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO users (username, salt, vault) VALUES (?, ?, ?)",
                   (username, salt, encrypted_vault))
    conn.commit()
    conn.close()

def username_exists(username):
    with sqlite3.connect("vault.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return cursor.fetchone() is not None

def get_vault(username: str) -> tuple:
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("SELECT salt, vault FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result if result else (None, None)

def password_features(password: str) -> dict:
    features = {
        "length": len(password),
        "entropy": math.log2(len(set(password)) ** len(password)) if password else 0,
        "has_upper": int(bool(re.search(r"[A-Z]", password))),
        "has_symbol": int(bool(re.search(r"[^A-Za-z0-9]", password))),
        "has_leet": int(any(c in "@3!0" for c in password)),  # Simple leet-speak check
        "repetition": int(bool(re.search(r"(.)\1{2,}", password))),  # Repeated characters
        "digit_ratio": sum(c.isdigit() for c in password) / len(password) if password else 0,
        "unique_ratio": len(set(password)) / len(password) if password else 0,
        "hibp_breached": check_hibp(password)
    }
    return features

def check_hibp(password: str) -> int:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    return int(suffix in response.text)

def generate_password(length=12, use_symbols=True):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if use_symbols:
        alphabet += "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def generate_mnemonic(length=5) -> str:
    words = [secrets.choice(wordlist) for _ in range(length)]
    mnemonic = " ".join(words)
    logger.debug(f"Generated mnemonic: '{mnemonic}'")
    return mnemonic

@app.route("/", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    username = request.form["username"]
    mnemonic = request.form["mnemonic"]
    logger.debug(f"Login attempt for {username} with mnemonic: '{mnemonic}'")
    salt, vault = get_vault(username)
    if not vault:
        logger.warning(f"User not found: {username}")
        return render_template("login.html", error="User not found")
    key = derive_key(mnemonic, salt)
    try:
        decrypted_vault = decrypt_data(vault, key)
        vault_data = json.loads(decrypted_vault)
        session["username"] = username
        session["vault"] = decrypted_vault
        session["key"] = key.decode('utf-8')
        logger.info(f"Login successful for {username}")
        return render_template("dashboard.html", vault=vault_data)
    except InvalidToken:
        logger.debug(f"Invalid mnemonic for {username}")
        return render_template("login.html", error="Invalid mnemonic")
    except json.JSONDecodeError:
        logger.error(f"Decrypted vault is not valid JSON for {username}")
        return render_template("login.html", error="Invalid vault data")

@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    if not username.strip():
        logger.warning("Missing or empty username")
        return "Bad Request: Username is required", 400
    if username_exists(username):
        logger.warning(f"Username already taken: {username}")
        return render_template("login.html", error="Username already taken")
    mnemonic = generate_mnemonic()
    salt = secrets.token_bytes(16)
    key = derive_key(mnemonic, salt)
    vault = json.dumps({"passwords": []})
    encrypted_vault = encrypt_data(vault, key)
    try:
        decrypted_vault = decrypt_data(encrypted_vault, key)
        if decrypted_vault != vault:
            logger.error(f"Decryption mismatch for {username}: expected {vault}, got {decrypted_vault}")
            raise ValueError("Encryption/decryption mismatch")
        logger.debug(f"Encryption verified for {username}")
    except Exception as e:
        logger.error(f"Encryption verification failed for {username}: {e}")
        raise
    create_user(username, salt, encrypted_vault)
    logger.info(f"User {username} registered with mnemonic: '{mnemonic}'")
    return render_template("login.html", success=f"Account created! Your mnemonic is: {mnemonic}. Save it securely.")

@app.route("/add_password", methods=["POST"])
def add_password():
    if "username" not in session or "key" not in session:
        logger.warning("Unauthorized add_password attempt")
        return redirect("/")
    username = session["username"]
    key = session["key"].encode()
    salt, vault = get_vault(username)
    fernet = Fernet(key)
    vault_data = json.loads(fernet.decrypt(vault).decode())
    vault_data["passwords"].append({
        "site": request.form["site"],
        "password": request.form["password"]
    })
    encrypted_vault = fernet.encrypt(json.dumps(vault_data).encode())
    create_user(username, salt, encrypted_vault)
    session["vault"] = json.dumps(vault_data)
    logger.info(f"Password added for {username}")
    return render_template("dashboard.html", vault=vault_data)


@app.route("/delete_password", methods=["POST"])
def delete_password():
    if "username" not in session or "key" not in session:
        logger.warning("Unauthorized delete_password attempt")
        return redirect("/")
    username = session["username"]
    key = session["key"].encode()
    try:
        index = int(request.form["index"])  # Index of the password to delete
    except (KeyError, ValueError):
        logger.warning(f"Invalid index provided for {username}")
        return render_template("dashboard.html", vault=json.loads(session["vault"]), error="Invalid password selection")

    salt, vault = get_vault(username)
    fernet = Fernet(key)
    vault_data = json.loads(fernet.decrypt(vault).decode())

    if 0 <= index < len(vault_data["passwords"]):
        deleted_entry = vault_data["passwords"].pop(index)
        logger.info(f"Password for {deleted_entry['site']} deleted for {username}")
        encrypted_vault = fernet.encrypt(json.dumps(vault_data).encode())
        create_user(username, salt, encrypted_vault)
        session["vault"] = json.dumps(vault_data)
        return render_template("dashboard.html", vault=vault_data,
                               success=f"Password for {deleted_entry['site']} deleted successfully")
    else:
        logger.warning(f"Index {index} out of range for {username}")
        return render_template("dashboard.html", vault=vault_data, error="Password not found")

@app.route("/generate_password", methods=["POST"])
def gen_password():
    length = int(request.form.get("length", 12))
    use_symbols = request.form.get("symbols", "true") == "true"
    password = generate_password(length, use_symbols)
    return jsonify({"password": password})

@app.route("/check_password", methods=["POST"])
def check_password():
    password = request.form["password"]
    features = pd.DataFrame([password_features(password)])
    strength = model.predict(features)[0]
    tips = ["Add symbols", "Increase length"] if strength == 0 else []
    return render_template("result.html", strength=strength, tips=tips, password=password)

@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "username" not in session:
        return redirect("/")
    username = session["username"]
    with sqlite3.connect("vault.db") as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
    logger.info(f"User {username} deleted their account")
    session.clear()
    return render_template("login.html", success="Account deleted successfully")

@app.route("/logout", methods=["GET"])
def logout():
    logger.info(f"User {session.get('username', 'unknown')} logged out")
    session.clear()
    resp = make_response(redirect("/"))
    resp.set_cookie('session', '', expires=0)
    return resp

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)