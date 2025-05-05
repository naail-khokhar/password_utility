# Main Flask application for the Password Utility:
# - Handles user registration/login with zero‑knowledge encryption
# - Manages password vault operations via encrypted SQLite storage
# - Integrates ML password health checking and breach alerts

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
from categories import get_category, get_url
import zlib
from breach_utils import init_breach_db, get_site_breach_info, clean_old_breaches, get_user_sites_breaches, get_general_breaches
import os

# Configure basic logging for the application
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask application
app = Flask(__name__)
# Set a secret key for session management
app.secret_key = secrets.token_hex(16)
# Initialize rate limiter based on remote address
limiter = Limiter(app=app, key_func=get_remote_address)
# Configure server-side session storage to use the filesystem
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Load the pre-trained password health prediction model
model = joblib.load("password_health_model.pkl")

# Load a wordlist used for mnemonic generation and memorable passwords
with open("wordlist.txt", "r") as f:
    wordlist = [word.strip() for word in f.read().splitlines()]  # Strip whitespace from words

# Define database file paths
AUTH_DB = "auth.db" # Stores user authentication data (username, salt)
VAULTS_DB = "vaults.db" # Stores encrypted user password vaults

def derive_key(mnemonic: str, salt: bytes) -> bytes:
    # Derive a secure encryption key from the user’s mnemonic and per‑user salt using Argon2id.
    # Normalizes the mnemonic by stripping whitespace and joining words with single spaces.
    normalized_mnemonic = " ".join(word.strip() for word in mnemonic.split())
    # Hash the normalized mnemonic using Argon2id with specified parameters for security.
    hashed = hash_secret_raw(
        secret=normalized_mnemonic.encode(),
        salt=salt,
        time_cost=3,        # Number of iterations
        memory_cost=64*1024, # Memory cost in KiB (64 MiB)
        parallelism=4,      # Degree of parallelism
        hash_len=32,        # Desired hash length in bytes
        type=Type.ID        # Use Argon2id variant
    )
    # Encode the raw hash using URL-safe Base64 for use as a Fernet key.
    key = base64.urlsafe_b64encode(hashed)
    logger.debug(f"Derived key: {key.decode()} for mnemonic: '{normalized_mnemonic}' with salt: {salt.hex()}")
    return key

def encrypt_data(data: str, key: bytes) -> bytes:
    # Encrypt plaintext data using symmetric Fernet encryption with the derived key.
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    logger.debug(f"Encrypted vault: {encrypted.hex()}")
    return encrypted

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    # Decrypt data previously encrypted with encrypt_data() using the same Fernet key.
    fernet = Fernet(key)
    # Decrypt the data and decode it from bytes to a UTF-8 string.
    decrypted = fernet.decrypt(encrypted_data).decode()
    logger.debug("Vault decrypted successfully.")
    return decrypted

def init_db():
    # Initialize the SQLite databases and create tables if they don't exist.
    # Ensures the application has the necessary database structure on startup.
    # Initialize auth.db: stores usernames and their corresponding salts.
    with sqlite3.connect(AUTH_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt BLOB)")
        conn.commit()
    # Initialize vaults.db: stores usernames and their encrypted password vaults.
    with sqlite3.connect(VAULTS_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS user_vaults (username TEXT PRIMARY KEY, vault BLOB)")
        conn.commit()
    # Initialize breaches.db: used for caching breach information.
    init_breach_db()

def create_user(username: str, salt: bytes, encrypted_vault: bytes):
    # Store a new user's credentials (username, salt) and their initial empty encrypted vault.
    # Uses INSERT OR REPLACE to handle potential re-registration attempts gracefully.
    # Insert user's username and salt into the authentication database.
    with sqlite3.connect(AUTH_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO users (username, salt) VALUES (?, ?)", (username, salt))
        conn.commit()
    # Insert the user's username and their newly encrypted empty vault into the vaults database.
    with sqlite3.connect(VAULTS_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO user_vaults (username, vault) VALUES (?, ?)", (username, encrypted_vault))
        conn.commit()

def username_exists(username):
    # Check if a username is already registered in the authentication database.
    # Returns True if the username exists, False otherwise.
    with sqlite3.connect(AUTH_DB) as conn:
        cursor = conn.cursor()
        # Query for the existence of the username.
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        # fetchone() returns a tuple if a record is found, None otherwise.
        return cursor.fetchone() is not None

def get_vault(username: str) -> tuple:
    # Retrieve the salt and the encrypted vault blob for a given username.
    # Returns a tuple (salt, vault_blob) or (None, None) if the user or vault is not found.
    salt = None
    vault = None
    # Retrieve the salt associated with the username from the authentication database.
    with sqlite3.connect(AUTH_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            salt = result[0] # Extract salt if found.

    # If salt was found, retrieve the corresponding encrypted vault from the vaults database.
    if salt:
        with sqlite3.connect(VAULTS_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT vault FROM user_vaults WHERE username = ?", (username,))
            result = cursor.fetchone()
            if result:
                vault = result[0] # Extract encrypted vault blob if found.

    return salt, vault # Return the retrieved salt and vault blob.

def password_features(password: str) -> dict:
    # Extract a set of features from a password string for the ML health prediction model.
    # Features include length, entropy, character types, repetition, ratios, and breach status.
    features = {
        "length": len(password),
        # Shannon entropy calculation based on character frequency.
        "entropy": math.log2(len(set(password)) ** len(password)) if password else 0,
        # Presence of uppercase letters.
        "has_upper": int(bool(re.search(r"[A-Z]", password))),
        # Presence of non-alphanumeric symbols.
        "has_symbol": int(bool(re.search(r"[^A-Za-z0-9]", password))),
        # Presence of common leetspeak characters.
        "has_leet": int(any(c in "@3!0" for c in password)),
        # Presence of character repetition (3 or more consecutive identical characters).
        "repetition": int(bool(re.search(r"(.)\1{2,}", password))),
        # Ratio of digits to total length.
        "digit_ratio": sum(c.isdigit() for c in password) / len(password) if password else 0,
        # Ratio of unique characters to total length.
        "unique_ratio": len(set(password)) / len(password) if password else 0,
        # Initialize complex features.
        "bigram_entropy": 0,
        "compression_ratio": 1.0,
        # Check if the password has been exposed in the Have I Been Pwned database.
        "hibp_breached": check_hibp(password)
    }
    # Calculate bigram entropy and compression ratio for passwords of length 2 or more.
    if password and len(password) >= 2:
        # Calculate entropy based on adjacent character pairs (bigrams).
        bigrams = [password[i:i+2] for i in range(len(password)-1)]
        from collections import Counter
        bigram_counts = Counter(bigrams)
        total_bigrams = sum(bigram_counts.values())
        features["bigram_entropy"] = -sum(
            (count / total_bigrams) * math.log2(count / total_bigrams)
            for count in bigram_counts.values()
        ) if total_bigrams else 0
        # Calculate the ratio of compressed size to original size using zlib.
        # Lower ratio might indicate more repetitive patterns.
        features["compression_ratio"] = len(zlib.compress(password.encode())) / len(password)
    return features

def check_hibp(password: str) -> int:
    # Query the 'Have I Been Pwned' (HIBP) Pwned Passwords API (v3) using k-Anonymity.
    # Checks if a password hash prefix exists in the HIBP database.
    # Returns 1 if the password hash suffix is found in the API response, 0 otherwise.
    # Calculate the SHA-1 hash of the password.
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    # Split the hash into a 5-character prefix and the remaining suffix.
    prefix, suffix = sha1[:5], sha1[5:]
    # Query the HIBP API with the hash prefix.
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    # Check if the hash suffix exists in the response text (list of suffixes for that prefix).
    return int(suffix in response.text)

def generate_password(length=12, use_symbols=True, memorable=False):
    # Generate a password, either random or memorable (word-based).
    if memorable:
        # Construct a memorable password using words from the loaded wordlist,
        # appended with numbers, aiming for the specified length.
        words = []
        total_length = 0
        # Select words randomly, ensuring the total length doesn't exceed the target minus space for numbers.
        while total_length < length - 4:  # Reserve space for up to 4 digits.
            word = secrets.choice(wordlist)
            # Stop if adding the next word would exceed the limit.
            if total_length + len(word) > length - 4:
                break
            words.append(word)
            total_length += len(word)
        
        # Append random digits to reach closer to the target length.
        numbers = ''.join(secrets.choice("0123456789") for _ in range(min(4, length - total_length)))
        
        # Combine words and numbers.
        password = ''.join(words) + numbers
        
        # If still shorter than required, pad with random characters.
        if len(password) < length:
            extra_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            if use_symbols:
                extra_chars += "!@#$%^&*" # Include symbols if requested.
            password += ''.join(secrets.choice(extra_chars) for _ in range(length - len(password)))
            
        # Trim if the process resulted in a password longer than requested.
        return password[:length]
    else:
        # Generate a completely random password using the specified character set and length.
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        if use_symbols:
            alphabet += "!@#$%^&*" # Include symbols if requested.
        # Select characters randomly from the alphabet.
        return "".join(secrets.choice(alphabet) for _ in range(length))

def generate_mnemonic(length=8) -> str:
    # Generate a mnemonic phrase consisting of a specified number of random words from the wordlist.
    # This phrase is used as the basis for deriving the user's encryption key.
    words = [secrets.choice(wordlist) for _ in range(length)]
    mnemonic = " ".join(words)
    logger.debug(f"Generated mnemonic: '{mnemonic}'")
    return mnemonic

def get_password_strength(password):
    # Predict the strength of a password (0: weak, 1: medium, 2: strong) using the pre-trained ML model.
    # Extracts features from the password and feeds them into the model.
    features = pd.DataFrame([password_features(password)])
    # Return the predicted strength label.
    return model.predict(features)[0]

def validate_username(username):
    """Validate username: non-empty, between 3 and 24 chars, alphanumeric plus @._-"""
    # Check if the username is provided and is a string.
    if not username or not isinstance(username, str):
        return False, "Username is required"
    # Check minimum length.
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    # Check maximum length.
    if len(username) > 24:
        return False, "Username must be 24 characters or less"
    # Check allowed characters using regex (letters, numbers, @, ., _, -).
    if not re.match(r'^[a-zA-Z0-9@._-]+$', username):
        return False, "Username can only contain letters, numbers, @, ., _, and -"
    # Return True if all checks pass.
    return True, ""

def validate_password(password):
    """Validate password: non-empty, max 48 chars"""
    # Check if the password is provided and is a string.
    if not password or not isinstance(password, str):
        return False, "Password is required"
    # Check maximum length.
    if len(password) > 48:
        return False, "Password must be 48 characters or less"
    # Return True if all checks pass.
    return True, ""

@app.route("/", methods=["GET"])
def login_page():
    # Render the login/registration page.
    # If the user is already logged in (session contains username and vault blob), redirect to the dashboard.
    if "username" in session and "vault_blob" in session:
        return redirect("/dashboard")
    # Otherwise, show the login page.
    return render_template("login.html")

@app.route("/dashboard", methods=["GET"])
def dashboard():
    # Render the main dashboard page displaying the user's password vault.
    # Requires the user to be logged in.
    # Redirect to login if session data is missing.
    if "username" not in session or "vault_blob" not in session:
        logger.warning("Dashboard access attempt without username or vault_blob in session.")
        return redirect("/")
        
    # Retrieve the encryption key from the secure cookie and the encrypted vault from the session.
    key_str = request.cookies.get('enc_key')
    encrypted_vault_blob = session["vault_blob"]
    
    # If the encryption key cookie is missing, log error, clear session/cookie, and redirect to login.
    if not key_str:
        logger.error(f"Encryption key cookie not found for user {session['username']} during dashboard load.")
        session.clear() # Clear potentially invalid session.
        response = make_response(redirect("/"))
        response.set_cookie('enc_key', '', expires=0) # Clear the key cookie.
        return response

    # Decode the key from string to bytes and create a Fernet instance.
    key = key_str.encode()
    fernet = Fernet(key)
    
    try:
        # Decrypt the vault blob stored in the session.
        decrypted_vault = fernet.decrypt(encrypted_vault_blob).decode()
        # Parse the decrypted JSON string into a Python dictionary.
        vault_data = json.loads(decrypted_vault)
        # Render the dashboard template, passing the decrypted vault data.
        return render_template("dashboard.html", vault=vault_data)
    except (InvalidToken, json.JSONDecodeError, TypeError) as e:
        # Handle potential decryption errors (e.g., invalid key, corrupted data).
        logger.error(f"Failed to decrypt or parse vault from session for {session['username']}: {e}")
        # Clear potentially corrupted session/cookie and redirect to login for safety.
        session.clear()
        response = make_response(redirect("/"))
        response.set_cookie('enc_key', '', expires=0)
        return response

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute") # Apply rate limiting to prevent brute-force attacks.
def login():
    # Handle user login attempts.
    # Verifies credentials, decrypts the vault, starts a session, and sets the encryption key cookie.
    username = request.form["username"]
    mnemonic = request.form["mnemonic"]
    logger.debug(f"Login attempt for {username} with mnemonic: '{mnemonic}'")
    
    # Retrieve the user's salt and encrypted vault blob from the database.
    salt, encrypted_vault_blob = get_vault(username)
    # If no vault blob is found, the user likely doesn't exist or has no vault.
    if not encrypted_vault_blob:
        logger.warning(f"User not found or vault missing: {username}")
        return render_template("login.html", error="User not found or vault missing")
        
    # Derive the encryption key using the provided mnemonic and the user's salt.
    key = derive_key(mnemonic, salt)
    
    try:
        # Attempt to decrypt the vault blob with the derived key to verify the mnemonic.
        decrypted_vault = decrypt_data(encrypted_vault_blob, key)
        # Parse the decrypted vault data (JSON) into a Python object.
        vault_data = json.loads(decrypted_vault)
        
        # If decryption is successful, store username and the ENCRYPTED vault blob in the session.
        # Storing the encrypted blob avoids keeping the plaintext vault in memory or session storage long-term.
        session["username"] = username
        session["vault_blob"] = encrypted_vault_blob
        logger.info(f"Login successful for {username}")
        
        # Create a response to render the dashboard.
        # Pass the initially decrypted vault data for the first render.
        response = make_response(render_template("dashboard.html", vault=vault_data))
        # Set the derived encryption key in an HttpOnly, Secure (if applicable), Lax SameSite cookie.
        # This key will be used for subsequent vault operations within the session.
        response.set_cookie('enc_key', key.decode('utf-8'), httponly=True, secure=request.is_secure, samesite='Lax')
        return response
        
    except InvalidToken:
        # Handle incorrect mnemonic (decryption failed).
        logger.debug(f"Invalid mnemonic for {username}")
        return render_template("login.html", error="Invalid mnemonic")
    except json.JSONDecodeError:
        # Handle cases where the decrypted vault data is not valid JSON.
        logger.error(f"Decrypted vault is not valid JSON for {username}")
        return render_template("login.html", error="Invalid vault data")

@app.route("/register", methods=["POST"])
def register():
    # Handle new user registration.
    # Generates a mnemonic, derives a key, creates an empty encrypted vault, and stores user info.
    username = request.form["username"]
    
    # Validate the chosen username based on defined rules.
    valid, message = validate_username(username)
    if not valid:
        logger.warning(f"Invalid username during registration: {message}")
        return render_template("login.html", error=message) # Show error on login page.
        
    # Ensure username is not just whitespace.
    if not username.strip():
        logger.warning("Missing or empty username")
        return "Bad Request: Username is required", 400
    # Check if the username is already taken.
    if username_exists(username):
        logger.warning(f"Username already taken: {username}")
        return render_template("login.html", error="Username already taken") # Show error on login page.
        
    # Generate a unique mnemonic phrase for the new user.
    mnemonic = generate_mnemonic()
    # Generate a cryptographically secure salt for the user.
    salt = secrets.token_bytes(16)
    # Derive the encryption key from the mnemonic and salt.
    key = derive_key(mnemonic, salt)
    # Create an initial empty vault structure as a JSON string.
    vault = json.dumps({"passwords": []})
    # Encrypt the empty vault using the derived key.
    encrypted_vault = encrypt_data(vault, key)
    
    # Sanity check: Try decrypting the newly encrypted vault to ensure the key works.
    try:
        decrypted_vault = decrypt_data(encrypted_vault, key)
        if decrypted_vault != vault:
            # This should ideally never happen if encryption/decryption logic is correct.
            logger.error(f"Decryption mismatch for {username}: expected {vault}, got {decrypted_vault}")
            raise ValueError("Encryption/decryption mismatch")
        logger.debug(f"Encryption verified for {username}")
    except Exception as e:
        # Log any error during the verification step.
        logger.error(f"Encryption verification failed for {username}: {e}")
        raise # Re-raise the exception to halt registration if verification fails.
        
    # Store the new user's details (username, salt, encrypted vault) in the databases.
    create_user(username, salt, encrypted_vault)
    logger.info(f"User {username} registered with mnemonic: '{mnemonic}'")
    # Render the login page with a success message including the mnemonic.
    return render_template("login.html", success=f"Account created! Your mnemonic is: {mnemonic}. Save it securely.")

@app.route("/add_password", methods=["POST"])
def add_password():
    # Handle adding a new password entry to the user's vault.
    # Requires decryption, modification, re-encryption, and database update.
    # Redirect if user is not logged in.
    if "username" not in session:
        logger.warning("Unauthorized add_password attempt")
        return redirect("/")
    username = session["username"]
    
    # Retrieve the encryption key from the cookie.
    key_str = request.cookies.get('enc_key')
    if not key_str:
        logger.error(f"Encryption key cookie not found for user {username}")
        return redirect("/") # Redirect if key is missing.
    key = key_str.encode()
    fernet = Fernet(key) # Initialize Fernet for decryption/encryption.

    # Helper function to render the dashboard with an error message.
    # This requires decrypting the current vault state from the session for display.
    def render_dashboard_with_error(error_message):
        try:
            encrypted_blob = session.get("vault_blob")
            if not encrypted_blob:
                raise ValueError("Vault blob missing from session")
            # Decrypt and parse the vault from session to display current state with error.
            current_vault_data = json.loads(fernet.decrypt(encrypted_blob).decode())
            return render_template("dashboard.html", vault=current_vault_data, error=error_message)
        except Exception as e:
            # Handle errors during decryption for error rendering (e.g., corrupted session).
            logger.error(f"Error decrypting session vault for error rendering: {e}")
            session.clear() # Clear potentially corrupted session.
            response = make_response(redirect("/"))
            response.set_cookie('enc_key', '', expires=0) # Clear key cookie.
            return response

    # Validate form inputs (site, username, password).
    try:
        site = request.form["site"]
        # Validate site name length.
        if not site or len(site) > 48:
            return render_dashboard_with_error("Site name must be between 1 and 48 characters")
        
        form_username = request.form["username"]
        # Validate username format, unless it's an API key entry.
        valid, message = validate_username(form_username)
        if not valid and site.upper() != "API":
            return render_dashboard_with_error(message)
        
        password = request.form["password"]
        # Validate password length.
        valid, message = validate_password(password)
        if not valid:
            return render_dashboard_with_error(message)
    except KeyError as e:
        # Handle missing form fields.
        logger.error(f"Missing required form field: {e}")
        return render_dashboard_with_error(f"Missing required field: {e}")
        
    # Retrieve the latest encrypted vault blob directly from the database to ensure consistency.
    salt, encrypted_vault_blob = get_vault(username)
    if not salt or not encrypted_vault_blob:
        # This indicates a potential issue with database consistency or user data.
        logger.error(f"Salt or vault blob not found for user {username} during add_password")
        return redirect("/") # Redirect to avoid further errors.

    # Decrypt the vault blob fetched from the database.
    try:
        vault_data = json.loads(fernet.decrypt(encrypted_vault_blob).decode())
    except (InvalidToken, json.JSONDecodeError):
        # Handle decryption/parsing errors for the database vault.
        logger.error(f"Failed to decrypt or parse vault for {username} during add_password")
        session.clear() # Clear session as state might be inconsistent.
        response = make_response(redirect("/"))
        response.set_cookie('enc_key', '', expires=0)
        return response

    # Check if the vault has reached the maximum allowed password entries (e.g., 50).
    try:
        if len(vault_data["passwords"]) >= 50:
            logger.warning(f"Vault full for {username}")
            # Render dashboard with an error message, showing the current vault state.
            return render_template("dashboard.html", vault=vault_data, 
                                  error="Your vault is full (maximum 50 passwords)")
    except (TypeError, KeyError):
        # Handle cases where vault_data might be malformed or empty. Initialize if necessary.
        vault_data = {"passwords": []}
        
    # Get optional URL field from the form.
    url = request.form.get("url", "").strip()

    # Append the new password entry to the vault data structure.
    # Includes site, password, category (determined by get_category), strength, username, API key (if applicable), and URL.
    vault_data["passwords"].append({
        "site": site,
        "password": password,
        "category": get_category(site, url=url), # Determine category based on site/URL.
        "strength": int(get_password_strength(password)), # Calculate password strength.
        "username": form_username,
        "api": request.form.get("api", ""), # Get API key if provided.
        "url": url # Store the URL.
    })
    
    # Re-encrypt the modified vault data.
    new_encrypted_vault = fernet.encrypt(json.dumps(vault_data).encode())
    # Update the encrypted vault blob in the database.
    with sqlite3.connect(VAULTS_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE user_vaults SET vault = ? WHERE username = ?", (new_encrypted_vault, username))
        conn.commit()
        
    # Update the session with the newly encrypted vault blob to keep it synchronized.
    session["vault_blob"] = new_encrypted_vault
    
    logger.info(f"Password added for {username}")
    # Render the dashboard, passing the updated (decrypted) vault data for display.
    return render_template("dashboard.html", vault=vault_data)

@app.route("/delete_password", methods=["POST"])
def delete_password():
    # Handle deleting a password entry from the user's vault by its index.
    # Requires decryption, modification, re-encryption, and database update.
    # Redirect if user is not logged in.
    if "username" not in session:
        logger.warning("Unauthorized delete_password attempt")
        return redirect("/")
    username = session["username"]
    
    # Retrieve encryption key from cookie.
    key_str = request.cookies.get('enc_key')
    if not key_str:
        logger.error(f"Encryption key cookie not found for user {username}")
        return redirect("/")
    key = key_str.encode()
    fernet = Fernet(key)

    # Helper function to render dashboard with an error (requires decryption).
    def render_dashboard_with_error(error_message):
        try:
            encrypted_blob = session.get("vault_blob")
            if not encrypted_blob:
                raise ValueError("Vault blob missing from session")
            current_vault_data = json.loads(fernet.decrypt(encrypted_blob).decode())
            return render_template("dashboard.html", vault=current_vault_data, error=error_message)
        except Exception as e:
            logger.error(f"Error decrypting session vault for error rendering: {e}")
            session.clear()
            response = make_response(redirect("/"))
            response.set_cookie('enc_key', '', expires=0)
            return response

    # Get the index of the password entry to delete from the form.
    try:
        index = int(request.form["index"])
    except (KeyError, ValueError):
        # Handle invalid or missing index.
        logger.warning(f"Invalid index provided for {username}")
        return render_dashboard_with_error("Invalid password selection")

    # Retrieve the latest encrypted vault blob from the database.
    salt, encrypted_vault_blob = get_vault(username)
    if not salt or not encrypted_vault_blob:
        logger.error(f"Salt or vault blob not found for user {username} during delete_password")
        return redirect("/")

    # Decrypt the vault blob.
    try:
        vault_data = json.loads(fernet.decrypt(encrypted_vault_blob).decode())
    except (InvalidToken, json.JSONDecodeError):
        # Handle decryption/parsing errors.
        logger.error(f"Failed to decrypt or parse vault for {username} during delete_password")
        session.clear()
        response = make_response(redirect("/"))
        response.set_cookie('enc_key', '', expires=0)
        return response

    # Check if the provided index is valid for the passwords list.
    if 0 <= index < len(vault_data["passwords"]):
        # Remove the password entry at the specified index.
        deleted_entry = vault_data["passwords"].pop(index)
        logger.info(f"Password for {deleted_entry['site']} deleted for {username}")
        
        # Store the deleted entry and its original index in the session for potential undo.
        if "deletion_stack" not in session:
            session["deletion_stack"] = []
        session["deletion_stack"].append({"entry": deleted_entry, "index": index})
        session.modified = True # Mark session as modified to ensure it's saved.
        
        # Re-encrypt the modified vault data.
        new_encrypted_vault = fernet.encrypt(json.dumps(vault_data).encode())
        # Update the encrypted vault in the database.
        with sqlite3.connect(VAULTS_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE user_vaults SET vault = ? WHERE username = ?", (new_encrypted_vault, username))
            conn.commit()
            
        # Update the session with the latest encrypted vault blob.
        session["vault_blob"] = new_encrypted_vault
        
        # Render the dashboard with a success message and an option to undo the deletion.
        return render_template("dashboard.html", vault=vault_data,
                               success=f"Password for {deleted_entry['site']} deleted successfully,",
                               show_undo=True)
    else:
        # Handle invalid index (out of range).
        logger.warning(f"Index {index} out of range for {username}")
        # Render dashboard with an error, showing the current vault state.
        return render_template("dashboard.html", vault=vault_data, error="Password not found")

@app.route("/undo_delete", methods=["POST"])
def undo_delete():
    # Handle undoing the last password deletion.
    # Retrieves the last deleted item from the session stack and re-inserts it into the vault.
    # Redirect if user is not logged in.
    if "username" not in session:
        logger.warning("Unauthorized undo_delete attempt")
        return redirect("/")
        
    username = session["username"]
    # Retrieve encryption key from cookie.
    key_str = request.cookies.get('enc_key')
    if not key_str:
        logger.error(f"Encryption key cookie not found for user {username}")
        return redirect("/")
    key = key_str.encode()
    fernet = Fernet(key)
        
    # Check if the deletion stack exists in the session and is not empty.
    if "deletion_stack" not in session or not session["deletion_stack"]:
        logger.warning(f"Undo attempt with empty stack for {username}")
        return redirect("/dashboard") # Redirect if nothing to undo.
    
    # Pop the last deleted item (entry and original index) from the stack.
    last_deleted = session["deletion_stack"].pop()
    session.modified = True # Mark session as modified.
    deleted_entry = last_deleted["entry"]
    original_index = last_deleted["index"]
    
    # Retrieve the latest encrypted vault blob from the database.
    salt, encrypted_vault_blob = get_vault(username)
    if not salt or not encrypted_vault_blob:
        logger.error(f"Salt or vault blob not found for user {username} during undo_delete")
        return redirect("/")
    
    # Decrypt the vault blob.
    try:
        vault_data = json.loads(fernet.decrypt(encrypted_vault_blob).decode())
    except (InvalidToken, json.JSONDecodeError):
        # Handle decryption/parsing errors.
        logger.error(f"Failed to decrypt/parse vault for {username} during undo")
        session.clear()
        response = make_response(redirect("/"))
        response.set_cookie('enc_key', '', expires=0)
        return response
    
    # Ensure the 'passwords' list exists in the vault data.
    if "passwords" not in vault_data:
        vault_data["passwords"] = []
        
    # Re-insert the deleted entry at its original index.
    # If the original index is now out of bounds (e.g., other deletions happened), append it.
    if original_index > len(vault_data["passwords"]):
        vault_data["passwords"].append(deleted_entry)
    else:
        vault_data["passwords"].insert(original_index, deleted_entry)
    
    # Re-encrypt the restored vault data.
    new_encrypted_vault = fernet.encrypt(json.dumps(vault_data).encode())
    # Update the encrypted vault in the database.
    with sqlite3.connect(VAULTS_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE user_vaults SET vault = ? WHERE username = ?", (new_encrypted_vault, username))
        conn.commit()
    
    # Update the session with the latest encrypted vault blob.
    session["vault_blob"] = new_encrypted_vault
    
    # Render the dashboard with a success message indicating the restoration.
    return render_template("dashboard.html", vault=vault_data, 
                         success=f"Password for {deleted_entry['site']} restored")

@app.route("/edit_password", methods=["POST"])
def edit_password():
    # Handle editing an existing password entry in the vault.
    # Requires decryption, modification based on form data, re-encryption, and database update.
    # Redirect if user is not logged in.
    if "username" not in session:
        logger.warning("Unauthorized edit_password attempt")
        return redirect("/")
    username = session["username"]
    # Retrieve encryption key from cookie.
    key_str = request.cookies.get('enc_key')
    if not key_str:
        logger.error(f"Encryption key cookie not found for user {username}")
        return redirect("/")
    key = key_str.encode()
    fernet = Fernet(key)

    # Helper function to render dashboard with an error (requires decryption).
    def render_dashboard_with_error(error_message):
        try:
            encrypted_blob = session.get("vault_blob")
            if not encrypted_blob:
                raise ValueError("Vault blob missing from session")
            current_vault_data = json.loads(fernet.decrypt(encrypted_blob).decode())
            return render_template("dashboard.html", vault=current_vault_data, error=error_message)
        except Exception as e:
            logger.error(f"Error decrypting session vault for error rendering: {e}")
            session.clear()
            response = make_response(redirect("/"))
            response.set_cookie('enc_key', '', expires=0)
            return response

    # Get the index of the password entry to edit from the form.
    try:
        index = int(request.form["index"])
    except (KeyError, ValueError):
        # Handle invalid or missing index.
        logger.warning(f"Invalid index provided for {username}")
        return render_dashboard_with_error("Invalid password selection")

    # Retrieve the latest encrypted vault blob from the database.
    salt, encrypted_vault_blob = get_vault(username)
    if not salt or not encrypted_vault_blob:
        logger.error(f"Salt or vault blob not found for user {username} during edit_password")
        return redirect("/")

    # Decrypt the vault blob.
    try:
        vault_data = json.loads(fernet.decrypt(encrypted_vault_blob).decode())
    except (InvalidToken, json.JSONDecodeError):
        # Handle decryption/parsing errors.
        logger.error(f"Failed to decrypt or parse vault for {username} during edit_password")
        session.clear()
        response = make_response(redirect("/"))
        response.set_cookie('enc_key', '', expires=0)
        return response
    
    # Validate the edited form inputs (username, password).
    try:
        edit_username = request.form["username"]
        # Ensure the index is valid before attempting to access the entry for validation.
        if not (0 <= index < len(vault_data.get("passwords", []))):
             return render_dashboard_with_error("Invalid password index for edit.")
        # Get the site name of the entry being edited (used for username validation logic).
        current_site = vault_data["passwords"][index]["site"]
        # Validate the edited username (required unless it's an API key).
        valid, message = validate_username(edit_username)
        if not valid and current_site.upper() != "API":
            return render_dashboard_with_error(message)
        
        edit_password = request.form["password"]
        # Validate the edited password.
        valid, message = validate_password(edit_password)
        if not valid:
            return render_dashboard_with_error(message)
    except KeyError as e:
        # Handle missing required form fields.
        logger.error(f"Missing required form field: {e}")
        return render_dashboard_with_error(f"Missing required field: {e}")
    except IndexError:
         # Handle index out of range error during validation access.
         logger.error(f"Index {index} out of range during edit validation for {username}")
         return render_dashboard_with_error("Password index out of range.")
    
    # Check if the index is valid before proceeding with the update.
    if 0 <= index < len(vault_data["passwords"]):
        # Get the original site name for the success message.
        site = vault_data["passwords"][index]["site"]
        # Update the password entry fields with the new values from the form.
        vault_data["passwords"][index]["username"] = edit_username
        vault_data["passwords"][index]["password"] = edit_password
        # Update API key if provided in the form.
        if "api" in request.form:
            vault_data["passwords"][index]["api"] = request.form["api"]
        # Update URL if provided in the form.
        if "url" in request.form:
            vault_data["passwords"][index]["url"] = request.form["url"]
        # Recalculate and update the password strength.
        vault_data["passwords"][index]["strength"] = int(get_password_strength(edit_password))
        
        # Re-encrypt the modified vault data.
        new_encrypted_vault = fernet.encrypt(json.dumps(vault_data).encode())
        # Update the encrypted vault in the database.
        with sqlite3.connect(VAULTS_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE user_vaults SET vault = ? WHERE username = ?", (new_encrypted_vault, username))
            conn.commit()
            
        # Update the session with the latest encrypted vault blob.
        session["vault_blob"] = new_encrypted_vault
        
        # Render the dashboard with a success message.
        return render_template("dashboard.html", vault=vault_data,
                               success=f"Password for {site} updated successfully")
    else:
        # Handle invalid index (out of range).
        logger.warning(f"Index {index} out of range for {username}")
        # Render dashboard with an error, showing the current vault state.
        return render_template("dashboard.html", vault=vault_data, error="Password not found")

@app.route("/generate_password", methods=["POST"])
def gen_password():
    # API endpoint for the password generator modal in the frontend.
    # Generates a password based on parameters received via POST request.
    # Get length, ensuring it's within the allowed range (8-24).
    length = int(request.form.get("length", 12))
    length = max(8, min(24, length))
    # Get boolean flags for using symbols and generating memorable passwords.
    use_symbols = request.form.get("symbols", "false") == "true"
    memorable = request.form.get("memorable", "false") == "true"
    # Generate the password using the utility function.
    password = generate_password(length, use_symbols, memorable)
    # Return the generated password as JSON.
    return jsonify({"password": password})

@app.route("/check_password", methods=["POST"])
def check_password():
    # Handle checking the health/strength of a single password provided via form.
    # Renders a result page showing the strength and improvement tips.
    password = request.form["password"]
    # Extract features from the password.
    features = pd.DataFrame([password_features(password)])
    # Predict the strength using the ML model.
    strength = model.predict(features)[0]
    # Provide basic improvement tips for weak passwords.
    tips = ["Add symbols", "Increase length"] if strength == 0 else []
    # Render the result template with strength, tips, and the password itself.
    return render_template("result.html", strength=strength, tips=tips, password=password)

@app.route("/delete_account", methods=["POST"])
def delete_account():
    # Handle permanent deletion of a user account.
    # Removes user data from both authentication and vault databases, clears session, and logs out.
    # Redirect if user is not logged in.
    if "username" not in session:
        return redirect("/")
    username = session["username"]
    
    # Delete user record from the authentication database.
    with sqlite3.connect(AUTH_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
    # Delete user's vault record from the vaults database.
    with sqlite3.connect(VAULTS_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_vaults WHERE username = ?", (username,))
        conn.commit()
        
    logger.info(f"User {username} deleted their account from both databases")
    # Clear all session data.
    session.clear()
    # Create a response to render the login page with a success message.
    response = make_response(render_template("login.html", success="Account deleted successfully"))
    # Clear the encryption key cookie.
    response.set_cookie('enc_key', '', expires=0)
    return response

@app.route("/logout", methods=["GET"])
def logout():
    # Handle user logout.
    # Clears the session and associated cookies, then redirects to the login page.
    logger.info(f"User {session.get('username', 'unknown')} logged out")
    # Clear all session data.
    session.clear()
    # Create a response to redirect to the login page.
    resp = make_response(redirect("/"))
    # Explicitly clear the session cookie and the encryption key cookie.
    resp.set_cookie('session', '', expires=0)
    resp.set_cookie('enc_key', '', expires=0)
    return resp

@app.route("/check_all_breaches", methods=["GET"])
@limiter.limit("10 per hour") # Limit frequency of breach checks per user.
def check_all_breaches():
    # API endpoint to check for data breaches related to sites stored in the user's vault
    # and general recent breaches. Requires user to be logged in.
    # Redirect if user is not logged in or session is incomplete.
    if "username" not in session or "vault_blob" not in session:
        logger.warning("Unauthorized breach check attempt.")
        return jsonify({"error": "Not authenticated"}), 401

    # Retrieve encryption key from cookie and encrypted vault from session.
    key_str = request.cookies.get('enc_key')
    encrypted_vault_blob = session["vault_blob"]
    
    # Handle missing encryption key.
    if not key_str:
        logger.error(f"Encryption key cookie not found for user {session['username']} during breach check.")
        return jsonify({"error": "Authentication key missing"}), 401

    # Decode key and initialize Fernet.
    key = key_str.encode()
    fernet = Fernet(key)

    try:
        # Decrypt the vault blob from the session.
        decrypted_vault = fernet.decrypt(encrypted_vault_blob).decode()
        # Parse the decrypted vault data.
        vault_data = json.loads(decrypted_vault)
        
        # Extract unique site names/domains from the user's vault entries.
        # Excludes generic entries like 'API', 'WiFi', 'Other', 'Custom'.
        sites = set()
        for entry in vault_data.get("passwords", []):
            site = entry.get("site")
            # Filter out non-website entries.
            if site and site.lower() not in ["api", "wifi", "other", "custom", ""]:
                try:
                    # Attempt to extract the base domain name (e.g., 'Google' from 'google.com').
                    # Handles potential variations like 'https://' prefixes.
                    domain = site.split('.')[0] if '.' in site else site
                    domain = domain.replace('https://','').replace('http://','').split('/')[0].lower()
                    if domain:
                         sites.add(domain.capitalize()) # Add capitalized domain to the set.
                except Exception:
                    # If domain extraction fails, use the site name as is.
                    sites.add(site)

        logger.info(f"Checking breaches for user sites: {sites}")

        # Fetch breach information specifically for the user's stored sites.
        user_breaches = []
        if sites:
            user_breaches = get_user_sites_breaches(list(sites))
            logger.info(f"Found {len(user_breaches)} breaches for user sites")

        # Fetch general recent breach news, excluding sites already checked to avoid duplicates.
        other_breaches = get_general_breaches(exclude_sites=sites)
        logger.info(f"Found {len(other_breaches)} general breaches")

        # Return the results as JSON, separated into user-specific and general breaches.
        return jsonify({
            "user_breaches": user_breaches,
            "other_breaches": other_breaches
        })

    except (InvalidToken, json.JSONDecodeError) as e:
        # Handle errors during vault decryption or parsing.
        logger.error(f"Failed to decrypt or parse vault from session for breach check: {e}")
        return jsonify({"error": "Failed to process vault data"}), 500
    except Exception as e:
        # Catch any other unexpected errors during the breach check process.
        logger.error(f"Unexpected error during breach check: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route("/get_url", methods=["GET"])
def site_url():
    """Return the canonical URL for a given site name based on predefined mapping."""
    # Used by the frontend to auto-populate the URL field when adding a known site.
    site = request.args.get("site", "")
    # Retrieve the URL using the get_url function from categories module.
    return jsonify({"url": get_url(site)})

if __name__ == "__main__":
    # Entry point for running the Flask application directly.
    # Ensures the databases are initialized before starting the server.
    init_db()
    # Run the Flask development server.
    # host="0.0.0.0" makes it accessible on the network.
    # debug=False should be used for production/deployment.
    app.run(host="0.0.0.0", port=5000, debug=False)