import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox
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
from categories import get_category
import zlib                        # added for compression_ratio
from collections import Counter    # added for bigram_entropy

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load ML model
model = joblib.load("password_health_model.pkl")

# Load wordlist
with open("wordlist.txt", "r") as f:
    wordlist = [word.strip() for word in f.read().splitlines()]

# Database files
AUTH_DB = "auth.db"
VAULTS_DB = "vaults.db"

# Encryption utilities
def derive_key(mnemonic: str, salt: bytes) -> bytes:
    normalized_mnemonic = " ".join(word.strip() for word in mnemonic.split())
    hashed = hash_secret_raw(
        secret=normalized_mnemonic.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    key = base64.urlsafe_b64encode(hashed)
    return key


def encrypt_data(data: str, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())


def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()


# Database utilities
def init_db():
    # Initialize auth.db
    with sqlite3.connect(AUTH_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt BLOB)")
    # Initialize vaults.db
    with sqlite3.connect(VAULTS_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS user_vaults (username TEXT PRIMARY KEY, vault BLOB)")


def create_user(username: str, salt: bytes, encrypted_vault: bytes):
    # Insert into auth.db
    with sqlite3.connect(AUTH_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO users (username, salt) VALUES (?, ?)",
                       (username, salt))
    # Insert into vaults.db
    with sqlite3.connect(VAULTS_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO user_vaults (username, vault) VALUES (?, ?)",
                       (username, encrypted_vault))


def username_exists(username):
    # Check in auth.db
    with sqlite3.connect(AUTH_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return cursor.fetchone() is not None


def get_vault(username: str) -> tuple:
    salt = None
    vault = None
    # Get salt from auth.db
    with sqlite3.connect(AUTH_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            salt = result[0]

    # Get vault from vaults.db if salt was found
    if salt:
        with sqlite3.connect(VAULTS_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT vault FROM user_vaults WHERE username = ?", (username,))
            result = cursor.fetchone()
            if result:
                vault = result[0]

    return salt, vault  # Returns (None, None) if user not found or vault missing


def delete_user(username):
    # Delete from auth.db
    with sqlite3.connect(AUTH_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    # Delete from vaults.db
    with sqlite3.connect(VAULTS_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_vaults WHERE username = ?", (username,))


# Password features
def password_features(password: str) -> dict:
    # Extract features matching those used during model training
    features = {
        "length": len(password),
        "entropy": math.log2(len(set(password)) ** len(password)) if password else 0,
        "has_upper": int(bool(re.search(r"[A-Z]", password))),
        "has_symbol": int(bool(re.search(r"[^A-Za-z0-9]", password))),
        "has_leet": int(any(c in "@3!0" for c in password)),
        "repetition": int(bool(re.search(r"(.)\\1{2,}", password))),
        "digit_ratio": sum(c.isdigit() for c in password) / len(password) if password else 0,
        "unique_ratio": len(set(password)) / len(password) if password else 0,
        "bigram_entropy": 0,
        "compression_ratio": 1.0,
        "hibp_breached": check_hibp(password)
    }
    if password and len(password) >= 2:
        bigrams = [password[i:i+2] for i in range(len(password)-1)]
        counts = Counter(bigrams)
        total = sum(counts.values())
        features["bigram_entropy"] = -sum(
            (cnt/total) * math.log2(cnt/total) for cnt in counts.values()
        ) if total else 0
        features["compression_ratio"] = len(zlib.compress(password.encode())) / len(password)
    return features


def check_hibp(password: str) -> int:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    return int(suffix in response.text)


def generate_password(length=12, use_symbols=True, memorable=False):
    if memorable:
        # Generate a memorable password using words from wordlist with numbers
        words = []
        total_length = 0
        # Add words until we approach but don't exceed the target length
        while total_length < length - 4:  # Leave room for numbers
            word = secrets.choice(wordlist)
            if total_length + len(word) > length - 4:
                break
            words.append(word)
            total_length += len(word)
        
        # Add numbers at the end
        numbers = ''.join(secrets.choice("0123456789") for _ in range(min(4, length - total_length)))
        
        # Combine words and numbers
        password = ''.join(words) + numbers
        
        # If the password is still too short, add random characters
        if len(password) < length:
            extra_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            if use_symbols:
                extra_chars += "!@#$%^&*"
            password += ''.join(secrets.choice(extra_chars) for _ in range(length - len(password)))
            
        # If password is too long, trim it
        return password[:length]
    else:
        # Generate a random password
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        if use_symbols:
            alphabet += "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_mnemonic(length=5) -> str:
    return " ".join(secrets.choice(wordlist) for _ in range(length))


def get_password_strength(password):
    """Get password strength rating: 0 (weak), 1 (medium), 2 (strong)"""
    features = pd.DataFrame([password_features(password)])
    return model.predict(features)[0]


# GUI Application
class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Utility")
        self.geometry("600x400")
        # Set the favicon/icon for the window
        self.iconphoto(False, tk.PhotoImage(file="desktop_icon.png"))  # Load favicon
        self.username = None
        self.key = None
        self.vault = None
        init_db()
        self.show_login()

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear_window()
        tk.Label(self, text="Login", font=("Roboto", 20, "bold")).pack(pady=10)

        tk.Label(self, text="Username").pack()
        self.login_username = tk.Entry(self)
        self.login_username.pack(pady=5)

        tk.Label(self, text="Mnemonic").pack()
        self.login_mnemonic = tk.Entry(self, show="*")
        self.login_mnemonic.pack(pady=5)

        tk.Button(self, text="Login", command=self.login).pack(pady=10)
        tk.Button(self, text="Register", command=self.show_register).pack()

    def show_register(self):
        self.clear_window()
        tk.Label(self, text="Register", font=("Roboto", 20, "bold")).pack(pady=10)

        tk.Label(self, text="Username").pack()
        self.reg_username = tk.Entry(self)
        self.reg_username.pack(pady=5)

        tk.Button(self, text="Register", command=self.register).pack(pady=10)
        tk.Button(self, text="Back", command=self.show_login).pack()

    def login(self):
        username = self.login_username.get().strip()
        mnemonic = self.login_mnemonic.get()
        salt, vault = get_vault(username)
        if not vault:
            messagebox.showerror("Error", "User not found")
            return
        try:
            key = derive_key(mnemonic, salt)
            decrypted_vault = decrypt_data(vault, key)
            self.vault = json.loads(decrypted_vault)
            self.username = username
            self.key = key
            self.show_vault()
        except (InvalidToken, json.JSONDecodeError):
            messagebox.showerror("Error", "Invalid mnemonic")

    def register(self):
        username = self.reg_username.get().strip()
        if not username:
            messagebox.showerror("Error", "Username required")
            return
        if username_exists(username):
            messagebox.showerror("Error", "Username already taken")
            return
        mnemonic = generate_mnemonic()
        salt = secrets.token_bytes(16)
        key = derive_key(mnemonic, salt)
        vault = json.dumps({"passwords": []})
        encrypted_vault = encrypt_data(vault, key)
        create_user(username, salt, encrypted_vault)
        messagebox.showinfo("Success", f"Account created! Your mnemonic is:\n{mnemonic}\nSave it securely!")
        self.show_login()

    def show_vault(self):
        self.clear_window()
        tk.Label(self, text="Password Vault", font=("Roboto", 20, "bold")).pack(pady=10)

        self.vault_frame = ttk.Frame(self)
        self.vault_frame.pack(fill="both", expand=True)
        self.update_vault_display()

        tk.Label(self, text="Add Password").pack(pady=5)
        self.site_var = tk.StringVar(value="")
        sites = ["", "Google", "Facebook", "Twitter", "Amazon", "GitHub", "Other"]
        ttk.Combobox(self, textvariable=self.site_var, values=sites, state="readonly").pack(pady=5)
        self.custom_site = tk.Entry(self)
        self.custom_site.pack(pady=5)
        self.custom_site.pack_forget()  # Hide initially
        self.site_var.trace_add("write", self.toggle_custom_site)  # Updated to trace_add

        tk.Label(self, text="Password").pack()
        self.new_password = tk.Entry(self)
        self.new_password.pack(pady=5)

        # Add Generate Password button
        generate_btn = ttk.Button(self, text="Generate Password", command=self.show_password_generator)
        generate_btn.pack(pady=5)

        tk.Button(self, text="Add", command=self.add_password).pack(pady=5)
        tk.Button(self, text="Delete Account", command=self.delete_account).pack(pady=5)
        tk.Button(self, text="Logout", command=self.logout).pack()

    def show_password_generator(self):
        # Create a new top-level window for password generator
        generator_window = tk.Toplevel(self)
        generator_window.title("Password Generator")
        generator_window.geometry("400x300")
        generator_window.transient(self)  # Make it a modal window
        generator_window.grab_set()  # Make it take all input
        
        ttk.Label(generator_window, text="Password Generator", font=("Roboto", 16, "bold")).pack(pady=10)
        
        # Length slider
        length_frame = ttk.Frame(generator_window)
        length_frame.pack(fill="x", padx=20, pady=10)
        ttk.Label(length_frame, text="Length:").pack(side="left")
        length_value = ttk.Label(length_frame, text="12")
        length_value.pack(side="right")
        
        length_var = tk.IntVar(value=12)
        length_slider = ttk.Scale(generator_window, from_=8, to=24, variable=length_var, orient="horizontal")
        length_slider.pack(fill="x", padx=20)
        
        # Update the length value label when slider changes
        def update_length_label(*args):
            length_value.config(text=str(length_var.get()))
        
        length_var.trace_add("write", update_length_label)
        
        # Options checkboxes
        options_frame = ttk.Frame(generator_window)
        options_frame.pack(fill="x", padx=20, pady=10)
        
        symbols_var = tk.BooleanVar(value=True)
        symbols_check = ttk.Checkbutton(options_frame, text="Include special characters", variable=symbols_var)
        symbols_check.pack(anchor="w")
        
        memorable_var = tk.BooleanVar(value=False)
        memorable_check = ttk.Checkbutton(options_frame, text="Memorable password", variable=memorable_var)
        memorable_check.pack(anchor="w")
        
        # Generated password field
        password_frame = ttk.Frame(generator_window)
        password_frame.pack(fill="x", padx=20, pady=10)
        ttk.Label(password_frame, text="Generated Password:").pack(anchor="w")
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, textvariable=password_var, width=30)
        password_entry.pack(fill="x", pady=5)
        
        # Buttons
        buttons_frame = ttk.Frame(generator_window)
        buttons_frame.pack(fill="x", padx=20, pady=10)
        
        def generate():
            length = length_var.get()
            use_symbols = symbols_var.get()
            memorable = memorable_var.get()
            password = generate_password(length, use_symbols, memorable)
            password_var.set(password)
        
        def use_password():
            self.new_password.delete(0, tk.END)
            self.new_password.insert(0, password_var.get())
            generator_window.destroy()
        
        generate_btn = ttk.Button(buttons_frame, text="Generate", command=generate)
        generate_btn.pack(side="left", padx=5)
        
        copy_btn = ttk.Button(buttons_frame, text="Copy", command=lambda: self.clipboard_clear() or self.clipboard_append(password_var.get()))
        copy_btn.pack(side="left", padx=5)
        
        use_btn = ttk.Button(buttons_frame, text="Use This Password", command=use_password)
        use_btn.pack(side="right", padx=5)
        
        # Generate a password immediately
        generate()

    def update_vault_display(self):
        for widget in self.vault_frame.winfo_children():
            widget.destroy()
            
        # Group passwords by category
        categories = {}
        for i, entry in enumerate(self.vault["passwords"]):
            category = entry.get("category", "Other")
            if category not in categories:
                categories[category] = []
            categories[category].append((i, entry))
            
        # Display passwords by category
        for category, entries in categories.items():
            # Add category header
            category_label = ttk.Label(self.vault_frame, text=category, font=("Roboto", 11, "bold"))
            category_label.pack(anchor="w", pady=(10, 5))
            
            # Display entries in this category
            for i, entry in entries:
                frame = ttk.Frame(self.vault_frame)
                frame.pack(fill="x", pady=2)
                
                # Add strength indicator (small colored circle) - now first and bigger
                strength = entry.get("strength", 0)  # Default to 0 if not present
                strength_colors = {0: "#e74c3c", 1: "#f39c12", 2: "#27ae60"}  # Red, Orange, Green
                strength_label = tk.Label(frame, text="●", fg=strength_colors[strength], 
                                         font=("", 14), padx=0)
                strength_label.pack(side="left", padx=(0, 5))
                
                site_label = ttk.Label(frame, text=entry["site"], cursor="hand2")
                site_label.pack(side="left")
                site_label.bind("<Button-1>", lambda e, idx=i: self.toggle_password(idx))
                
                pwd_var = tk.StringVar(value="****")
                pwd_label = ttk.Label(frame, textvariable=pwd_var)
                pwd_label.pack(side="left", padx=10)
                entry["pwd_var"] = pwd_var
                ttk.Button(frame, text="x", command=lambda idx=i: self.delete_password(idx), width=2).pack(side="right")

    def toggle_password(self, index):
        entry = self.vault["passwords"][index]
        pwd_var = entry.get("pwd_var")
        current = pwd_var.get()
        pwd_var.set(entry["password"] if current == "****" else "****")

    def toggle_custom_site(self, *args):
        if self.site_var.get() == "Other":
            self.custom_site.pack(pady=5)
            self.custom_site.focus()
        else:
            self.custom_site.pack_forget()

    def add_password(self):
        site = self.site_var.get()
        if site == "Other":
            site = self.custom_site.get().strip()
        if not site:
            messagebox.showerror("Error", "Site required")
            return
        password = self.new_password.get()
        if not password:
            messagebox.showerror("Error", "Password required")
            return
        category = get_category(site)
        strength = get_password_strength(password)
        self.vault["passwords"].append({
            "site": site, 
            "password": password,
            "category": category,
            "strength": int(strength)
        })
        encrypted_vault = encrypt_data(json.dumps(self.vault), self.key)
        # Update only vaults.db
        with sqlite3.connect(VAULTS_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE user_vaults SET vault = ? WHERE username = ?", (encrypted_vault, self.username))
            conn.commit()
        self.update_vault_display()
        self.new_password.delete(0, tk.END)

    def delete_password(self, index):
        if 0 <= index < len(self.vault["passwords"]):
            deleted = self.vault["passwords"].pop(index)
            encrypted_vault = encrypt_data(json.dumps(self.vault), self.key)
            # Update only vaults.db
            with sqlite3.connect(VAULTS_DB) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE user_vaults SET vault = ? WHERE username = ?", (encrypted_vault, self.username))
                conn.commit()
            self.update_vault_display()
            messagebox.showinfo("Success", f"Password for {deleted['site']} deleted")

    def delete_account(self):
        if messagebox.askyesno("Confirm", "Delete account? This cannot be undone."):
            delete_user(self.username)
            self.logout()

    def logout(self):
        self.username = None
        self.key = None
        self.vault = None
        self.show_login()


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()