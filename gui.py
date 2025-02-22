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

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load ML model
model = joblib.load("password_health_model.pkl")

# Load wordlist
with open("wordlist.txt", "r") as f:
    wordlist = [word.strip() for word in f.read().splitlines()]


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
    with sqlite3.connect("vault.db") as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt BLOB, vault BLOB)")


def create_user(username: str, salt: bytes, encrypted_vault: bytes):
    with sqlite3.connect("vault.db") as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO users (username, salt, vault) VALUES (?, ?, ?)",
                       (username, salt, encrypted_vault))


def username_exists(username):
    with sqlite3.connect("vault.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return cursor.fetchone() is not None


def get_vault(username: str) -> tuple:
    with sqlite3.connect("vault.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT salt, vault FROM users WHERE username = ?", (username,))
        return cursor.fetchone() or (None, None)


def delete_user(username):
    with sqlite3.connect("vault.db") as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))


# Password features
def password_features(password: str) -> dict:
    return {
        "length": len(password),
        "entropy": math.log2(len(set(password)) ** len(password)) if password else 0,
        "has_upper": int(bool(re.search(r"[A-Z]", password))),
        "has_symbol": int(bool(re.search(r"[^A-Za-z0-9]", password))),
        "has_leet": int(any(c in "@3!0" for c in password)),
        "repetition": int(bool(re.search(r"(.)\1{2,}", password))),
        "hibp_breached": check_hibp(password)
    }


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
    return " ".join(secrets.choice(wordlist) for _ in range(length))


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

        tk.Button(self, text="Add", command=self.add_password).pack(pady=5)
        tk.Button(self, text="Delete Account", command=self.delete_account).pack(pady=5)
        tk.Button(self, text="Logout", command=self.logout).pack()

    def update_vault_display(self):
        for widget in self.vault_frame.winfo_children():
            widget.destroy()
        for i, entry in enumerate(self.vault["passwords"]):
            frame = ttk.Frame(self.vault_frame)
            frame.pack(fill="x", pady=2)
            site_label = ttk.Label(frame, text=entry["site"], cursor="hand2")
            site_label.pack(side="left")
            site_label.bind("<Button-1>", lambda e, idx=i: self.toggle_password(idx))
            pwd_var = tk.StringVar(value="****")
            pwd_label = ttk.Label(frame, textvariable=pwd_var)
            pwd_label.pack(side="left", padx=10)
            self.vault[i]["pwd_var"] = pwd_var
            ttk.Button(frame, text="x", command=lambda idx=i: self.delete_password(idx), width=2).pack(side="right")

    def toggle_password(self, index):
        entry = self.vault["passwords"][index]
        pwd_var = self.vault[index]["pwd_var"]
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
        self.vault["passwords"].append({"site": site, "password": password})
        encrypted_vault = encrypt_data(json.dumps(self.vault), self.key)
        salt, _ = get_vault(self.username)
        create_user(self.username, salt, encrypted_vault)
        self.update_vault_display()
        self.new_password.delete(0, tk.END)

    def delete_password(self, index):
        if 0 <= index < len(self.vault["passwords"]):
            deleted = self.vault["passwords"].pop(index)
            encrypted_vault = encrypt_data(json.dumps(self.vault), self.key)
            salt, _ = get_vault(self.username)
            create_user(self.username, salt, encrypted_vault)
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