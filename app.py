import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === Constants ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# === Session State Initialization ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === Utility Functions ===
def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    # If the file doesn't exist, return default user
    return {
        "khansa": {
            "password": hash_password("khansa456"),
            "data": []
        }
    }

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# === Load Data ===
stored_data = load_data()

# === UI Layout ===
st.set_page_config(page_title="Secure Vault", page_icon="🔐")
st.title("🔐 Secure Multi-User Data Vault")

menu = ["🏠 Home", "🔑 Login", "📝 Register", "📦 Store Data", "🔎 Retrieve Data"]
choice = st.sidebar.radio("📁 Navigation", menu)

# === Pages ===
if choice == "🏠 Home":
    st.subheader("Welcome to Your Encrypted Vault")
    st.markdown("""
    💬 This app allows multiple users to securely store and retrieve sensitive information using encryption.
    
    ✅ Each user has a personal vault  
    🔒 Data is encrypted using AES (Fernet)  
    🔁 Only you can decrypt your data using your chosen passkey  
    """)
    st.info("👈 Use the sidebar to Login, Register and access your vault.")

elif choice == "🔑 Login":
    st.subheader("Login to Your Account")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Locked out. Try again in {remaining} seconds.")
        st.stop()

    with st.form("login_form"):
        username = st.text_input("👤 Username")
        password = st.text_input("🔐 Password", type="password")
        submit = st.form_submit_button("Login")

        if submit:
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"✅ Welcome, {username}!")
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Invalid credentials! {remaining} attempts left.")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("🔒 Too many failed attempts. Locked for 60 seconds.")
                    st.stop()

elif choice == "📝 Register":
    st.subheader("Register a New Account")

    with st.form("register_form"):
        username = st.text_input("👤 Username")
        password = st.text_input("🔐 Password", type="password")
        confirm_password = st.text_input("🔐 Confirm Password", type="password")
        submit = st.form_submit_button("Register")

        if submit:
            if username in stored_data:
                st.error("❌ Username already exists! Please choose a different one.")
            elif password != confirm_password:
                st.error("❌ Passwords do not match!")
            elif username and password:
                hashed_password = hash_password(password)
                stored_data[username] = {"password": hashed_password, "data": []}
                save_data(stored_data)
                st.success("✅ Registration successful! You can now log in.")
            else:
                st.error("❌ Please fill in all fields.")

elif choice == "📦 Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("📁 Store Confidential Data")

        with st.form("store_data_form"):
            data = st.text_area("📝 Enter the data to encrypt")
            passkey = st.text_input("🔑 Your Passphrase (Encryption Key)", type="password")
            submit = st.form_submit_button("Encrypt & Save")

            if submit:
                if data and passkey:
                    encrypted = encrypt_text(data, passkey)
                    stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                    save_data(stored_data)
                    st.success("✅ Data encrypted and stored!")
                else:
                    st.error("Please provide both data and passphrase.")

elif choice == "🔎 Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("🔓 Retrieve & Decrypt Your Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ You haven't saved any data yet.")
        else:
            st.markdown("#### 🔐 Encrypted Entries:")
            for i, item in enumerate(user_data, 1):
                st.code(f"{i}. {item}", language="text")

            with st.form("decrypt_form"):
                encrypted_input = st.text_area("📋 Paste Encrypted Text to Decrypt")
                passkey = st.text_input("🔑 Enter Your Passphrase", type="password")
                submit = st.form_submit_button("Decrypt")

                if submit:
                    result = decrypt_text(encrypted_input, passkey)
                    if result:
                        st.success(f"✅ Decrypted Data:\n\n{result}")
                    else:
                        st.error("❌ Incorrect passkey or invalid data.")
