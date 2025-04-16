import streamlit as st
import hashlib
from cryptography.fernet import Fernet

FIXED_KEY = b'oYcQzEiLsYGW6NwqpwTbFkNmEqD04GHYWEFG1uHv_zg='  
cipher = Fernet(FIXED_KEY)

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # Format: {"encrypted_text": {"encrypted_text": "abc", "passkey": "hashed"}}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    stored_data = st.session_state.stored_data

    if encrypted_text in stored_data and stored_data[encrypted_text]["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# --- Streamlit UI ---

st.set_page_config(page_title="Secure Data Vault")
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# --- HOME ---
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.markdown("""
    Use this app to **securely store and retrieve your personal data** using encryption.
    
    - 🔐 Data is stored with your secret passkey.
    - 🔓 Retrieve it only by providing the correct passkey.
    - 🔄 After 3 failed attempts, login is required again.
    """)

# --- STORE DATA ---
elif choice == "Store Data":
    st.subheader("📂 Store Your Secure Data")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Set a Secret Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data Encrypted and Stored!")
            st.text(f"Copy this Encrypted Text to use later:\n\n{encrypted_text}")
        else:
            st.error("❗ Please enter both Data and Passkey.")

# --- RETRIEVE DATA ---
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    if st.session_state.failed_attempts >= 3:
        st.warning("🔒 Too many failed attempts. Please login again.")
        st.switch_page("Login")

    encrypted_input = st.text_area("Paste your Encrypted Data:")
    passkey_input = st.text_input("Enter your Secret Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success(f"✅ Decrypted Data:\n\n{result}")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect Passkey! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔐 Redirecting to Login Page...")
                    st.experimental_rerun()
        else:
            st.error("❗ Both fields are required.")

# --- LOGIN ---
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    master_password = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_password == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized. You can now retrieve data.")
            st.experimental_rerun()
        else:
            st.error("❌ Wrong Password!")
