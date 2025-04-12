import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# # Generate a key (Note: in production, store securely)
# KEY = Fernet.generate_key()
# cipher = Fernet(KEY)


if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
cipher = Fernet(st.session_state.fernet_key)


# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "user_credentials" not in st.session_state:
    st.session_state.user_credentials = {}

if 'page' not in st.session_state:
    st.session_state.page = 'login'

if 'user_name' not in st.session_state:
    st.session_state.user_name = ''

if 'encrypted' not in st.session_state:
    st.session_state.encrypted = ''

if 'passkey' not in st.session_state:
    st.session_state.passkey = ''

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

# Hashing function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Encryption
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()


# Decryption
def decrypt_data(encrypted, passkey):
    hashed_passkey = hash_password(passkey)  # Hash the provided passkey

    # Check if the encrypted data exists in stored_data
    if encrypted in st.session_state.stored_data:
        # Validate the passkey
        if st.session_state.stored_data[encrypted]["passkey"] == str(passkey):
            try:
                # Decrypt the data using the fixed KEY
                decrypted_text = cipher.decrypt(encrypted.encode()).decode()
                st.session_state.failed_attempts = 0  # Reset failed attempts
                return decrypted_text
            except Exception as e:
                st.error(f"Decryption failed: {e}")
                return None
        else:
            # Increment failed attempts if passkey validation fails
            st.session_state.failed_attempts += 1
            return None
    else:
        st.error("The selected encrypted data does not exist.")
        return None

# Sign Up Page
def show_signup():
    st.title("📝 Sign Up")
    user_name = st.text_input("Enter Username:")
    password = st.text_input("Enter Password:", type="password")
    confirm_password = st.text_input("Confirm Password:", type="password")

    if st.button("Sign Up"):
        if user_name and password and confirm_password:
            if user_name in st.session_state.user_credentials:
                st.error("❌ Username already exists.")
            elif password != confirm_password:
                st.error("❌ Passwords do not match.")
            else:
                st.session_state.user_credentials[user_name] = hash_password(password)
                st.success("✅ Account created! Please log in.")
                st.session_state.page = 'login'
                st.rerun()
        else:
            st.error("⚠ All fields are required.")

    if st.button("Back to Login"):
        st.session_state.page = 'login'
        st.rerun()

# Login Page
def show_login():
    st.title("🔐 Login")
    user_name = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if user_name in st.session_state.user_credentials and \
                st.session_state.user_credentials[user_name] == hash_password(password):
            st.success(f"Welcome back, {user_name}!")
            st.session_state.logged_in = True
            st.session_state.user_name = user_name
            st.session_state.page = 'dashboard'
            st.rerun()
        else:
            st.error("❌ Invalid username or password.")

    if st.button("Go to Sign Up"):
        st.session_state.page = 'signup'
        st.rerun()

# Dashboard Page
def show_dashboard():
    st.sidebar.title("📚 Menu")
    choice = st.sidebar.radio("Choose an option", ["Store Data", "Decrypt Data", "Logout"])
    st.sidebar.markdown("---")
    st.sidebar.caption("🔒 Secure System by Amna Aftab Kifayat")

    st.title(f"👋 Welcome, {st.session_state.user_name}")

    if choice == "Store Data":
        st.subheader("🔐 Store Encrypted Data")
        user_data = st.text_area("Enter data to encrypt:")
        st.session_state.passkey = st.text_input("Enter a secret passkey:", type="password")

        if st.button("Encrypt & Store"):
            if user_data and st.session_state.passkey:
                encrypted = encrypt_data(user_data)
                st.session_state.stored_data[encrypted] = {
                    "encrypted_text": encrypted,
                    "passkey": str(st.session_state.passkey)
                }
                st.success("✅ Data encrypted and stored successfully!")
            else:
                st.error("⚠ Both fields are required.")

    elif choice == "Decrypt Data":
        st.subheader("🔍 Decrypt Your Data")

        if st.session_state.stored_data:
            selected_encrypted = st.selectbox("Select encrypted data to decrypt:", list(st.session_state.stored_data.keys()))
            entered_passkey = str(st.text_input("Enter your secret passkey:", type="password"))

            if st.button("Decrypt"):
                if selected_encrypted and entered_passkey:
                    decrypted = decrypt_data(selected_encrypted, entered_passkey)
                    if decrypted:
                        st.success("✅ Decrypted Data:")
                        st.code(decrypted, language="text")
                    else:
                        attempts_left = 3 - st.session_state.failed_attempts
                        st.error(f"❌ Wrong passkey! Attempts left: {attempts_left}")
                        if st.session_state.failed_attempts >= 3:
                            st.warning("🚫 Too many failed attempts. Logging out...")
                            st.session_state.logged_in = False
                            st.session_state.page = 'login'
                            st.rerun()
                else:
                    st.error("⚠ Please select a message and enter the passkey.")
        else:
            st.info("ℹ No encrypted data found yet.")

    elif choice == "Logout":
        st.session_state.page = 'login'
        st.session_state.logged_in = False
        st.session_state.user_name = ''
        st.success("🔓 Logged out successfully.")
        st.rerun()

# Routing Logic
if st.session_state.page == 'signup':
    show_signup()
elif st.session_state.page == 'login':
    show_login()
elif st.session_state.page == 'dashboard' and st.session_state.logged_in:
    show_dashboard()
else:
    st.session_state.page = 'login'
    st.rerun()