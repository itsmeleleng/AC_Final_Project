import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
import hashlib
import base64
import io
from Crypto.Random.random import getrandbits

st.set_page_config(page_title="Applied Cryptography Application", layout="wide")
st.title("Applied Cryptography Application")

menu = [
    "Symmetric Encryption/Decryption",
    "Asymmetric Encryption/Decryption",
    "Hashing",
    "Algorithm Information"
]
choice = st.sidebar.selectbox("Navigation", menu)

# --- Helper Functions ---

def pad(text, block_size):
    pad_len = block_size - len(text) % block_size
    return text + chr(pad_len) * pad_len

def unpad(text):
    pad_len = ord(text[-1])
    return text[:-pad_len]

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size).encode())
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def aes_decrypt(key, ciphertext):
    raw = base64.b64decode(ciphertext)
    iv = raw[:AES.block_size]
    ct = raw[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct).decode()
    return unpad(pt)

# --- RC4 Stream Cipher Implementation ---
def rc4(key, data):
    S = list(range(256))
    j = 0
    out = []
    key = [ord(c) for c in key]
    # KSA Phase
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # PRGA Phase
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(chr(ord(char) ^ K))
    return ''.join(out)

# --- Vigenère Cipher Implementation ---
def vigenere_encrypt(plaintext, key):
    key = key.upper()
    ciphertext = ""
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            k = ord(key[key_index % len(key)]) - 65
            c = chr((ord(char) - offset + k) % 26 + offset)
            ciphertext += c
            key_index += 1
        else:
            ciphertext += char
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    plaintext = ""
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            k = ord(key[key_index % len(key)]) - 65
            p = chr((ord(char) - offset - k) % 26 + offset)
            plaintext += p
            key_index += 1
        else:
            plaintext += char
    return plaintext

def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, plaintext):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ct = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ct).decode()

def rsa_decrypt(private_key, ciphertext):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    pt = cipher.decrypt(base64.b64decode(ciphertext))
    return pt.decode()

def ecc_generate_keys():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_bytes, pub_bytes

def ecc_encrypt(public_key_pem, plaintext):
    # ECC is not typically used for direct encryption, but for demonstration, we'll simulate with ECDH + symmetric
    public_key = serialization.load_pem_public_key(public_key_pem)
    ephemeral_key = ec.generate_private_key(ec.SECP384R1())
    shared_key = ephemeral_key.exchange(ec.ECDH(), public_key)
    aes_key = hashlib.sha256(shared_key).digest()
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size).encode())
    return base64.b64encode(cipher.iv + ct_bytes + ephemeral_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )).decode()

def ecc_decrypt(private_key_pem, ciphertext):
    # Simulate ECC decryption as above
    raw = base64.b64decode(ciphertext)
    iv = raw[:AES.block_size]
    ct = raw[AES.block_size:-215]  # 215 is length of PEM public key for SECP384R1
    ephemeral_pub_pem = raw[-215:]
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    ephemeral_pub = serialization.load_pem_public_key(ephemeral_pub_pem)
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_pub)
    aes_key = hashlib.sha256(shared_key).digest()
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct).decode()
    return unpad(pt)

def hash_text(text, algo):
    h = hashlib.new(algo)
    h.update(text.encode())
    return h.hexdigest()

def hash_file(file, algo):
    h = hashlib.new(algo)
    for chunk in iter(lambda: file.read(4096), b""):
        h.update(chunk)
    file.seek(0)
    return h.hexdigest()

# --- Diffie-Hellman Implementation ---
def dh_generate_params():
    # Use a small safe prime for demonstration (not secure for real use)
    p = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F
    g = 2
    return p, g

def dh_generate_private_key(p):
    return getrandbits(128) % p

def dh_generate_public_key(g, private_key, p):
    return pow(g, private_key, p)

def dh_compute_shared_secret(peer_public, private_key, p):
    return pow(peer_public, private_key, p)

def dh_shared_secret_to_aes_key(shared_secret):
    # Derive a 32-byte AES key from shared secret
    return hashlib.sha256(str(shared_secret).encode()).digest()

# --- UI Logic ---

if choice == "Symmetric Encryption/Decryption":
    st.header("Symmetric Encryption/Decryption")
    tab1, tab2 = st.tabs(["Text", "File"])
    with tab1:
        algo = st.selectbox("Algorithm", ["Block Cipher (AES)", "Stream Cipher (RC4)", "Vigenère Cipher"])
        mode = st.radio("Mode", ["Encrypt", "Decrypt"])
        text = st.text_area("Text")
        if algo == "Block Cipher (AES)":
            key = st.text_input("Key (16/24/32 bytes)", value="mysecretkey12345")
            key_bytes = key.encode().ljust(32, b'\0')[:32]
            if st.button("Run"):
                try:
                    if mode == "Encrypt":
                        result = aes_encrypt(key_bytes, text)
                    else:
                        result = aes_decrypt(key_bytes, text)
                    st.code(result)
                except Exception as e:
                    st.error(str(e))
        elif algo == "Stream Cipher (RC4)":
            key = st.text_input("RC4 Key (any length)", value="rc4key")
            if st.button("Run"):
                try:
                    if mode == "Encrypt":
                        result = base64.b64encode(rc4(key, text).encode()).decode()
                    else:
                        # decode from base64 before decrypting
                        result = rc4(key, base64.b64decode(text).decode())
                    st.code(result)
                except Exception as e:
                    st.error(str(e))
        elif algo == "Vigenère Cipher":
            key = st.text_input("Vigenère Key (letters only)", value="KEY")
            if st.button("Run"):
                try:
                    if mode == "Encrypt":
                        result = vigenere_encrypt(text, key)
                    else:
                        result = vigenere_decrypt(text, key)
                    st.code(result)
                except Exception as e:
                    st.error(str(e))
    with tab2:
        algo = st.selectbox("Algorithm (File)", ["Block Cipher (AES)", "Stream Cipher (RC4)"])
        mode = st.radio("Mode (File)", ["Encrypt", "Decrypt"])
        uploaded_file = st.file_uploader("Upload File", type=None)
        if uploaded_file:
            key = st.text_input("Key", value="filekey123456789")
            if st.button("Run File Crypto"):
                try:
                    file_bytes = uploaded_file.read()
                    if algo == "Block Cipher (AES)":
                        key_bytes = key.encode().ljust(32, b'\0')[:32]
                        if mode == "Encrypt":
                            cipher = AES.new(key_bytes, AES.MODE_CBC)
                            ct_bytes = cipher.encrypt(pad(file_bytes.decode(errors='ignore'), AES.block_size).encode())
                            out = cipher.iv + ct_bytes
                        else:
                            iv = file_bytes[:AES.block_size]
                            ct = file_bytes[AES.block_size:]
                            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                            pt = cipher.decrypt(ct)
                            out = pt
                    elif algo == "Stream Cipher (RC4)":
                        if mode == "Encrypt":
                            out = rc4(key, file_bytes.decode(errors='ignore')).encode()
                        else:
                            out = rc4(key, file_bytes.decode(errors='ignore')).encode()
                    st.download_button("Download Result", data=out, file_name="result.bin")
                except Exception as e:
                    st.error(str(e))

elif choice == "Asymmetric Encryption/Decryption":
    st.header("Asymmetric Encryption/Decryption")
    algo = st.selectbox("Algorithm", ["RSA", "Diffie-Hellman"])
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])
    text = st.text_area("Text")
    if algo == "RSA":
        priv, pub = st.columns(2)
        with priv:
            private_key = st.text_area("Private Key (PEM)", height=150)
            if st.button("Generate RSA Keys"):
                priv_key, pub_key = rsa_generate_keys()
                st.code(priv_key.decode())
                st.code(pub_key.decode())
        with pub:
            public_key = st.text_area("Public Key (PEM)", height=150)
        if st.button("Run RSA"):
            try:
                if mode == "Encrypt":
                    result = rsa_encrypt(public_key, text)
                else:
                    result = rsa_decrypt(private_key, text)
                st.code(result)
            except Exception as e:
                st.error(str(e))
    elif algo == "Diffie-Hellman":
        st.markdown("#### Diffie-Hellman Key Exchange (for demonstration, uses AES for encryption with shared secret)")
        p, g = dh_generate_params()
        st.code(f"p = {p}\ng = {g}")
        col1, col2 = st.columns(2)
        with col1:
            priv1 = st.text_input("Your Private Key (leave blank to generate)", value="")
            if st.button("Generate My Private Key"):
                priv1 = str(dh_generate_private_key(p))
                st.code(priv1)
            pub1 = st.text_input("Your Public Key", value="")
            if st.button("Compute My Public Key"):
                if priv1:
                    pub1 = str(dh_generate_public_key(g, int(priv1), p))
                    st.code(pub1)
        with col2:
            peer_pub = st.text_input("Peer's Public Key", value="")
        shared_secret = None
        if priv1 and peer_pub:
            try:
                shared_secret = dh_compute_shared_secret(int(peer_pub), int(priv1), p)
                st.success(f"Shared Secret: {shared_secret}")
            except Exception as e:
                st.error(str(e))
        if shared_secret:
            aes_key = dh_shared_secret_to_aes_key(shared_secret)
            if st.button("Run DH AES Crypto"):
                try:
                    if mode == "Encrypt":
                        result = aes_encrypt(aes_key, text)
                    else:
                        result = aes_decrypt(aes_key, text)
                    st.code(result)
                except Exception as e:
                    st.error(str(e))

elif choice == "Hashing":
    st.header("Hashing")
    tab1, tab2 = st.tabs(["Text", "File"])
    with tab1:
        algo = st.selectbox("Algorithm", ["sha256", "sha512", "md5", "sha1"])
        text = st.text_area("Text to Hash")
        if st.button("Hash Text"):
            try:
                result = hash_text(text, algo)
                st.code(result)
            except Exception as e:
                st.error(str(e))
    with tab2:
        algo = st.selectbox("Algorithm (File)", ["sha256", "sha512", "md5", "sha1"])
        uploaded_file = st.file_uploader("Upload File for Hashing", type=None, key="hashfile")
        if uploaded_file and st.button("Hash File"):
            try:
                result = hash_file(uploaded_file, algo)
                st.code(result)
            except Exception as e:
                st.error(str(e))

elif choice == "Algorithm Information":
    st.header("Algorithm Information")
    st.subheader("Symmetric Algorithms")
    st.markdown("""
- **AES**: Advanced Encryption Standard, widely used block cipher, 128/192/256-bit keys.
- **RC4**: Rivest Cipher 4, stream cipher, variable key length.
- **Vigenère Cipher**: Classic encryption algorithm using a keyword for shifting letters.
    """)
    st.subheader("Asymmetric Algorithms")
    st.markdown("""
- **RSA**: Rivest–Shamir–Adleman, public-key cryptosystem, widely used for secure data transmission.
- **Diffie-Hellman**: Key exchange protocol for establishing a shared secret over an insecure channel.
    """)
    st.subheader("Hashing Functions")
    st.markdown("""
- **SHA-256**: Secure Hash Algorithm 256-bit, widely used for integrity.
- **SHA-512**: Secure Hash Algorithm 512-bit, stronger variant.
- **MD5**: Message Digest 5, fast but not collision-resistant.
- **SHA-1**: Secure Hash Algorithm 1, legacy, not recommended for security.
    """)
    st.subheader("References")
    st.markdown("""
- [PyCryptodome](https://www.pycryptodome.org/)
- [cryptography](https://cryptography.io/)
- [hashlib](https://docs.python.org/3/library/hashlib.html)
    """)