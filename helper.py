import random
import hashlib
import json


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y

    _, x, _ = extended_gcd(e % phi, phi)
    return (x % phi + phi) % phi


def is_prime(n, k=5):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits=512):
    while True:
        num = random.getrandbits(bits)
        num |= (1 << (bits - 1)) | 1

        if is_prime(num):
            return num


def generate_keypair(bits=1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537

    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = mod_inverse(e, phi)

    return (e, n), (d, n)


# ===========================================================
# RSA FUNCTIONS
# ===========================================================

def rsa_encrypt(public_key, plaintext):
    """Fungsi enkripsi RSA (digunakan juga untuk signing dengan private key)."""
    e, n = public_key
    # Karakter harus dikonversi ke int sebelum dienkripsi.
    return [pow(ord(char), e, n) for char in plaintext]


def rsa_decrypt(private_key, ciphertext):
    """Fungsi dekripsi RSA (digunakan juga untuk verification dengan public key)."""
    d, n = private_key
    # Karakter hasil dekripsi harus dikonversi kembali ke karakter string.
    return ''.join(chr(pow(char, d, n)) for char in ciphertext)


# ===========================================================
# DIGITAL SIGNATURE FUNCTIONS
# ===========================================================

def hash_message(message):
    """Menghasilkan hash SHA-256 dari sebuah string."""
    # Data yang di-hash adalah kunci DES terenkripsi + pesan terenkripsi DES.
    # Ini memastikan integritas dan keaslian kedua bagian.
    return hashlib.sha256(message.encode('utf-8')).hexdigest()

def rsa_sign(private_key, data_to_sign):
    """Menandatangani hash data menggunakan kunci privat (RSA Decrypt)."""
    # 1. Hashing data
    data_hash = hash_message(data_to_sign)
    
    # 2. Menandatangani hash menggunakan PRIVATE KEY (operasi enkripsi RSA)
    # Catatan: Dalam prakteknya, signing adalah dekripsi hash dengan private key.
    # Karena rsa_encrypt menggunakan (e, n) dan rsa_decrypt menggunakan (d, n), 
    # untuk signing, kita menggunakan (d, n) sebagai kunci 'publik' (alias private key).
    return rsa_encrypt(private_key, data_hash) 

def rsa_verify(public_key, data_to_verify, signature_list):
    """Memverifikasi tanda tangan menggunakan kunci publik (RSA Encrypt)."""
    # 1. Dekripsi/verifikasi tanda tangan menggunakan PUBLIC KEY (operasi dekripsi RSA)
    decrypted_hash = rsa_decrypt(public_key, signature_list) 
    
    # 2. Hitung hash lokal dari data yang diterima
    local_hash = hash_message(data_to_verify)
    
    # 3. Bandingkan hash yang didekripsi dengan hash lokal
    return decrypted_hash == local_hash


# ===========================================================
# HELPER FUNCTIONS
# ===========================================================

def generate_random_des_key():
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(8))


def encrypt_list_to_string(encrypted_list):
    return ",".join(map(str, encrypted_list))


def string_to_encrypted_list(encrypted_string):
    return [int(x) for x in encrypted_string.split(",")]


# ===========================================================
# DES PLACEHOLDER (XOR)
# ===========================================================

def des_encrypt(key, plaintext):
    """
    Placeholder DES: menggunakan XOR sederhana.
    """
    print(f"[Using placeholder DES_ENCRYPT with key '{key}']")

    key_bytes = key.encode()
    plain_bytes = plaintext.encode()
    key_len = len(key_bytes)

    cipher_bytes = bytearray()

    for i in range(len(plain_bytes)):
        cipher_bytes.append(plain_bytes[i] ^ key_bytes[i % key_len])

    return cipher_bytes.hex()


def des_decrypt(key, ciphertext_hex):
    """
    Placeholder DES decrypt: XOR sederhana.
    """
    print(f"[Using placeholder DES_DECRYPT with key '{key}']")

    key_bytes = key.encode()

    try:
        cipher_bytes = bytes.fromhex(ciphertext_hex)
    except ValueError:
        return "ERROR: Invalid hex data"

    key_len = len(key_bytes)
    plain_bytes = bytearray()

    for i in range(len(cipher_bytes)):
        plain_bytes.append(cipher_bytes[i] ^ key_bytes[i % key_len])

    try:
        return plain_bytes.decode()
    except UnicodeDecodeError:
        return "ERROR: Gagal decode (kunci salah)"