"""
rsa_module.py
=============
Implementasi RSA Manual tanpa library RSA siap pakai.
Mencakup: generate kunci, enkripsi, dekripsi, simpan/load kunci.

Rumus:
  n   = p × q
  phi = (p-1)(q-1)
  e   dipilih sehingga gcd(e, phi) = 1
  d   = modular inverse dari e terhadap phi
  Enkripsi  : C = M^e mod n
  Dekripsi  : M = C^d mod n
"""

import random
import math
import json
import os


# ─────────────────────────────────────────────
# 1. Fungsi Pembantu Bilangan Prima
# ─────────────────────────────────────────────

def is_prime(n, k=10):
    """
    Uji Miller-Rabin untuk menentukan apakah n adalah bilangan prima.
    k  = jumlah iterasi (semakin besar semakin akurat).
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Tulis n-1 sebagai 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)          # a^d mod n

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False           # n pasti komposit

    return True                    # n kemungkinan besar prima


def generate_prime(bits=512):
    """
    Generate bilangan prima acak dengan panjang `bits` bit.
    Terus mencoba hingga menemukan bilangan prima.
    """
    while True:
        # Buat angka acak dengan panjang `bits` bit
        candidate = random.getrandbits(bits)

        # Pastikan bit tertinggi dan terendah = 1
        # (agar panjang bit tepat dan angkanya ganjil)
        candidate |= (1 << (bits - 1))   # set bit tertinggi
        candidate |= 1                    # set bit terendah (ganjil)

        if is_prime(candidate):
            return candidate


# ─────────────────────────────────────────────
# 2. Fungsi Matematika RSA
# ─────────────────────────────────────────────

def gcd(a, b):
    """
    Menghitung Greatest Common Divisor (GCD) menggunakan algoritma Euclidean.
    """
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    """
    Menghitung modular inverse dari e terhadap phi menggunakan
    Extended Euclidean Algorithm.
    Mencari d sehingga: (e * d) mod phi = 1
    """
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError("Modular inverse tidak ada (e dan phi tidak relatif prima)")
    return x % phi


# ─────────────────────────────────────────────
# 3. Generate RSA Key Pair
# ─────────────────────────────────────────────

def generate_rsa_keys(bits=512):
    """
    Generate pasangan kunci RSA (Public Key & Private Key).

    Langkah:
      1. Generate dua bilangan prima p dan q
      2. Hitung n = p × q
      3. Hitung phi = (p-1)(q-1)
      4. Pilih e: 1 < e < phi dan gcd(e, phi) = 1
      5. Hitung d = modular inverse(e, phi)

    Return:
      public_key  = (e, n)
      private_key = (d, n)
    """
    print("[RSA] Generating bilangan prima p...")
    p = generate_prime(bits)

    print("[RSA] Generating bilangan prima q...")
    q = generate_prime(bits)

    # Pastikan p ≠ q
    while p == q:
        q = generate_prime(bits)

    # Hitung n dan phi
    n   = p * q
    phi = (p - 1) * (q - 1)

    # Pilih e (umum menggunakan 65537)
    e = 65537
    if gcd(e, phi) != 1:
        # Fallback: cari e lain jika 65537 tidak cocok
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    # Hitung d
    d = mod_inverse(e, phi)

    public_key  = (e, n)
    private_key = (d, n)

    print(f"[RSA] Key generated! n = {n.bit_length()} bit")
    return public_key, private_key


# ─────────────────────────────────────────────
# 4. RSA Encrypt & Decrypt (untuk data kecil)
# ─────────────────────────────────────────────

def rsa_encrypt(message_bytes, public_key):
    """
    Enkripsi data menggunakan RSA Public Key.

    RSA bekerja pada integer, sehingga bytes dikonversi ke integer.
    C = M^e mod n

    Parameter:
      message_bytes : data yang akan dienkripsi (bytes)
      public_key    : tuple (e, n)

    Return:
      ciphertext sebagai integer
    """
    e, n = public_key

    # Konversi bytes ke integer
    m = int.from_bytes(message_bytes, byteorder='big')

    # Validasi ukuran pesan
    if m >= n:
        raise ValueError(
            f"Pesan terlalu besar untuk kunci RSA ini. "
            f"Ukuran pesan: {m.bit_length()} bit, ukuran n: {n.bit_length()} bit"
        )

    # C = M^e mod n
    c = pow(m, e, n)
    return c


def rsa_decrypt(ciphertext_int, private_key):
    """
    Dekripsi data menggunakan RSA Private Key.

    M = C^d mod n

    Parameter:
      ciphertext_int : ciphertext sebagai integer
      private_key    : tuple (d, n)

    Return:
      plaintext sebagai bytes
    """
    d, n = private_key

    # M = C^d mod n
    m = pow(ciphertext_int, d, n)

    # Konversi integer kembali ke bytes
    # Hitung panjang bytes yang dibutuhkan
    byte_length = (m.bit_length() + 7) // 8
    return m.to_bytes(byte_length, byteorder='big')


# ─────────────────────────────────────────────
# 5. Simpan & Load Kunci RSA (format JSON)
# ─────────────────────────────────────────────

def save_keys(public_key, private_key, folder=".", prefix="rsa"):
    """
    Simpan public key dan private key ke file JSON.

    File yang dihasilkan:
      {prefix}_public.json
      {prefix}_private.json
    """
    os.makedirs(folder, exist_ok=True)

    e, n = public_key
    d, _ = private_key

    # Simpan public key
    pub_path = os.path.join(folder, f"{prefix}_public.json")
    with open(pub_path, 'w') as f:
        json.dump({"e": str(e), "n": str(n)}, f, indent=2)

    # Simpan private key
    priv_path = os.path.join(folder, f"{prefix}_private.json")
    with open(priv_path, 'w') as f:
        json.dump({"d": str(d), "n": str(n)}, f, indent=2)

    print(f"[RSA] Public key  disimpan: {pub_path}")
    print(f"[RSA] Private key disimpan: {priv_path}")
    return pub_path, priv_path


def load_public_key(filepath):
    """
    Load public key dari file JSON.
    Return: tuple (e, n)
    """
    with open(filepath, 'r') as f:
        data = json.load(f)
    return (int(data["e"]), int(data["n"]))


def load_private_key(filepath):
    """
    Load private key dari file JSON.
    Return: tuple (d, n)
    """
    with open(filepath, 'r') as f:
        data = json.load(f)
    return (int(data["d"]), int(data["n"]))


# ─────────────────────────────────────────────
# 6. Fungsi RSA untuk Encrypt/Decrypt AES Key
# ─────────────────────────────────────────────

def encrypt_aes_key(aes_key_bytes, public_key):
    """
    Enkripsi AES key (32 bytes) menggunakan RSA public key.
    AES key diubah menjadi integer lalu dienkripsi dengan RSA.

    Return: ciphertext sebagai bytes (untuk disimpan ke file)
    """
    c = rsa_encrypt(aes_key_bytes, public_key)

    # Konversi ciphertext integer ke bytes
    byte_length = (c.bit_length() + 7) // 8
    return c.to_bytes(byte_length, byteorder='big')


def decrypt_aes_key(encrypted_key_bytes, private_key):
    """
    Dekripsi AES key menggunakan RSA private key.

    Return: AES key sebagai bytes (32 bytes)
    """
    # Konversi bytes ke integer
    c = int.from_bytes(encrypted_key_bytes, byteorder='big')

    # Dekripsi
    decrypted = rsa_decrypt(c, private_key)

    # Padding: pastikan panjang = 32 bytes (AES-256)
    if len(decrypted) < 32:
        decrypted = decrypted.rjust(32, b'\x00')

    return decrypted


# ─────────────────────────────────────────────
# 7. Testing Mandiri
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("   TEST RSA MODULE")
    print("=" * 50)

    # Generate kunci
    pub, priv = generate_rsa_keys(bits=512)
    print(f"\nPublic Key  (e): {str(pub[0])[:30]}...")
    print(f"Public Key  (n): {str(pub[1])[:30]}...")
    print(f"Private Key (d): {str(priv[0])[:30]}...")

    # Test enkripsi/dekripsi pesan sederhana
    pesan = b"Hello RSA!"
    print(f"\nPesan asli   : {pesan}")

    cipher = rsa_encrypt(pesan, pub)
    print(f"Ciphertext   : {str(cipher)[:40]}...")

    hasil = rsa_decrypt(cipher, priv)
    # Hapus padding null di depan
    hasil = hasil.lstrip(b'\x00')
    print(f"Hasil dekripsi: {hasil}")

    # Simpan kunci
    save_keys(pub, priv, folder="sender", prefix="dosen")
    print("\n[RSA] Test selesai!")