"""
signature_module.py
===================
Implementasi Digital Signature menggunakan RSA manual.

Konsep:
  - Digital Signature = enkripsi hash menggunakan Private Key pengirim
  - Verifikasi        = dekripsi signature menggunakan Public Key pengirim
                        lalu bandingkan dengan hash file

Proses penandatanganan:
  1. Hitung hash SHA-256 dari file
  2. Enkripsi hash menggunakan Private Key mahasiswa → signature
  3. Simpan signature

Proses verifikasi:
  1. Hitung hash SHA-256 dari file yang diterima
  2. Dekripsi signature menggunakan Public Key mahasiswa → hash asli
  3. Bandingkan kedua hash
"""

import os
import json
import hashlib
from rsa_module import (
    generate_rsa_keys, save_keys, load_public_key, load_private_key,
    rsa_encrypt, rsa_decrypt
)
from hashing_module import hash_bytes


# ─────────────────────────────────────────────
# 1. Generate Key Pair untuk Mahasiswa
# ─────────────────────────────────────────────

def generate_student_keys(student_name, folder="sender", bits=512):
    """
    Generate pasangan kunci RSA untuk mahasiswa (pengirim).
    Kunci ini digunakan untuk digital signature.

    Private Key mahasiswa: untuk menandatangani file
    Public Key mahasiswa : untuk verifikasi tanda tangan

    Parameter:
      student_name : nama/NIM mahasiswa
      folder       : folder penyimpanan kunci
      bits         : panjang kunci RSA

    Return: (public_key, private_key)
    """
    print(f"[SIG] Generating kunci untuk mahasiswa: {student_name}")
    pub, priv = generate_rsa_keys(bits=bits)
    prefix = f"mahasiswa_{student_name.replace(' ', '_')}"
    save_keys(pub, priv, folder=folder, prefix=prefix)
    return pub, priv


# ─────────────────────────────────────────────
# 2. Buat Digital Signature
# ─────────────────────────────────────────────

def sign_file(filepath, private_key):
    """
    Membuat digital signature untuk sebuah file.

    Langkah:
      1. Baca isi file
      2. Hitung SHA-256 → hash digest (32 bytes)
      3. Enkripsi hash digest menggunakan Private Key mahasiswa
         signature = RSA_encrypt(hash, private_key)

    Catatan: Untuk digital signature, kita menggunakan Private Key
    untuk "signing" (bukan enkripsi biasa). Dalam RSA manual ini,
    kita menggunakan operasi yang sama: M^d mod n

    Parameter:
      filepath    : path file yang akan ditandatangani
      private_key : tuple (d, n) Private Key mahasiswa

    Return: bytes signature
    """
    # Baca file
    with open(filepath, 'rb') as f:
        data = f.read()

    # Hitung hash SHA-256
    file_hash = hash_bytes(data)    # 32 bytes
    print(f"[SIG] Hash file: {file_hash.hex()[:20]}...")

    # Enkripsi hash menggunakan Private Key (sign)
    # Sign = hash^d mod n
    d, n = private_key
    hash_int = int.from_bytes(file_hash, byteorder='big')

    # Pastikan hash < n
    if hash_int >= n:
        raise ValueError("Hash lebih besar dari n, gunakan kunci RSA yang lebih besar")

    signature_int = pow(hash_int, d, n)

    # Konversi ke bytes
    byte_length   = (signature_int.bit_length() + 7) // 8
    signature_bytes = signature_int.to_bytes(byte_length, byteorder='big')

    print(f"[SIG] Signature dibuat: {len(signature_bytes)} bytes")
    return signature_bytes


def sign_bytes(data_bytes, private_key):
    """
    Membuat digital signature dari data bytes langsung.

    Return: bytes signature
    """
    file_hash = hash_bytes(data_bytes)
    d, n = private_key
    hash_int = int.from_bytes(file_hash, byteorder='big')

    if hash_int >= n:
        raise ValueError("Hash lebih besar dari n")

    signature_int   = pow(hash_int, d, n)
    byte_length     = (signature_int.bit_length() + 7) // 8
    return signature_int.to_bytes(byte_length, byteorder='big')


# ─────────────────────────────────────────────
# 3. Simpan Signature
# ─────────────────────────────────────────────

def save_signature(signature_bytes, original_filepath, output_folder="."):
    """
    Simpan signature ke file .sig.

    Format file .sig: JSON berisi
      - filename   : nama file asli
      - signature  : signature dalam hex
      - algorithm  : "RSA-SHA256"

    Return: path file .sig
    """
    import datetime

    os.makedirs(output_folder, exist_ok=True)
    filename = os.path.basename(original_filepath)
    sig_path = os.path.join(output_folder, filename + ".sig")

    data = {
        "filename"  : filename,
        "signature" : signature_bytes.hex(),
        "algorithm" : "RSA-SHA256-MANUAL",
        "timestamp" : datetime.datetime.now().isoformat()
    }

    with open(sig_path, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"[SIG] Signature disimpan: {sig_path}")
    return sig_path


# ─────────────────────────────────────────────
# 4. Load Signature
# ─────────────────────────────────────────────

def load_signature(sig_filepath):
    """
    Load signature dari file .sig.
    Return: dict berisi info signature
    """
    with open(sig_filepath, 'r') as f:
        data = json.load(f)

    # Konversi hex kembali ke bytes
    data["signature_bytes"] = bytes.fromhex(data["signature"])
    return data


# ─────────────────────────────────────────────
# 5. Verifikasi Digital Signature
# ─────────────────────────────────────────────

def verify_signature(filepath, signature_bytes, public_key):
    """
    Verifikasi digital signature sebuah file.

    Langkah:
      1. Hitung SHA-256 dari file yang diterima → hash_sekarang
      2. Dekripsi signature menggunakan Public Key mahasiswa
         hash_asli = RSA_decrypt(signature, public_key)
         (verify = signature^e mod n)
      3. Bandingkan hash_sekarang vs hash_asli
         Jika sama → signature valid, file asli
         Jika beda → file telah dimodifikasi atau bukan dari pengirim asli

    Parameter:
      filepath        : path file yang akan diverifikasi
      signature_bytes : bytes signature
      public_key      : tuple (e, n) Public Key mahasiswa

    Return: tuple (bool, str)
    """
    print(f"\n[SIG] Verifikasi signature: {os.path.basename(filepath)}")

    # Baca file saat ini
    with open(filepath, 'rb') as f:
        data = f.read()

    # Hitung hash file saat ini
    current_hash = hash_bytes(data)
    print(f"[SIG] Hash file saat ini : {current_hash.hex()[:20]}...")

    # Dekripsi signature untuk mendapatkan hash asli
    e, n = public_key
    sig_int  = int.from_bytes(signature_bytes, byteorder='big')

    # Verify: sig^e mod n = hash_asli
    hash_asli_int    = pow(sig_int, e, n)
    hash_asli_length = (hash_asli_int.bit_length() + 7) // 8
    hash_asli_bytes  = hash_asli_int.to_bytes(hash_asli_length, byteorder='big')

    # Padding jika perlu (SHA-256 = 32 bytes)
    if len(hash_asli_bytes) < 32:
        hash_asli_bytes = hash_asli_bytes.rjust(32, b'\x00')

    print(f"[SIG] Hash dari signature: {hash_asli_bytes.hex()[:20]}...")

    if current_hash == hash_asli_bytes:
        pesan = "[OK] SIGNATURE VALID - File asli dari pengirim"
        print(f"[SIG] {pesan}")
        return True, pesan
    else:
        pesan = "[FAIL] SIGNATURE TIDAK VALID - File telah dimodifikasi atau pengirim palsu!"
        print(f"[SIG] {pesan}")
        return False, pesan


def verify_signature_bytes(data_bytes, signature_bytes, public_key):
    """
    Verifikasi signature dari data bytes langsung.
    Return: tuple (bool, str)
    """
    current_hash = hash_bytes(data_bytes)

    e, n = public_key
    sig_int  = int.from_bytes(signature_bytes, byteorder='big')

    hash_asli_int    = pow(sig_int, e, n)
    hash_asli_length = (hash_asli_int.bit_length() + 7) // 8
    hash_asli_bytes  = hash_asli_int.to_bytes(hash_asli_length, byteorder='big')

    if len(hash_asli_bytes) < 32:
        hash_asli_bytes = hash_asli_bytes.rjust(32, b'\x00')

    if current_hash == hash_asli_bytes:
        return True, "[OK] SIGNATURE VALID"
    else:
        return False, "[FAIL] SIGNATURE TIDAK VALID"


# ─────────────────────────────────────────────
# 6. Testing Mandiri
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("   TEST SIGNATURE MODULE")
    print("=" * 50)

    os.makedirs("testfiles", exist_ok=True)
    os.makedirs("sender",    exist_ok=True)
    os.makedirs("encrypted", exist_ok=True)

    # Buat file test
    test_file = "testfiles/tugas_mhs.txt"
    with open(test_file, 'w') as f:
        f.write("Laporan Kriptografi\nNIM: 12345678\nNama: Budi Santoso\n")

    # Generate kunci mahasiswa
    pub_mhs, priv_mhs = generate_student_keys("Budi_Santoso", folder="sender")

    # Tanda tangani file
    signature = sign_file(test_file, priv_mhs)
    sig_path  = save_signature(signature, test_file, output_folder="encrypted")

    # Verifikasi (harus VALID)
    ok, msg = verify_signature(test_file, signature, pub_mhs)
    print(f"\nHasil verifikasi: {msg}")

    # Modifikasi file
    with open(test_file, 'a') as f:
        f.write("Nilai: A+ (diubah oleh orang iseng)\n")

    # Verifikasi lagi (harus GAGAL)
    ok, msg = verify_signature(test_file, signature, pub_mhs)
    print(f"Setelah modifikasi: {msg}")

    print("\n[SIG] Test selesai!")