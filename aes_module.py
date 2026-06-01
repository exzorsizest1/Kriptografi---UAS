"""
aes_module.py
=============
Implementasi enkripsi/dekripsi file menggunakan AES-256.

Mode yang digunakan: AES.MODE_EAX
  - Authenticated encryption (enkripsi + autentikasi sekaligus)
  - Menghasilkan nonce (number used once) dan tag autentikasi
  - Aman dari modifikasi ciphertext

Library: pycryptodome
  pip install pycryptodome
"""

import os
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ─────────────────────────────────────────────
# 1. Generate AES Key
# ─────────────────────────────────────────────

def generate_aes_key():
    """
    Generate kunci AES-256 secara acak (32 bytes = 256 bit).
    Menggunakan get_random_bytes dari pycryptodome yang
    menggunakan sumber entropi kriptografis yang aman.

    Return: bytes (32 bytes)
    """
    key = get_random_bytes(32)    # 32 bytes = 256 bit
    print(f"[AES] Generated AES-256 key: {key.hex()[:20]}...")
    return key


# ─────────────────────────────────────────────
# 2. Enkripsi File
# ─────────────────────────────────────────────

def encrypt_file(input_path, output_path, aes_key):
    """
    Enkripsi file menggunakan AES-256 mode EAX.

    Format file .enc yang dihasilkan:
      [16 bytes nonce] + [16 bytes tag] + [ciphertext...]

    Nonce  : angka acak sekali pakai (16 bytes)
    Tag    : autentikasi integrity (16 bytes)
    Cipher : data terenkripsi

    Parameter:
      input_path  : path file asli
      output_path : path file .enc
      aes_key     : kunci AES (32 bytes)

    Return: dict berisi info enkripsi
    """
    start_time = time.time()

    # Baca file asli
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    file_size = len(plaintext)

    # Buat cipher AES mode EAX
    cipher = AES.new(aes_key, AES.MODE_EAX)

    # Enkripsi dan hasilkan tag autentikasi
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Simpan: nonce (16) + tag (16) + ciphertext
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(cipher.nonce)    # 16 bytes
        f.write(tag)             # 16 bytes
        f.write(ciphertext)      # sisanya

    elapsed = time.time() - start_time

    info = {
        "input_file"   : input_path,
        "output_file"  : output_path,
        "original_size": file_size,
        "encrypted_size": os.path.getsize(output_path),
        "nonce"        : cipher.nonce.hex(),
        "tag"          : tag.hex(),
        "elapsed_time" : round(elapsed, 4)
    }

    print(f"[AES] Enkripsi selesai!")
    print(f"      File asli   : {file_size} bytes")
    print(f"      File .enc   : {info['encrypted_size']} bytes")
    print(f"      Waktu       : {elapsed:.4f} detik")

    return info


# ─────────────────────────────────────────────
# 3. Dekripsi File
# ─────────────────────────────────────────────

def decrypt_file(input_path, output_path, aes_key):
    """
    Dekripsi file .enc menggunakan AES-256 mode EAX.

    Proses:
      1. Baca nonce (16 bytes pertama)
      2. Baca tag  (16 bytes berikutnya)
      3. Baca ciphertext (sisanya)
      4. Dekripsi dan verifikasi tag

    Parameter:
      input_path  : path file .enc
      output_path : path file hasil dekripsi
      aes_key     : kunci AES (32 bytes)

    Return: dict berisi info dekripsi, atau None jika gagal
    """
    start_time = time.time()

    # Baca file .enc
    with open(input_path, 'rb') as f:
        nonce      = f.read(16)    # 16 bytes nonce
        tag        = f.read(16)    # 16 bytes tag
        ciphertext = f.read()      # sisanya adalah ciphertext

    # Buat cipher untuk dekripsi menggunakan nonce yang sama
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)

    try:
        # Dekripsi dan verifikasi autentikasi
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # Simpan file hasil dekripsi
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        elapsed = time.time() - start_time

        info = {
            "input_file"    : input_path,
            "output_file"   : output_path,
            "decrypted_size": len(plaintext),
            "elapsed_time"  : round(elapsed, 4),
            "status"        : "SUCCESS"
        }

        print(f"[AES] Dekripsi berhasil!")
        print(f"      File hasil  : {len(plaintext)} bytes")
        print(f"      Waktu       : {elapsed:.4f} detik")

        return info

    except ValueError as e:
        # Tag verifikasi gagal = file telah dimodifikasi
        elapsed = time.time() - start_time
        print(f"[AES] DEKRIPSI GAGAL! Tag verifikasi tidak cocok.")
        print(f"      Kemungkinan file telah dimanipulasi!")

        return {
            "status"      : "FAILED",
            "error"       : str(e),
            "elapsed_time": round(elapsed, 4)
        }


# ─────────────────────────────────────────────
# 4. Benchmark AES
# ─────────────────────────────────────────────

def benchmark_aes(file_path):
    """
    Benchmark enkripsi dan dekripsi AES pada file tertentu.
    Menampilkan waktu enkripsi, waktu dekripsi, dan throughput.
    """
    print(f"\n[BENCHMARK AES] File: {file_path}")
    print("-" * 40)

    key = generate_aes_key()
    enc_path = "encrypted/benchmark_test.enc"
    dec_path = "decrypted/benchmark_result.bin"

    # Benchmark enkripsi
    enc_info = encrypt_file(file_path, enc_path, key)

    # Benchmark dekripsi
    dec_info = decrypt_file(enc_path, dec_path, key)

    file_size_mb = enc_info["original_size"] / (1024 * 1024)

    print(f"\n[BENCHMARK RESULT]")
    print(f"  Ukuran file     : {enc_info['original_size']} bytes ({file_size_mb:.2f} MB)")
    print(f"  Waktu enkripsi  : {enc_info['elapsed_time']} detik")
    print(f"  Waktu dekripsi  : {dec_info['elapsed_time']} detik")

    if enc_info['elapsed_time'] > 0:
        throughput = file_size_mb / enc_info['elapsed_time']
        print(f"  Throughput enc  : {throughput:.2f} MB/s")

    return enc_info, dec_info


# ─────────────────────────────────────────────
# 5. Testing Mandiri
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("   TEST AES MODULE")
    print("=" * 50)

    # Buat file test
    os.makedirs("testfiles", exist_ok=True)
    os.makedirs("encrypted", exist_ok=True)
    os.makedirs("decrypted", exist_ok=True)

    test_content = b"Ini adalah tugas kriptografi saya. " * 100
    test_file = "testfiles/test_tugas.txt"
    with open(test_file, 'wb') as f:
        f.write(test_content)

    print(f"\nFile test dibuat: {test_file} ({len(test_content)} bytes)")

    # Generate key
    key = generate_aes_key()

    # Enkripsi
    print("\n--- ENKRIPSI ---")
    enc_info = encrypt_file(test_file, "encrypted/test_tugas.enc", key)

    # Dekripsi
    print("\n--- DEKRIPSI ---")
    dec_info = decrypt_file("encrypted/test_tugas.enc", "decrypted/test_tugas.txt", key)

    # Verifikasi isi
    with open("decrypted/test_tugas.txt", 'rb') as f:
        hasil = f.read()

    if hasil == test_content:
        print("\n[OK] Verifikasi: Isi file sama persis!")
    else:
        print("\n[FAIL] Verifikasi: Isi file BERBEDA!")

    print("\n[AES] Test selesai!")