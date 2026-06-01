"""
hashing_module.py
=================
Implementasi hashing SHA-256 untuk verifikasi integritas file.

Fungsi utama:
  - Hitung hash SHA-256 dari file
  - Simpan hash ke file .hash
  - Verifikasi integritas dengan membandingkan hash
"""

import hashlib
import os
import json
import time


# ─────────────────────────────────────────────
# 1. Hitung Hash SHA-256 dari File
# ─────────────────────────────────────────────

def hash_file(filepath):
    """
    Menghitung hash SHA-256 dari sebuah file.

    SHA-256 menghasilkan digest 256-bit (32 bytes = 64 karakter hex).
    File dibaca per blok untuk efisiensi pada file besar.

    Parameter:
      filepath : path file yang akan di-hash

    Return: string hex SHA-256
    """
    sha256 = hashlib.sha256()
    block_size = 65536    # 64 KB per blok

    with open(filepath, 'rb') as f:
        while True:
            block = f.read(block_size)
            if not block:
                break
            sha256.update(block)

    digest = sha256.hexdigest()
    print(f"[HASH] SHA-256({os.path.basename(filepath)}) = {digest[:20]}...")
    return digest


# ─────────────────────────────────────────────
# 2. Hitung Hash SHA-256 dari Bytes
# ─────────────────────────────────────────────

def hash_bytes(data):
    """
    Menghitung hash SHA-256 dari data bytes langsung.

    Parameter:
      data : bytes yang akan di-hash

    Return: bytes (32 bytes digest)
    """
    return hashlib.sha256(data).digest()


def hash_bytes_hex(data):
    """
    Menghitung hash SHA-256 dari data bytes.
    Return: string hex
    """
    return hashlib.sha256(data).hexdigest()


# ─────────────────────────────────────────────
# 3. Simpan Hash ke File
# ─────────────────────────────────────────────

def save_hash(filepath, hash_value, output_folder="."):
    """
    Simpan hash ke file .hash dalam format JSON.

    Format file .hash:
      {
        "filename": "tugas.pdf",
        "sha256"  : "abc123...",
        "timestamp": "2024-..."
      }

    Parameter:
      filepath      : path file asli (untuk nama referensi)
      hash_value    : string hex hash SHA-256
      output_folder : folder penyimpanan file .hash
    """
    import datetime

    os.makedirs(output_folder, exist_ok=True)
    filename  = os.path.basename(filepath)
    hash_file_path = os.path.join(output_folder, filename + ".hash")

    data = {
        "filename" : filename,
        "sha256"   : hash_value,
        "timestamp": datetime.datetime.now().isoformat()
    }

    with open(hash_file_path, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"[HASH] Hash disimpan: {hash_file_path}")
    return hash_file_path


# ─────────────────────────────────────────────
# 4. Load Hash dari File
# ─────────────────────────────────────────────

def load_hash(hash_filepath):
    """
    Load hash dari file .hash.
    Return: dict berisi filename, sha256, timestamp
    """
    with open(hash_filepath, 'r') as f:
        data = json.load(f)
    return data


# ─────────────────────────────────────────────
# 5. Verifikasi Integritas File
# ─────────────────────────────────────────────

def verify_integrity(filepath, expected_hash):
    """
    Verifikasi integritas file dengan membandingkan hash SHA-256.

    Proses:
      1. Hitung hash file saat ini
      2. Bandingkan dengan hash yang tersimpan
      3. Jika sama = integritas terjaga
         Jika berbeda = file telah dimodifikasi

    Parameter:
      filepath      : path file yang akan diverifikasi
      expected_hash : hash yang diharapkan (dari file .hash)

    Return: tuple (bool, str) = (status, pesan)
    """
    print(f"\n[VERIFY] Memverifikasi integritas: {os.path.basename(filepath)}")

    # Hitung hash file saat ini
    current_hash = hash_file(filepath)

    print(f"[VERIFY] Hash tersimpan : {expected_hash[:30]}...")
    print(f"[VERIFY] Hash saat ini  : {current_hash[:30]}...")

    if current_hash == expected_hash:
        pesan = "[OK] INTEGRITAS TERJAGA - File tidak dimodifikasi"
        print(f"[VERIFY] {pesan}")
        return True, pesan
    else:
        pesan = "[FAIL] INTEGRITAS GAGAL - File telah dimodifikasi!"
        print(f"[VERIFY] {pesan}")
        return False, pesan


def verify_integrity_bytes(data_bytes, expected_hash):
    """
    Verifikasi integritas dari data bytes langsung.

    Parameter:
      data_bytes    : bytes yang akan diverifikasi
      expected_hash : hash hex yang diharapkan

    Return: tuple (bool, str)
    """
    current_hash = hashlib.sha256(data_bytes).hexdigest()

    if current_hash == expected_hash:
        return True, "[OK] INTEGRITAS TERJAGA"
    else:
        return False, "[FAIL] INTEGRITAS GAGAL"


# ─────────────────────────────────────────────
# 6. Testing Mandiri
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("   TEST HASHING MODULE")
    print("=" * 50)

    # Buat file test
    os.makedirs("testfiles", exist_ok=True)
    test_file = "testfiles/test_hash.txt"
    with open(test_file, 'w') as f:
        f.write("Ini adalah tugas mahasiswa A\nNIM: 12345678\n")

    # Hitung hash
    h = hash_file(test_file)
    print(f"Hash SHA-256: {h}")

    # Simpan hash
    save_hash(test_file, h, output_folder="encrypted")

    # Verifikasi (seharusnya PASS)
    ok, msg = verify_integrity(test_file, h)
    print(f"Status: {msg}")

    # Modifikasi file (simulasi serangan)
    with open(test_file, 'a') as f:
        f.write("Saya tambahkan nilai A+\n")

    # Verifikasi lagi (seharusnya FAIL)
    ok, msg = verify_integrity(test_file, h)
    print(f"Status setelah modifikasi: {msg}")

    print("\n[HASH] Test selesai!")