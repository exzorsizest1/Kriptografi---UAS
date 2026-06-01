"""
attack_simulation.py
====================
Simulasi serangan manipulasi file oleh pihak tidak bertanggung jawab.

Skenario serangan:
  - Mahasiswa iseng mengubah beberapa byte file .enc
  - File terenkripsi menjadi rusak
  - Saat dosen mendekripsi, integritas gagal

Jenis serangan yang disimulasikan:
  1. Byte flip  : mengubah beberapa byte di tengah file .enc
  2. Append     : menambahkan data di akhir file .enc
  3. Truncate   : memotong sebagian file .enc
"""

import os
import random
import shutil


# ─────────────────────────────────────────────
# 1. Serangan Byte Flip (ubah beberapa byte)
# ─────────────────────────────────────────────

def attack_byte_flip(enc_filepath, num_bytes=5):
    """
    Simulasi serangan: mengubah beberapa byte secara acak
    di dalam file .enc (di luar area nonce+tag).

    Area nonce (16 bytes pertama) dan tag (16 bytes berikutnya)
    sengaja dilewati agar perubahan ada di bagian data.

    Parameter:
      enc_filepath : path file .enc yang akan dimanipulasi
      num_bytes    : jumlah byte yang diubah

    Return: dict info serangan
    """
    print(f"\n[ATTACK] Melakukan byte flip pada: {enc_filepath}")

    # Baca file .enc
    with open(enc_filepath, 'rb') as f:
        data = bytearray(f.read())

    file_size = len(data)
    header_size = 32    # 16 nonce + 16 tag

    if file_size <= header_size + num_bytes:
        print("[ATTACK] File terlalu kecil untuk diserang!")
        return None

    # Pilih posisi acak di bagian data (setelah header)
    changed_positions = []
    for _ in range(num_bytes):
        pos = random.randint(header_size, file_size - 1)
        original_byte = data[pos]
        # XOR dengan nilai acak untuk mengubah byte
        data[pos] = original_byte ^ random.randint(1, 255)
        changed_positions.append((pos, original_byte, data[pos]))

    # Tulis kembali file yang sudah dimanipulasi
    with open(enc_filepath, 'wb') as f:
        f.write(bytes(data))

    info = {
        "attack_type"     : "byte_flip",
        "file"            : enc_filepath,
        "bytes_changed"   : num_bytes,
        "positions"       : changed_positions
    }

    print(f"[ATTACK] {num_bytes} byte berhasil diubah!")
    for pos, ori, new in changed_positions:
        print(f"         Posisi {pos}: 0x{ori:02X} → 0x{new:02X}")

    return info


# ─────────────────────────────────────────────
# 2. Serangan Append (tambah data di akhir)
# ─────────────────────────────────────────────

def attack_append(enc_filepath, extra_bytes=10):
    """
    Simulasi serangan: menambahkan bytes sampah di akhir file .enc.
    Menyebabkan ukuran file berubah dan dekripsi gagal.
    """
    print(f"\n[ATTACK] Menambahkan {extra_bytes} bytes di akhir: {enc_filepath}")

    garbage = os.urandom(extra_bytes)

    with open(enc_filepath, 'ab') as f:
        f.write(garbage)

    print(f"[ATTACK] {extra_bytes} bytes sampah ditambahkan!")
    return {"attack_type": "append", "file": enc_filepath, "extra_bytes": extra_bytes}


# ─────────────────────────────────────────────
# 3. Serangan Truncate (potong file)
# ─────────────────────────────────────────────

def attack_truncate(enc_filepath, cut_bytes=20):
    """
    Simulasi serangan: memotong beberapa byte dari akhir file.
    """
    print(f"\n[ATTACK] Memotong {cut_bytes} bytes dari akhir: {enc_filepath}")

    with open(enc_filepath, 'rb') as f:
        data = f.read()

    if len(data) <= cut_bytes:
        print("[ATTACK] File terlalu kecil untuk dipotong!")
        return None

    with open(enc_filepath, 'wb') as f:
        f.write(data[:-cut_bytes])

    print(f"[ATTACK] File dipotong: {len(data)} → {len(data) - cut_bytes} bytes")
    return {"attack_type": "truncate", "file": enc_filepath, "cut_bytes": cut_bytes}


# ─────────────────────────────────────────────
# 4. Backup & Restore File Asli
# ─────────────────────────────────────────────

def backup_file(filepath):
    """
    Buat backup file sebelum diserang.
    Backup disimpan dengan nama {filepath}.backup
    """
    backup_path = filepath + ".backup"
    shutil.copy2(filepath, backup_path)
    print(f"[ATTACK] Backup dibuat: {backup_path}")
    return backup_path


def restore_file(filepath):
    """
    Restore file dari backup.
    """
    backup_path = filepath + ".backup"
    if os.path.exists(backup_path):
        shutil.copy2(backup_path, filepath)
        print(f"[ATTACK] File dipulihkan dari backup: {filepath}")
        return True
    else:
        print(f"[ATTACK] Backup tidak ditemukan: {backup_path}")
        return False


# ─────────────────────────────────────────────
# 5. Laporan Serangan
# ─────────────────────────────────────────────

def generate_attack_report(attack_info):
    """
    Tampilkan laporan serangan dalam format yang mudah dibaca.
    """
    print("\n" + "=" * 50)
    print("   LAPORAN SIMULASI SERANGAN")
    print("=" * 50)

    if attack_info is None:
        print("Tidak ada serangan yang berhasil dilakukan.")
        return

    print(f"Jenis Serangan : {attack_info.get('attack_type', 'unknown').upper()}")
    print(f"File Target    : {attack_info.get('file', '-')}")

    if attack_info['attack_type'] == 'byte_flip':
        print(f"Byte Diubah    : {attack_info['bytes_changed']}")
        print(f"\nDetail perubahan:")
        for pos, ori, new in attack_info.get('positions', []):
            print(f"  Offset 0x{pos:04X}: {ori:08b} ({ori}) → {new:08b} ({new})")

    elif attack_info['attack_type'] == 'append':
        print(f"Bytes Ditambah : {attack_info['extra_bytes']}")

    elif attack_info['attack_type'] == 'truncate':
        print(f"Bytes Dipotong : {attack_info['cut_bytes']}")

    print("\nDampak yang diharapkan:")
    print("  - Verifikasi tag AES-EAX akan GAGAL")
    print("  - Hash SHA-256 akan BERBEDA")
    print("  - Signature verifikasi akan GAGAL")
    print("  - Dosen akan melihat pesan: INTEGRITAS GAGAL")
    print("=" * 50)


# ─────────────────────────────────────────────
# 6. Testing Mandiri
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("   TEST ATTACK SIMULATION MODULE")
    print("=" * 50)

    # Buat file dummy untuk diserang
    os.makedirs("encrypted", exist_ok=True)
    test_enc = "encrypted/test_attack.enc"

    # Tulis 16 bytes nonce + 16 bytes tag + konten dummy
    dummy_data = b'\x00' * 16 + b'\x11' * 16 + b"Ini adalah tugas saya yang sangat penting sekali!"
    with open(test_enc, 'wb') as f:
        f.write(dummy_data)

    print(f"File dummy dibuat: {test_enc} ({len(dummy_data)} bytes)")

    # Backup
    backup_file(test_enc)

    # Serang dengan byte flip
    info = attack_byte_flip(test_enc, num_bytes=3)
    generate_attack_report(info)

    # Restore
    restore_file(test_enc)

    print("\n[ATTACK] Test selesai!")