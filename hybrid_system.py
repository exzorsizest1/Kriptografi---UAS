"""
hybrid_system.py
================
Sistem Hybrid Encryption lengkap yang menggabungkan:
  - RSA manual (enkripsi/dekripsi AES key)
  - AES-256 EAX (enkripsi/dekripsi file)
  - SHA-256 Hashing (verifikasi integritas)
  - Digital Signature RSA manual (autentikasi pengirim)

ALUR MAHASISWA (ENKRIPSI):
  File → AES Encrypt → .enc
  AES Key → RSA Encrypt (pub dosen) → .key
  File → SHA-256 → Hash + Sign (priv mahasiswa) → .sig
  Hash → .hash

ALUR DOSEN (DEKRIPSI):
  .key → RSA Decrypt (priv dosen) → AES Key
  .enc + AES Key → AES Decrypt → File asli
  File + .sig + pub mahasiswa → Verify Signature
  File + .hash → Verify Hash
"""

import os
import time
import json

from rsa_module       import (load_public_key, load_private_key,
                               encrypt_aes_key, decrypt_aes_key)
from aes_module       import generate_aes_key, encrypt_file, decrypt_file
from hashing_module   import hash_file, save_hash, verify_integrity, load_hash
from signature_module import sign_file, save_signature, verify_signature, load_signature


# ─────────────────────────────────────────────
# 1. ENKRIPSI (Sisi Mahasiswa)
# ─────────────────────────────────────────────

def encrypt_assignment(
    input_file,
    dosen_public_key_path,
    student_private_key_path,
    output_folder="encrypted"
):
    """
    Proses lengkap enkripsi tugas oleh mahasiswa.

    Input:
      input_file               : path file tugas asli
      dosen_public_key_path    : path file public key dosen (.json)
      student_private_key_path : path file private key mahasiswa (.json)
      output_folder            : folder output file terenkripsi

    Output files di output_folder/:
      {filename}.enc  : file tugas terenkripsi (AES)
      {filename}.key  : AES key terenkripsi (RSA)
      {filename}.sig  : digital signature mahasiswa
      {filename}.hash : hash SHA-256 file asli

    Return: dict berisi semua info dan path file output
    """
    print("\n" + "=" * 60)
    print("   ENKRIPSI TUGAS MAHASISWA")
    print("=" * 60)
    start_total = time.time()

    os.makedirs(output_folder, exist_ok=True)
    filename = os.path.basename(input_file)

    # ── LANGKAH 1: Load kunci ──────────────────────────────────
    print("\n[STEP 1] Memuat kunci RSA...")
    dosen_pub_key   = load_public_key(dosen_public_key_path)
    student_priv_key = load_private_key(student_private_key_path)
    print("         [OK] Public Key dosen dimuat")
    print("         [OK] Private Key mahasiswa dimuat")

    # ── LANGKAH 2: Generate AES Key ───────────────────────────
    print("\n[STEP 2] Generate AES-256 key...")
    aes_key = generate_aes_key()
    print(f"         [OK] AES Key: {aes_key.hex()[:16]}... (32 bytes)")

    # ── LANGKAH 3: AES Encrypt File ───────────────────────────
    print("\n[STEP 3] Enkripsi file menggunakan AES-256...")
    enc_path = os.path.join(output_folder, filename + ".enc")
    enc_info = encrypt_file(input_file, enc_path, aes_key)
    print(f"         [OK] File terenkripsi: {enc_path}")

    # ── LANGKAH 4: RSA Encrypt AES Key ────────────────────────
    print("\n[STEP 4] Enkripsi AES key menggunakan RSA Public Key dosen...")
    t_rsa_start  = time.time()
    encrypted_key = encrypt_aes_key(aes_key, dosen_pub_key)
    t_rsa_enc    = time.time() - t_rsa_start

    key_path = os.path.join(output_folder, filename + ".key")
    with open(key_path, 'wb') as f:
        f.write(encrypted_key)
    print(f"         [OK] Encrypted AES key disimpan: {key_path}")
    print(f"         [OK] Waktu RSA enkripsi: {t_rsa_enc:.4f} detik")

    # ── LANGKAH 5: Hash File Asli ──────────────────────────────
    print("\n[STEP 5] Menghitung hash SHA-256 file asli...")
    file_hash  = hash_file(input_file)
    hash_path  = save_hash(input_file, file_hash, output_folder=output_folder)
    print(f"         [OK] SHA-256: {file_hash[:20]}...")

    # ── LANGKAH 6: Digital Signature ──────────────────────────
    print("\n[STEP 6] Membuat digital signature...")
    t_sig_start = time.time()
    signature   = sign_file(input_file, student_priv_key)
    t_sig       = time.time() - t_sig_start

    sig_path = save_signature(signature, input_file, output_folder=output_folder)
    print(f"         [OK] Signature disimpan: {sig_path}")
    print(f"         [OK] Waktu signing: {t_sig:.4f} detik")

    # ── Ringkasan ──────────────────────────────────────────────
    total_time = time.time() - start_total
    print("\n" + "-" * 60)
    print("   RINGKASAN ENKRIPSI")
    print("-" * 60)
    print(f"   File asli        : {input_file}")
    print(f"   Ukuran file      : {enc_info['original_size']} bytes")
    print(f"   File .enc        : {enc_path}")
    print(f"   File .key        : {key_path}")
    print(f"   File .sig        : {sig_path}")
    print(f"   File .hash       : {hash_path}")
    print(f"   Total waktu      : {total_time:.4f} detik")
    print("-" * 60)

    return {
        "input_file"  : input_file,
        "enc_path"    : enc_path,
        "key_path"    : key_path,
        "sig_path"    : sig_path,
        "hash_path"   : hash_path,
        "file_hash"   : file_hash,
        "aes_key_hex" : aes_key.hex(),
        "total_time"  : round(total_time, 4),
        "rsa_enc_time": round(t_rsa_enc, 4),
        "sig_time"    : round(t_sig, 4),
        "aes_enc_time": enc_info["elapsed_time"]
    }


# ─────────────────────────────────────────────
# 2. DEKRIPSI (Sisi Dosen)
# ─────────────────────────────────────────────

def decrypt_assignment(
    enc_file,
    key_file,
    sig_file,
    hash_file_path,
    dosen_private_key_path,
    student_public_key_path,
    output_folder="decrypted"
):
    """
    Proses lengkap dekripsi dan verifikasi tugas oleh dosen.

    Input:
      enc_file                 : path file .enc
      key_file                 : path file .key
      sig_file                 : path file .sig
      hash_file_path           : path file .hash
      dosen_private_key_path   : path private key dosen (.json)
      student_public_key_path  : path public key mahasiswa (.json)
      output_folder            : folder output file terdekripsi

    Return: dict berisi semua info verifikasi
    """
    print("\n" + "=" * 60)
    print("   DEKRIPSI TUGAS (SISI DOSEN)")
    print("=" * 60)
    start_total = time.time()

    os.makedirs(output_folder, exist_ok=True)
    filename = os.path.basename(enc_file).replace('.enc', '')

    hasil = {
        "status"            : "UNKNOWN",
        "integrity_ok"      : False,
        "signature_ok"      : False,
        "decryption_ok"     : False,
        "integrity_msg"     : "",
        "signature_msg"     : "",
        "decryption_msg"    : "",
        "output_file"       : "",
        "total_time"        : 0
    }

    try:
        # -- LANGKAH 1: Load kunci ---------------------------------
        print("\n[STEP 1] Memuat kunci RSA dosen...")
        dosen_priv_key    = load_private_key(dosen_private_key_path)
        student_pub_key   = load_public_key(student_public_key_path)
        print("         [OK] Private Key dosen dimuat")
        print("         [OK] Public Key mahasiswa dimuat")

        # ── LANGKAH 2: RSA Decrypt AES Key ────────────────────
        print("\n[STEP 2] Mendekripsi AES key menggunakan RSA Private Key dosen...")
        t_rsa_start = time.time()
        with open(key_file, 'rb') as f:
            encrypted_key_bytes = f.read()

        aes_key   = decrypt_aes_key(encrypted_key_bytes, dosen_priv_key)
        t_rsa_dec = time.time() - t_rsa_start
        print(f"         [OK] AES Key berhasil didekripsi: {aes_key.hex()[:16]}...")
        print(f"         [OK] Waktu RSA dekripsi: {t_rsa_dec:.4f} detik")

        # ── LANGKAH 3: AES Decrypt File ───────────────────────
        print("\n[STEP 3] Mendekripsi file menggunakan AES-256...")
        output_file = os.path.join(output_folder, filename)
        dec_info    = decrypt_file(enc_file, output_file, aes_key)

        if dec_info["status"] == "SUCCESS":
            hasil["decryption_ok"]  = True
            hasil["decryption_msg"] = "[OK] Dekripsi AES berhasil"
            hasil["output_file"]    = output_file
            print(f"         [OK] File berhasil didekripsi: {output_file}")
        else:
            hasil["decryption_ok"]  = False
            hasil["decryption_msg"] = "[FAIL] Dekripsi AES GAGAL - File mungkin dimanipulasi"
            print(f"         [FAIL] Dekripsi GAGAL!")

        # -- LANGKAH 4: Verifikasi Hash ----------------------------
        print("\n[STEP 4] Verifikasi integritas hash SHA-256...")
        hash_data      = load_hash(hash_file_path)
        expected_hash  = hash_data["sha256"]

        if hasil["decryption_ok"]:
            int_ok, int_msg = verify_integrity(output_file, expected_hash)
        else:
            int_ok  = False
            int_msg = "[FAIL] INTEGRITAS GAGAL - Dekripsi tidak berhasil"

        hasil["integrity_ok"]  = int_ok
        hasil["integrity_msg"] = int_msg

        # -- LANGKAH 5: Verifikasi Digital Signature ----------------
        print("\n[STEP 5] Verifikasi digital signature mahasiswa...")
        sig_data = load_signature(sig_file)
        sig_bytes = sig_data["signature_bytes"]

        if hasil["decryption_ok"]:
            sig_ok, sig_msg = verify_signature(output_file, sig_bytes, student_pub_key)
        else:
            sig_ok  = False
            sig_msg = "[FAIL] SIGNATURE TIDAK DAPAT DIVERIFIKASI - Dekripsi gagal"

        hasil["signature_ok"]  = sig_ok
        hasil["signature_msg"] = sig_msg

    except Exception as e:
        print(f"\n[ERROR] Terjadi kesalahan: {e}")
        hasil["status"] = "ERROR"
        hasil["error"]  = str(e)

    # ── Tentukan status akhir ──────────────────────────────────
    if hasil["decryption_ok"] and hasil["integrity_ok"] and hasil["signature_ok"]:
        hasil["status"] = "AMAN"
    else:
        hasil["status"] = "GAGAL"

    total_time = time.time() - start_total
    hasil["total_time"] = round(total_time, 4)

    # ── Tampilkan Laporan ──────────────────────────────────────
    print("\n" + "=" * 60)
    print("   LAPORAN VERIFIKASI DOSEN")
    print("=" * 60)
    print(f"   Dekripsi AES     : {hasil['decryption_msg']}")
    print(f"   Integritas Hash  : {hasil['integrity_msg']}")
    print(f"   Digital Signature: {hasil['signature_msg']}")
    print(f"   Total waktu      : {total_time:.4f} detik")
    print("-" * 60)

    if hasil["status"] == "AMAN":
        print("   STATUS AKHIR : [OK] FILE AMAN DAN TERPERCAYA")
    else:
        print("   STATUS AKHIR : [FAIL] FILE BERMASALAH - INTEGRITAS/SIGNATURE GAGAL")

    print("=" * 60)

    return hasil


# ─────────────────────────────────────────────
# 3. Benchmark: RSA Murni vs Hybrid
# ─────────────────────────────────────────────

def benchmark_comparison(file_path, rsa_bits=512):
    """
    Membandingkan performa RSA murni vs Hybrid Encryption.

    Catatan: RSA murni tidak efisien untuk file besar karena
    ukuran plaintext harus lebih kecil dari n.
    Oleh karena itu, benchmark RSA murni diukur per-blok.

    Return: dict hasil benchmark
    """
    import math
    from rsa_module import generate_rsa_keys, rsa_encrypt, rsa_decrypt

    print("\n" + "=" * 60)
    print("   BENCHMARK: RSA MURNI vs HYBRID ENCRYPTION")
    print("=" * 60)

    with open(file_path, 'rb') as f:
        data = f.read()
    file_size = len(data)
    print(f"\nUkuran file: {file_size} bytes ({file_size/1024:.2f} KB)")

    # ── Benchmark Hybrid ──────────────────────────────────────
    print("\n--- HYBRID ENCRYPTION ---")
    from aes_module import generate_aes_key, encrypt_file, decrypt_file

    os.makedirs("encrypted", exist_ok=True)
    os.makedirs("decrypted", exist_ok=True)

    pub, priv = generate_rsa_keys(rsa_bits)
    aes_key   = generate_aes_key()

    # Hybrid enkripsi
    t_start = time.time()
    enc_info = encrypt_file(file_path, "encrypted/_bench.enc", aes_key)
    encrypt_aes_key(aes_key, pub)
    hybrid_enc_time = time.time() - t_start

    # Hybrid dekripsi
    t_start = time.time()
    decrypt_aes_key(encrypt_aes_key(aes_key, pub), priv)
    decrypt_file("encrypted/_bench.enc", "decrypted/_bench_result.bin", aes_key)
    hybrid_dec_time = time.time() - t_start

    # ── Benchmark RSA Murni (simulasi per-blok) ───────────────
    print("\n--- RSA MURNI (simulasi per-blok) ---")
    # RSA 512-bit dapat mengenkripsi maks ~63 bytes data
    block_size = 30    # byte per blok (konservatif)
    num_blocks = math.ceil(file_size / block_size)
    sample_block = data[:block_size]

    # Ukur waktu enkripsi satu blok × jumlah blok (estimasi)
    t_start = time.time()
    for _ in range(min(num_blocks, 50)):    # batasi max 50 iterasi untuk benchmark
        rsa_encrypt(sample_block, pub)
    t_one_batch = time.time() - t_start

    rsa_enc_time_est = (t_one_batch / min(num_blocks, 50)) * num_blocks
    rsa_dec_time_est = rsa_enc_time_est * 1.5    # dekripsi RSA biasanya ~1.5x lebih lambat

    # ── Tampilkan Hasil ───────────────────────────────────────
    print("\n" + "=" * 60)
    print(f"{'METODE':<25} {'ENC (detik)':<15} {'DEC (detik)':<15} {'KETERANGAN'}")
    print("-" * 60)
    print(f"{'Hybrid (AES+RSA)':<25} {hybrid_enc_time:<15.4f} {hybrid_dec_time:<15.4f} Direkomendasikan")
    print(f"{'RSA Murni (est.)':<25} {rsa_enc_time_est:<15.4f} {rsa_dec_time_est:<15.4f} Tidak efisien file besar")
    print("-" * 60)

    if rsa_enc_time_est > 0:
        speedup = rsa_enc_time_est / hybrid_enc_time
        print(f"\nHybrid {speedup:.1f}x lebih cepat dari RSA murni (estimasi)")

    print("\nKesimpulan:")
    print("  ✓ Hybrid Encryption jauh lebih efisien untuk file besar")
    print("  ✓ RSA hanya digunakan untuk mengenkripsi kunci AES (32 bytes)")
    print("  ✓ AES mengenkripsi file berukuran besar dengan cepat")
    print("=" * 60)

    return {
        "file_size"        : file_size,
        "hybrid_enc_time"  : round(hybrid_enc_time, 4),
        "hybrid_dec_time"  : round(hybrid_dec_time, 4),
        "rsa_enc_time_est" : round(rsa_enc_time_est, 4),
        "rsa_dec_time_est" : round(rsa_dec_time_est, 4)
    }


# ─────────────────────────────────────────────
# 4. Testing Mandiri
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("   TEST HYBRID SYSTEM")
    print("=" * 60)

    # Pastikan folder ada
    for folder in ["sender", "receiver", "encrypted", "decrypted", "testfiles"]:
        os.makedirs(folder, exist_ok=True)

    # ── Setup: Generate kunci dosen dan mahasiswa ──────────────
    from rsa_module    import generate_rsa_keys, save_keys
    from signature_module import generate_student_keys

    print("\n[SETUP] Generate kunci dosen...")
    pub_dosen, priv_dosen = generate_rsa_keys(bits=512)
    save_keys(pub_dosen, priv_dosen, folder="receiver", prefix="dosen")

    print("\n[SETUP] Generate kunci mahasiswa...")
    pub_mhs, priv_mhs = generate_student_keys("Budi", folder="sender", bits=512)

    # ── Buat file tugas test ───────────────────────────────────
    test_file = "testfiles/tugas_kriptografi.txt"
    with open(test_file, 'w') as f:
        f.write("TUGAS KRIPTOGRAFI\n")
        f.write("Nama  : Budi Santoso\n")
        f.write("NIM   : 12345678\n")
        f.write("Materi: Implementasi RSA dan AES\n" * 20)

    print(f"\n[SETUP] File test dibuat: {test_file}")

    # ── Enkripsi (mahasiswa) ───────────────────────────────────
    enc_result = encrypt_assignment(
        input_file               = test_file,
        dosen_public_key_path    = "receiver/dosen_public.json",
        student_private_key_path = "sender/mahasiswa_Budi_private.json",
        output_folder            = "encrypted"
    )

    # ── Dekripsi (dosen) ───────────────────────────────────────
    filename = os.path.basename(test_file)
    dec_result = decrypt_assignment(
        enc_file                = f"encrypted/{filename}.enc",
        key_file                = f"encrypted/{filename}.key",
        sig_file                = f"encrypted/{filename}.sig",
        hash_file_path          = f"encrypted/{filename}.hash",
        dosen_private_key_path  = "receiver/dosen_private.json",
        student_public_key_path = "sender/mahasiswa_Budi_public.json",
        output_folder           = "decrypted"
    )

    # ── Benchmark ─────────────────────────────────────────────
    benchmark_comparison(test_file)

    print("\n[HYBRID] Test selesai!")