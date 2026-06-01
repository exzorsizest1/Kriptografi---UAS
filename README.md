# 🔐 Sistem Keamanan Pengiriman Data Rahasia
### Hybrid Encryption: RSA + AES-256 + SHA-256 + Digital Signature

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Crypto](https://img.shields.io/badge/Crypto-RSA%20%2B%20AES--256-purple?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen?style=for-the-badge)
![GUI](https://img.shields.io/badge/GUI-Tkinter-orange?style=for-the-badge)

**Implementasi sistem kriptografi hibrid untuk mengamankan pengiriman data pada instansi pemerintah.**  
Dibangun menggunakan RSA manual, AES-256-EAX, SHA-256, dan Digital Signature.

</div>

---

## 📋 Daftar Isi

- [Tentang Project](#-tentang-project)
- [Fitur Utama](#-fitur-utama)
- [Arsitektur Sistem](#-arsitektur-sistem)
- [Alur Kerja Sistem](#-alur-kerja-sistem)
- [Cara Kerja Digital Signature](#-cara-kerja-digital-signature)
- [Struktur Project](#-struktur-project)
- [Persyaratan Sistem](#-persyaratan-sistem)
- [Instalasi](#-instalasi)
- [Cara Menjalankan](#-cara-menjalankan)
- [Panduan Penggunaan GUI](#-panduan-penggunaan-gui)
- [Penjelasan Modul](#-penjelasan-modul)
- [Benchmark & Evaluasi](#-benchmark--evaluasi)
- [Simulasi Serangan](#-simulasi-serangan)
- [Keamanan Sistem](#-keamanan-sistem)
- [Kelemahan Sistem](#-kelemahan-sistem)
- [Contoh Output](#-contoh-output)
- [FAQ](#-faq)
- [Lisensi](#-lisensi)

---

## 🧩 Tentang Project

Project ini merupakan implementasi **Hybrid Encryption System** yang dirancang untuk menjawab kebutuhan keamanan pengiriman data pada instansi pemerintah daerah. Sistem lama yang mengirimkan file tanpa enkripsi rentan terhadap:

- Penyadapan isi file oleh pihak tidak berwenang
- Manipulasi data di tengah perjalanan pengiriman
- Pemalsuan identitas pengirim
- Tidak adanya jaminan keaslian dokumen

Solusi yang diimplementasikan menggabungkan kekuatan **RSA** (kriptografi asimetris) untuk distribusi kunci dan **AES-256** (kriptografi simetris) untuk enkripsi data, didukung **SHA-256** untuk verifikasi integritas dan **Digital Signature** untuk autentikasi pengirim.

### Mengapa Hybrid Encryption?

| Masalah | RSA Murni | Hybrid (RSA + AES) |
|---|---|---|
| File berukuran besar | ❌ Tidak bisa (maks ~245 bytes) | ✅ Tidak terbatas |
| Kecepatan enkripsi | ❌ Sangat lambat | ✅ Cepat (AES) |
| Keamanan distribusi kunci | ✅ Sangat aman | ✅ Sangat aman |
| Kebutuhan server | ❌ Berat | ✅ Efisien |
| Implementasi praktis | ❌ Tidak praktis | ✅ Sangat praktis |

---

## ✨ Fitur Utama

### 🔒 Enkripsi & Dekripsi
- **RSA Manual** — implementasi dari nol tanpa library RSA siap pakai
- **AES-256-EAX** — enkripsi file dengan authenticated encryption
- **Hybrid System** — AES mengenkripsi file, RSA mengenkripsi kunci AES

### 🛡 Keamanan Tambahan
- **SHA-256 Hashing** — verifikasi integritas file
- **Digital Signature RSA** — membuktikan keaslian pengirim
- **Tag Autentikasi EAX** — deteksi modifikasi ciphertext

### ⚔️ Simulasi Serangan
- **Byte Flip Attack** — mengubah byte acak di file `.enc`
- **Append Attack** — menambahkan data sampah di akhir file
- **Truncate Attack** — memotong sebagian isi file

### 📊 Benchmark & Evaluasi
- Perbandingan waktu RSA murni vs Hybrid Encryption
- Pengukuran throughput enkripsi (MB/s)
- Analisis efisiensi untuk file besar

### 🖥 GUI Lengkap
- Antarmuka grafis Tkinter modern bertema gelap
- Log proses real-time dengan kode warna
- Status keamanan dan integritas visual
- Tidak memerlukan pengetahuan kriptografi untuk digunakan

---

## 🏗 Arsitektur Sistem

```
┌─────────────────────────────────────────────────────────────┐
│                    HYBRID ENCRYPTION SYSTEM                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌──────────────┐    ┌──────────────┐    ┌─────────────┐  │
│   │  RSA Module  │    │  AES Module  │    │  Hash/Sig   │  │
│   │              │    │              │    │  Modules    │  │
│   │ • Key Gen    │    │ • AES-256    │    │             │  │
│   │ • Encrypt    │◄───│   EAX Mode   │    │ • SHA-256   │  │
│   │ • Decrypt    │    │ • File Enc   │    │ • Sign      │  │
│   │ • Mod Inv    │    │ • File Dec   │    │ • Verify    │  │
│   └──────────────┘    └──────────────┘    └─────────────┘  │
│          ▲                   ▲                   ▲          │
│          └───────────────────┴───────────────────┘          │
│                              │                              │
│                   ┌──────────────────┐                      │
│                   │  hybrid_system   │                      │
│                   │  (Orchestrator)  │                      │
│                   └──────────────────┘                      │
│                              │                              │
│                   ┌──────────────────┐                      │
│                   │     gui.py       │                      │
│                   │  (Tkinter GUI)   │                      │
│                   └──────────────────┘                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔄 Alur Kerja Sistem

### Sisi Pengirim (Enkripsi)

```
File Asli
    │
    ├──► [1] Generate AES Key (32 bytes acak)
    │
    ├──► [2] AES-256-EAX Encrypt ──────────────► file.enc
    │         (file → ciphertext)
    │
    ├──► [3] RSA Encrypt AES Key ──────────────► file.key
    │         menggunakan Public Key penerima
    │
    ├──► [4] SHA-256 Hash file asli ───────────► file.hash
    │
    └──► [5] Digital Signature ────────────────► file.sig
              (sign hash dengan Private Key pengirim)

              📦 Kirim: file.enc + file.key + file.sig + file.hash
```

### Sisi Penerima (Dekripsi + Verifikasi)

```
Terima: file.enc + file.key + file.sig + file.hash
    │
    ├──► [1] RSA Decrypt file.key ─────────────► AES Key
    │         menggunakan Private Key penerima
    │
    ├──► [2] AES-256-EAX Decrypt ──────────────► File Asli
    │         menggunakan AES Key
    │
    ├──► [3] Hitung SHA-256 file hasil
    │         Bandingkan dengan file.hash
    │         ├── Cocok   → ✅ INTEGRITAS TERJAGA
    │         └── Berbeda → ❌ INTEGRITAS GAGAL
    │
    └──► [4] Verifikasi Signature
              Dekripsi file.sig dengan Public Key pengirim
              Bandingkan hash
              ├── Cocok   → ✅ SIGNATURE VALID
              └── Berbeda → ❌ SIGNATURE TIDAK VALID
```

---

## ✍ Cara Kerja Digital Signature

Digital Signature adalah mekanisme kriptografi yang **membuktikan keaslian pengirim** dan **menjamin integritas** dokumen sekaligus. Berikut penjelasan lengkapnya:

### Konsep Dasar

Berbeda dengan enkripsi biasa (menggunakan Public Key untuk mengunci, Private Key untuk membuka), Digital Signature bekerja **terbalik**:

```
Enkripsi Biasa  :  Public Key ──► [KUNCI]  ──► Private Key  (kerahasiaan)
Digital Signature: Private Key ──► [TANDA TANGAN] ──► Public Key (keaslian)
```

Logikanya: hanya pemilik **Private Key** yang bisa membuat tanda tangan, tapi **siapapun** yang memiliki Public Key bisa memverifikasinya.

---

### Proses Penandatanganan (Signing) — Sisi Pengirim

```
                    ┌─────────────────────────────────────┐
                    │         PROSES SIGNING               │
                    └─────────────────────────────────────┘

File Asli (contoh: laporan.pdf)
    │
    ▼
┌───────────────────────────────┐
│   SHA-256 Hash Function       │   ← hashlib.sha256()
│                               │
│   Input : file bytes          │
│   Output: 32 bytes (256 bit)  │
│                               │
│   Hash = "a3f8c2d1e9..."      │
└───────────────────────────────┘
    │
    │  hash_int = int.from_bytes(hash, 'big')
    ▼
┌───────────────────────────────┐
│   RSA Sign (Private Key)      │   ← Operasi: signature = hash^d mod n
│                               │
│   d = Private Key exponent    │
│   n = modulus                 │
│                               │
│   signature_int = hash^d mod n│
└───────────────────────────────┘
    │
    ▼
signature.sig  ──► disimpan & dikirim bersama file
```

**Rumus matematis signing:**
```
signature = hash_integer ^ d  mod n

Dimana:
  hash_integer = SHA-256(file) dikonversi ke integer
  d            = Private Key exponent pengirim
  n            = modulus RSA pengirim
```

---

### Proses Verifikasi — Sisi Penerima

```
                    ┌─────────────────────────────────────┐
                    │       PROSES VERIFIKASI              │
                    └─────────────────────────────────────┘

File Diterima + signature.sig + public_key_pengirim
    │                │
    │                │ sig_int = int.from_bytes(signature, 'big')
    │                ▼
    │   ┌────────────────────────────┐
    │   │  RSA Verify (Public Key)   │  ← Operasi: hash_asli = sig^e mod n
    │   │                            │
    │   │  e = Public Key exponent   │
    │   │  n = modulus               │
    │   │                            │
    │   │  hash_asli = sig^e mod n   │
    │   └────────────────────────────┘
    │                │
    │                │ hash_asli_bytes
    ▼                ▼
┌───────────────────────────────────────────┐
│           PERBANDINGAN HASH               │
│                                           │
│  hash_sekarang = SHA-256(file diterima)   │
│  hash_asli     = hasil dekripsi signature │
│                                           │
│  hash_sekarang == hash_asli ?             │
│    ├── YA  → ✅ SIGNATURE VALID           │
│    │          File asli dari pengirim     │
│    └── TIDAK → ❌ SIGNATURE TIDAK VALID   │
│               File diubah / pengirim palsu│
└───────────────────────────────────────────┘
```

**Rumus matematis verifikasi:**
```
hash_dari_signature = signature ^ e  mod n

Dimana:
  signature = nilai dari file .sig
  e         = Public Key exponent pengirim
  n         = modulus RSA pengirim

Kemudian bandingkan:
  SHA-256(file_diterima)  ==  hash_dari_signature
```

---

### Kenapa Ini Aman?

**Skenario 1: File dimanipulasi oleh pihak ketiga**
```
File asli    → SHA-256 → hash_A → ditandatangani dengan private key
File diubah  → SHA-256 → hash_B  ≠ hash_A

Verifikasi:
  Dekripsi signature → hash_A
  Hitung SHA-256 file baru → hash_B
  hash_A ≠ hash_B  →  ❌ GAGAL
```

**Skenario 2: Penyerang memalsukan signature**
```
Penyerang tidak punya private key pengirim
Penyerang tidak bisa membuat signature baru yang valid
Kalaupun buat signature dengan private key sendiri,
  verifikasi menggunakan public key pengirim asli akan gagal
  →  ❌ GAGAL
```

**Skenario 3: File asli, pengirim asli**
```
File asli    → SHA-256 → hash_A → ditandatangani dengan private key → signature
File diterima → SHA-256 → hash_A  (sama)

Verifikasi:
  Dekripsi signature dengan public key → hash_A
  Hitung SHA-256 file diterima → hash_A
  hash_A == hash_A  →  ✅ VALID
```

---

### Implementasi di Kode (`signature_module.py`)

```python
# ── SIGNING ──────────────────────────────────────────────────
def sign_file(filepath, private_key):
    with open(filepath, 'rb') as f:
        data = f.read()

    # Langkah 1: Hitung SHA-256
    file_hash = hashlib.sha256(data).digest()   # → 32 bytes

    # Langkah 2: Konversi ke integer
    d, n = private_key
    hash_int = int.from_bytes(file_hash, byteorder='big')

    # Langkah 3: RSA Sign — hash^d mod n
    signature_int   = pow(hash_int, d, n)
    byte_length     = (signature_int.bit_length() + 7) // 8
    return signature_int.to_bytes(byte_length, byteorder='big')


# ── VERIFIKASI ────────────────────────────────────────────────
def verify_signature(filepath, signature_bytes, public_key):
    with open(filepath, 'rb') as f:
        data = f.read()

    # Langkah 1: Hitung SHA-256 file saat ini
    current_hash = hashlib.sha256(data).digest()

    # Langkah 2: Dekripsi signature — sig^e mod n
    e, n = public_key
    sig_int        = int.from_bytes(signature_bytes, byteorder='big')
    hash_asli_int  = pow(sig_int, e, n)

    # Konversi kembali ke bytes (32 bytes, padding jika perlu)
    hash_asli_bytes = hash_asli_int.to_bytes(
        (hash_asli_int.bit_length() + 7) // 8, byteorder='big'
    ).rjust(32, b'\x00')

    # Langkah 3: Bandingkan
    return current_hash == hash_asli_bytes
```

---

### Ringkasan Jaminan Digital Signature

| Jaminan | Penjelasan |
|---|---|
| **Autentikasi** | Membuktikan file benar-benar dari pengirim yang mengklaim |
| **Integritas** | Perubahan sekecil apapun pada file akan terdeteksi |
| **Non-repudiation** | Pengirim tidak bisa menyangkal telah mengirim file |
| **Keamanan** | Tidak ada yang bisa memalsukan tanpa Private Key pengirim |

---

## 📁 Struktur Project

```
project_keamanan_tugas/
│
├── 📄 rsa_module.py          # Implementasi RSA manual (key gen, enc, dec)
├── 📄 aes_module.py          # Enkripsi/dekripsi file AES-256-EAX
├── 📄 signature_module.py    # Digital Signature RSA-SHA256
├── 📄 hashing_module.py      # SHA-256 hashing & verifikasi integritas
├── 📄 attack_simulation.py   # Simulasi serangan manipulasi file
├── 📄 hybrid_system.py       # Orkestrator sistem hybrid lengkap
├── 📄 gui.py                 # Antarmuka grafis Tkinter
├── 📄 requirements.txt       # Daftar dependensi Python
├── 📄 README.md              # Dokumentasi ini
│
├── 📁 sender/                # Kunci milik pengirim (mahasiswa/pegawai)
│   ├── mahasiswa_X_public.json
│   └── mahasiswa_X_private.json
│
├── 📁 receiver/              # Kunci milik penerima (dosen/kepala divisi)
│   ├── dosen_public.json
│   └── dosen_private.json
│
├── 📁 encrypted/             # Output file hasil enkripsi
│   ├── namafile.enc          # File terenkripsi (AES)
│   ├── namafile.key          # AES key terenkripsi (RSA)
│   ├── namafile.sig          # Digital signature
│   └── namafile.hash         # Hash SHA-256 file asli
│
├── 📁 decrypted/             # Output file hasil dekripsi
│   └── namafile              # File asli yang berhasil dipulihkan
│
└── 📁 testfiles/             # File uji coba
    └── tugas_kriptografi.txt
```

---

## 💻 Persyaratan Sistem

| Komponen | Minimum | Direkomendasikan |
|---|---|---|
| Python | 3.8 | 3.10+ |
| RAM | 256 MB | 512 MB+ |
| Penyimpanan | 50 MB | 200 MB+ |
| OS | Windows 7 / Ubuntu 18.04 / macOS 10.14 | Windows 10+ / Ubuntu 22.04+ |
| Layar | 1024×768 | 1366×768+ |

### Library yang Digunakan

| Library | Versi | Kegunaan |
|---|---|---|
| `pycryptodome` | ≥ 3.20.0 | AES-256-EAX cipher |
| `tkinter` | bawaan Python | Antarmuka grafis GUI |
| `hashlib` | bawaan Python | SHA-256 hashing |
| `json` | bawaan Python | Penyimpanan kunci RSA |
| `os`, `time`, `random` | bawaan Python | Utilitas sistem |

> **Catatan:** `tkinter` sudah termasuk dalam instalasi Python standar.  
> Khusus Linux, jika tidak tersedia: `sudo apt install python3-tk`

---

## 🚀 Instalasi

### Langkah 1 — Clone atau Buat Folder Project

```bash
# Opsi A: Buat folder manual
mkdir project_keamanan_tugas
cd project_keamanan_tugas

# Opsi B: Clone dari repository (jika tersedia)
git clone https://github.com/exzorsizest1/Kriptografi---UAS
cd project_keamanan_tugas
```

### Langkah 2 — Buat Virtual Environment (Sangat Disarankan)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### Langkah 3 — Install Dependensi

```bash
pip install -r requirements.txt
```

Isi `requirements.txt`:
```
pycryptodome==3.20.0
```

### Langkah 4 — Buat Folder yang Diperlukan

```bash
# Windows
mkdir sender receiver encrypted decrypted testfiles

# Linux / macOS
mkdir -p sender receiver encrypted decrypted testfiles
```

### Langkah 5 — Verifikasi Instalasi

```bash
python -c "from Crypto.Cipher import AES; print('✓ pycryptodome OK')"
python -c "import tkinter; print('✓ tkinter OK')"
```

### Troubleshooting Instalasi

**Error: `No module named 'Crypto'`**
```bash
pip uninstall pycrypto pycryptodome     # hapus semua dulu
pip install pycryptodome                # install ulang
```

**Error tkinter di Ubuntu/Debian**
```bash
sudo apt update
sudo apt install python3-tk
```

**Error tkinter di Fedora/CentOS**
```bash
sudo dnf install python3-tkinter
```

---

## ▶️ Cara Menjalankan

### Menjalankan GUI (Direkomendasikan)

```bash
python gui.py
```

### Menjalankan Test Modul Individu

```bash
# Test RSA manual
python rsa_module.py

# Test AES enkripsi/dekripsi
python aes_module.py

# Test hashing SHA-256
python hashing_module.py

# Test digital signature
python signature_module.py

# Test simulasi serangan
python attack_simulation.py

# Test sistem hybrid lengkap
python hybrid_system.py
```

### Menjalankan via Google Colab

1. Upload semua file `.py` ke Google Colab
2. Install dependensi:
```python
!pip install pycryptodome
```
3. Jalankan sistem hybrid (tanpa GUI):
```python
# Import semua modul
from rsa_module import generate_rsa_keys, save_keys
from signature_module import generate_student_keys
from hybrid_system import encrypt_assignment, decrypt_assignment

# Setup kunci
import os
for f in ['sender','receiver','encrypted','decrypted','testfiles']:
    os.makedirs(f, exist_ok=True)

pub_d, priv_d = generate_rsa_keys(512)
save_keys(pub_d, priv_d, folder='receiver', prefix='dosen')

pub_m, priv_m = generate_student_keys('Budi', folder='sender', bits=512)

# Buat file test
with open('testfiles/laporan.txt','w') as f:
    f.write('Laporan Rahasia Instansi Pemerintah\n' * 20)

# Enkripsi
encrypt_assignment(
    input_file='testfiles/laporan.txt',
    dosen_public_key_path='receiver/dosen_public.json',
    student_private_key_path='sender/mahasiswa_Budi_private.json'
)

# Dekripsi
decrypt_assignment(
    enc_file='encrypted/laporan.txt.enc',
    key_file='encrypted/laporan.txt.key',
    sig_file='encrypted/laporan.txt.sig',
    hash_file_path='encrypted/laporan.txt.hash',
    dosen_private_key_path='receiver/dosen_private.json',
    student_public_key_path='sender/mahasiswa_Budi_public.json'
)
```

---

## 🖥 Panduan Penggunaan GUI

### Urutan Penggunaan Normal

```
TAHAP 1 — SETUP KUNCI
  ┌─────────────────────────────────────────────────────────┐
  │ 1. Klik "Generate Kunci Dosen"                          │
  │    → Pilih folder: receiver/                            │
  │    → Menghasilkan: dosen_public.json, dosen_private.json│
  │                                                         │
  │ 2. Klik "Generate Kunci Mahasiswa"                      │
  │    → Masukkan nama/NIM                                  │
  │    → Pilih folder: sender/                              │
  │    → Menghasilkan: mahasiswa_X_public/private.json      │
  └─────────────────────────────────────────────────────────┘

TAHAP 2 — PERSIAPAN FILE
  ┌─────────────────────────────────────────────────────────┐
  │ 3. Klik "Buat File Test" (opsional)                     │
  │    → Membuat file contoh di testfiles/                  │
  │                                                         │
  │ 4. Klik "Pilih File Tugas"                              │
  │    → Pilih file apapun (pdf, docx, zip, txt, dll)       │
  └─────────────────────────────────────────────────────────┘

TAHAP 3 — ENKRIPSI (Sisi Pengirim)
  ┌─────────────────────────────────────────────────────────┐
  │ 5. Klik "RUN ENKRIPSI"                                  │
  │    → Program otomatis:                                  │
  │      • Generate AES key acak                            │
  │      • Enkripsi file dengan AES-256-EAX → .enc          │
  │      • Enkripsi AES key dengan RSA → .key               │
  │      • Hitung SHA-256 → .hash                           │
  │      • Buat digital signature → .sig                    │
  │    → 4 file tersimpan di encrypted/                     │
  └─────────────────────────────────────────────────────────┘

TAHAP 4 — DEKRIPSI (Sisi Penerima)
  ┌─────────────────────────────────────────────────────────┐
  │ 6. Klik "RUN DEKRIPSI"                                  │
  │    → Pilih file .enc dari encrypted/                    │
  │    → File .key, .sig, .hash dicari otomatis             │
  │    → Program otomatis verifikasi semua                  │
  │    → File asli tersimpan di decrypted/                  │
  └─────────────────────────────────────────────────────────┘
```

### Simulasi Serangan

```
SIMULASI SERANGAN
  ┌─────────────────────────────────────────────────────────┐
  │ 7. Klik "Manipulasi File .enc"                          │
  │    → Pilih file .enc                                    │
  │    → Backup otomatis dibuat (.enc.backup)               │
  │    → 5 byte acak diubah di tengah file                  │
  │                                                         │
  │ 8. Klik "RUN DEKRIPSI" lagi                             │
  │    → Program mendeteksi manipulasi                      │
  │    → Menampilkan: ✗ INTEGRITAS GAGAL                    │
  │                                                         │
  │ 9. Klik "Restore File .enc"                             │
  │    → File dipulihkan dari backup                        │
  └─────────────────────────────────────────────────────────┘
```

### Tombol Verifikasi Individual

| Tombol | Fungsi | Input yang Diperlukan |
|---|---|---|
| Verifikasi Signature | Verifikasi .sig saja | File asli + .sig + public key mahasiswa |
| Cek Hash Integritas | Verifikasi .hash saja | File asli + .hash |
| Benchmark RSA vs Hybrid | Ukur performa | File apapun |

---

## 📦 Penjelasan Modul

### `rsa_module.py` — Implementasi RSA Manual

Implementasi RSA dari nol menggunakan rumus matematika murni.

| Fungsi | Deskripsi |
|---|---|
| `is_prime(n, k)` | Uji primality Miller-Rabin dengan k iterasi |
| `generate_prime(bits)` | Generate bilangan prima acak sejumlah `bits` bit |
| `gcd(a, b)` | Algoritma Euclidean untuk GCD |
| `mod_inverse(e, phi)` | Extended Euclidean Algorithm untuk modular inverse |
| `generate_rsa_keys(bits)` | Generate pasangan kunci (public, private) |
| `rsa_encrypt(message_bytes, public_key)` | Enkripsi: `C = M^e mod n` |
| `rsa_decrypt(ciphertext_int, private_key)` | Dekripsi: `M = C^d mod n` |
| `encrypt_aes_key(aes_key, public_key)` | Enkripsi AES key (32 bytes) dengan RSA |
| `decrypt_aes_key(enc_bytes, private_key)` | Dekripsi AES key dengan RSA |
| `save_keys(pub, priv, folder, prefix)` | Simpan kunci ke file JSON |
| `load_public_key(filepath)` | Load public key dari JSON |
| `load_private_key(filepath)` | Load private key dari JSON |

**Rumus RSA yang diimplementasikan:**
```
n   = p × q
phi = (p - 1) × (q - 1)
e   = 65537  (atau dicari jika gcd(e, phi) ≠ 1)
d   = modular_inverse(e, phi)

Enkripsi : C = M^e mod n
Dekripsi : M = C^d mod n
```

---

### `aes_module.py` — Enkripsi File AES-256

| Fungsi | Deskripsi |
|---|---|
| `generate_aes_key()` | Generate 32 bytes kunci acak kriptografis |
| `encrypt_file(input, output, key)` | Enkripsi file → nonce+tag+ciphertext |
| `decrypt_file(input, output, key)` | Dekripsi file, verifikasi tag otomatis |
| `benchmark_aes(file_path)` | Benchmark enkripsi/dekripsi + throughput |

**Format file `.enc`:**
```
[16 bytes nonce] + [16 bytes tag] + [N bytes ciphertext]
```

---

### `hashing_module.py` — SHA-256 & Integritas

| Fungsi | Deskripsi |
|---|---|
| `hash_file(filepath)` | Hitung SHA-256 dari file (baca per 64KB blok) |
| `hash_bytes(data)` | Hitung SHA-256 dari bytes → bytes digest |
| `hash_bytes_hex(data)` | Hitung SHA-256 dari bytes → hex string |
| `save_hash(filepath, hash, folder)` | Simpan hash ke file JSON `.hash` |
| `load_hash(hash_filepath)` | Load hash dari file `.hash` |
| `verify_integrity(filepath, expected)` | Bandingkan hash file vs hash tersimpan |
| `verify_integrity_bytes(data, expected)` | Verifikasi dari bytes langsung |

---

### `signature_module.py` — Digital Signature

| Fungsi | Deskripsi |
|---|---|
| `generate_student_keys(name, folder, bits)` | Generate kunci RSA untuk pengirim |
| `sign_file(filepath, private_key)` | Buat signature: `hash^d mod n` |
| `sign_bytes(data, private_key)` | Buat signature dari bytes langsung |
| `save_signature(sig, filepath, folder)` | Simpan signature ke file `.sig` |
| `load_signature(sig_filepath)` | Load signature dari file `.sig` |
| `verify_signature(filepath, sig, pub)` | Verifikasi: `sig^e mod n == hash` |
| `verify_signature_bytes(data, sig, pub)` | Verifikasi dari bytes langsung |

---

### `attack_simulation.py` — Simulasi Serangan

| Fungsi | Deskripsi |
|---|---|
| `attack_byte_flip(filepath, n)` | Ubah n byte acak di dalam file .enc |
| `attack_append(filepath, n)` | Tambahkan n bytes sampah di akhir file |
| `attack_truncate(filepath, n)` | Potong n bytes dari akhir file |
| `backup_file(filepath)` | Buat backup sebelum diserang |
| `restore_file(filepath)` | Pulihkan file dari backup |
| `generate_attack_report(info)` | Tampilkan laporan serangan |

---

### `hybrid_system.py` — Orkestrator Sistem

| Fungsi | Deskripsi |
|---|---|
| `encrypt_assignment(file, dosen_pub, student_priv, output)` | Enkripsi lengkap dengan semua mekanisme |
| `decrypt_assignment(enc, key, sig, hash, dosen_priv, student_pub, output)` | Dekripsi + verifikasi lengkap |
| `benchmark_comparison(file_path, rsa_bits)` | Bandingkan RSA murni vs Hybrid |

---

## 📊 Benchmark & Evaluasi

### Hasil Benchmark Tipikal (file 100 KB, RSA 512-bit)

| Metode | Waktu Enkripsi | Waktu Dekripsi | Keterangan |
|---|---|---|---|
| Hybrid (AES+RSA) | ~0.003 detik | ~0.003 detik | ✅ Sangat cepat |
| RSA Murni (estimasi) | ~45 detik | ~65 detik | ❌ Tidak praktis |

> Catatan: RSA murni diestimasi berdasarkan enkripsi per-blok (30 bytes/blok). Waktu aktual bervariasi tergantung hardware.

### Perbandingan Kapasitas

| Metode | Maks Ukuran Data | Cocok Untuk |
|---|---|---|
| RSA 512-bit | ~53 bytes | Kunci saja |
| RSA 1024-bit | ~117 bytes | Kunci saja |
| RSA 2048-bit | ~245 bytes | Kunci saja |
| AES-256 | Tidak terbatas | File apapun |
| **Hybrid** | **Tidak terbatas** | **File apapun + aman distribusi kunci** |

### Menjalankan Benchmark

Di GUI: klik tombol **"Benchmark RSA vs Hybrid"** dan pilih file.

Via kode:
```python
from hybrid_system import benchmark_comparison
benchmark_comparison("testfiles/laporan.txt", rsa_bits=512)
```

---

## ⚔️ Simulasi Serangan

### Jenis Serangan yang Disimulasikan

#### 1. Byte Flip Attack
```
Penyerang mengubah beberapa byte di dalam file .enc

Dampak yang terdeteksi:
  ✗ AES-EAX tag verification → GAGAL (dekripsi gagal)
  ✗ SHA-256 hash comparison   → BERBEDA
  ✗ Digital signature verify  → GAGAL
```

#### 2. Append Attack
```
Penyerang menambahkan data sampah di akhir .enc

Dampak:
  ✗ Ukuran file berubah
  ✗ AES-EAX tag verification → GAGAL
```

#### 3. Truncate Attack
```
Penyerang memotong sebagian isi .enc

Dampak:
  ✗ Data tidak lengkap
  ✗ Dekripsi menghasilkan data korup atau error
```

### Mengapa Serangan Terdeteksi?

```
Lapisan 1 — AES-EAX Tag:
  Mode EAX menghasilkan authentication tag 16 bytes.
  Modifikasi apapun pada ciphertext akan membuat tag tidak cocok.
  Dekripsi langsung gagal sebelum menghasilkan plaintext.

Lapisan 2 — SHA-256 Hash:
  Hash dihitung dari file ASLI sebelum enkripsi.
  Setelah dekripsi, hash dihitung ulang dan dibandingkan.
  Perubahan 1 bit sekalipun menghasilkan hash yang sama sekali berbeda.

Lapisan 3 — Digital Signature:
  Signature dihitung dari hash file asli menggunakan Private Key pengirim.
  Jika file berubah, hash berubah, signature tidak akan match.
  Tanpa Private Key pengirim, signature baru tidak bisa dibuat.
```

---

## 🔒 Keamanan Sistem

### Jaminan Keamanan

| Properti | Mekanisme | Kekuatan |
|---|---|---|
| **Kerahasiaan** | AES-256-EAX | 256-bit key space, authenticated |
| **Integritas** | SHA-256 + AES tag | Collision resistant |
| **Autentikasi** | Digital Signature RSA | Non-forgeable tanpa private key |
| **Non-repudiation** | Private key signing | Pengirim tidak bisa menyangkal |
| **Key Security** | RSA enkripsi AES key | Hanya penerima yang bisa dekripsi |

### Mengapa AES-256-EAX?

Mode **EAX (Encrypt-then-Authenticate-then-Translate)** dipilih karena:
- **Authenticated Encryption**: enkripsi dan autentikasi dalam satu langkah
- **Nonce-based**: setiap enkripsi menggunakan nonce acak, mencegah replay attack
- **Tag 16 bytes**: deteksi otomatis modifikasi ciphertext
- **Aman dan modern**: direkomendasikan untuk penggunaan kriptografi saat ini

---

## ⚠️ Kelemahan Sistem

Berikut adalah kelemahan yang disadari dan perlu diperhatikan:

| Kelemahan | Dampak | Solusi untuk Produksi |
|---|---|---|
| RSA 512-bit | Rentan terhadap faktorisasi modern | Gunakan minimal 2048-bit |
| Tidak ada PKI | Distribusi public key manual, rentan MITM | Implementasi Certificate Authority |
| Kunci disimpan plain JSON | Jika file dicuri, private key terbaca | Enkripsi file kunci dengan passphrase |
| Tidak ada timestamp signature | Signature bisa di-replay | Tambahkan timestamp + nonce di signature |
| Single-thread GUI | GUI bisa freeze saat operasi berat | Sudah menggunakan threading, bisa ditingkatkan |
| Tidak ada revocation | Kunci yang bocor tidak bisa dicabut | Implementasi Certificate Revocation List |

---

## 💡 Contoh Output

### Output Enkripsi Berhasil
```
============================================================
   ENKRIPSI TUGAS MAHASISWA
============================================================

[STEP 1] Memuat kunci RSA...
         ✓ Public Key dosen dimuat
         ✓ Private Key mahasiswa dimuat

[STEP 2] Generate AES-256 key...
         ✓ AES Key: a3f8c2d1e9b5f7a2... (32 bytes)

[STEP 3] Enkripsi file menggunakan AES-256...
[AES] Enkripsi selesai!
      File asli   : 1024 bytes
      File .enc   : 1056 bytes
      Waktu       : 0.0012 detik

[STEP 4] Enkripsi AES key menggunakan RSA Public Key dosen...
         ✓ Encrypted AES key disimpan: encrypted/laporan.txt.key
         ✓ Waktu RSA enkripsi: 0.0003 detik

[STEP 5] Menghitung hash SHA-256 file asli...
[HASH] SHA-256(laporan.txt) = a3f8c2d1e9b5f7a2...
         ✓ SHA-256: a3f8c2d1e9b5f7a2...

[STEP 6] Membuat digital signature...
[SIG] Hash file: a3f8c2d1e9b5f7a2...
[SIG] Signature dibuat: 64 bytes
         ✓ Signature disimpan: encrypted/laporan.txt.sig
         ✓ Waktu signing: 0.0008 detik

------------------------------------------------------------
   RINGKASAN ENKRIPSI
------------------------------------------------------------
   File asli        : testfiles/laporan.txt
   Ukuran file      : 1024 bytes
   File .enc        : encrypted/laporan.txt.enc
   File .key        : encrypted/laporan.txt.key
   File .sig        : encrypted/laporan.txt.sig
   File .hash       : encrypted/laporan.txt.hash
   Total waktu      : 0.0031 detik
------------------------------------------------------------
```

### Output Dekripsi + Verifikasi Berhasil
```
============================================================
   LAPORAN VERIFIKASI DOSEN
============================================================
   Dekripsi AES     : ✓ Dekripsi AES berhasil
   Integritas Hash  : ✓ INTEGRITAS TERJAGA - File tidak dimodifikasi
   Digital Signature: ✓ SIGNATURE VALID - File asli dari pengirim
   Total waktu      : 0.0041 detik
------------------------------------------------------------
   STATUS AKHIR : ✓ FILE AMAN DAN TERPERCAYA
============================================================
```

### Output Setelah File Dimanipulasi
```
============================================================
   LAPORAN VERIFIKASI DOSEN
============================================================
   Dekripsi AES     : ✗ Dekripsi AES GAGAL - File mungkin dimanipulasi
   Integritas Hash  : ✗ INTEGRITAS GAGAL - File telah dimodifikasi!
   Digital Signature: ✗ SIGNATURE TIDAK VALID - File telah dimodifikasi!
   Total waktu      : 0.0039 detik
------------------------------------------------------------
   STATUS AKHIR : ✗ FILE BERMASALAH - INTEGRITAS/SIGNATURE GAGAL
============================================================
```

---

## ❓ FAQ

**Q: Apakah bisa digunakan untuk file selain `.txt`?**  
A: Ya. Program dapat mengenkripsi file apapun — `.pdf`, `.docx`, `.zip`, `.pptx`, gambar, dan lainnya — karena bekerja pada level bytes.

**Q: Berapa ukuran maksimum file yang bisa dienkripsi?**  
A: Tidak ada batasan praktis. AES-256 dapat mengenkripsi file berukuran GB sekalipun dengan cepat.

**Q: Apakah kunci RSA bisa digunakan berulang kali?**  
A: Ya. Sepasang kunci RSA dapat digunakan untuk mengenkripsi banyak file AES key yang berbeda-beda.

**Q: Apa yang terjadi jika file `.key` hilang?**  
A: File `.enc` tidak bisa didekripsi. AES key yang ada di dalamnya adalah satu-satunya cara membuka file terenkripsi.

**Q: Apakah RSA 512-bit cukup aman?**  
A: Untuk keperluan pembelajaran dan demo sudah cukup. Untuk produksi nyata, gunakan minimal 2048-bit karena RSA 512-bit sudah berhasil difaktorisasi dalam penelitian akademik.

**Q: Bagaimana cara mendistribusikan public key dengan aman?**  
A: Pada sistem ini, public key dibagikan secara manual (copy file JSON). Untuk produksi, disarankan menggunakan PKI (Public Key Infrastructure) dengan Certificate Authority.



---

## 👤 Informasi Project

| | |
|---|---|
| **Mata Kuliah** | Algoritma Kriptografi |
| **Topik** | Perancangan Sistem Pengiriman Data Rahasia Menggunakan RSA dan Hybrid Encryption |
| **Studi Kasus** | Instansi Pemerintah Daerah |
| **Teknologi** | Python 3, RSA Manual, AES-256-EAX, SHA-256, Digital Signature |

---

<div align="center">

**🔐 Dibangun untuk keamanan data yang nyata dan dapat dipercaya**

*RSA + AES-256 + SHA-256 + Digital Signature*

</div>