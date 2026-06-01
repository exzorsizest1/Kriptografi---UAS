"""
gui.py
======
Antarmuka grafis (GUI) sistem keamanan pengumpulan tugas
menggunakan tkinter.

Fitur GUI:
  - Generate RSA Keys (dosen & mahasiswa)
  - Load RSA Keys
  - Pilih file tugas
  - RUN ENKRIPSI (hybrid encryption)
  - RUN DEKRIPSI + verifikasi
  - Manipulasi File (simulasi serangan)
  - Verifikasi Signature
  - Cek Hash
  - Benchmark RSA vs Hybrid
  - Log proses lengkap
  - Status keamanan real-time
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import threading
import time
import sys
import io
from datetime import datetime


# ─────────────────────────────────────────────
# Kelas Utama GUI
# ─────────────────────────────────────────────

class HybridEncryptionGUI:
    """
    GUI utama sistem Hybrid Encryption untuk pengumpulan tugas.
    """

    def __init__(self, root):
        self.root = root
        self.root.title(" Sistem Keamanan Tugas - Hybrid RSA+AES")
        self.root.geometry("1000x750")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(True, True)

        # ── State aplikasi ──────────────────────────────────────
        self.selected_file     = tk.StringVar(value="Belum ada file dipilih")
        self.dosen_pub_key     = tk.StringVar(value="")
        self.dosen_priv_key    = tk.StringVar(value="")
        self.student_pub_key   = tk.StringVar(value="")
        self.student_priv_key  = tk.StringVar(value="")
        self.enc_output_folder = tk.StringVar(value="encrypted")
        self.dec_output_folder = tk.StringVar(value="decrypted")
        self.last_enc_result   = None

        # ── Warna tema ─────────────────────────────────────────
        self.colors = {
            "bg"       : "#1e1e2e",
            "panel"    : "#2a2a3e",
            "accent"   : "#7c3aed",
            "accent2"  : "#06b6d4",
            "success"  : "#10b981",
            "danger"   : "#ef4444",
            "warning"  : "#f59e0b",
            "text"     : "#e2e8f0",
            "subtext"  : "#94a3b8",
            "border"   : "#3d3d5c",
            "btn_enc"  : "#7c3aed",
            "btn_dec"  : "#0891b2",
            "btn_att"  : "#dc2626",
            "btn_gen"  : "#059669",
        }

        self._build_ui()
        self._log("🚀 Sistem Hybrid Encryption siap digunakan.", "info")
        self._log("📋 Petunjuk: Generate kunci → Pilih file → Enkripsi → Dekripsi", "info")

    # ─────────────────────────────────────────────
    # Bangun Antarmuka
    # ─────────────────────────────────────────────

    def _build_ui(self):
        """Membangun semua elemen GUI."""

        c = self.colors

        # ── Header ─────────────────────────────────────────────
        header_frame = tk.Frame(self.root, bg=c["accent"], pady=12)
        header_frame.pack(fill="x")

        tk.Label(
            header_frame,
            text="🔐  Sistem Keamanan Pengumpulan Tugas Mahasiswa",
            font=("Segoe UI", 16, "bold"),
            bg=c["accent"], fg="white"
        ).pack()

        tk.Label(
            header_frame,
            text="Hybrid Encryption: RSA + AES-256 + SHA-256 + Digital Signature",
            font=("Segoe UI", 10),
            bg=c["accent"], fg="#ddd6fe"
        ).pack()

        # ── Main container (3 kolom) ───────────────────────────
        main = tk.Frame(self.root, bg=c["bg"])
        main.pack(fill="both", expand=True, padx=10, pady=8)

        # Kolom kiri: tombol aksi
        left = tk.Frame(main, bg=c["bg"], width=280)
        left.pack(side="left", fill="y", padx=(0, 6))
        left.pack_propagate(False)

        # Kolom tengah: info file & kunci
        mid = tk.Frame(main, bg=c["bg"], width=280)
        mid.pack(side="left", fill="y", padx=6)
        mid.pack_propagate(False)

        # Kolom kanan: log
        right = tk.Frame(main, bg=c["bg"])
        right.pack(side="left", fill="both", expand=True, padx=(6, 0))

        self._build_left_panel(left)
        self._build_mid_panel(mid)
        self._build_right_panel(right)

        # ── Status bar bawah ────────────────────────────────────
        self.status_var = tk.StringVar(value="Siap")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            font=("Segoe UI", 9),
            bg=c["border"], fg=c["text"],
            anchor="w", padx=10, pady=4
        )
        status_bar.pack(fill="x", side="bottom")

    def _panel(self, parent, title):
        """Buat panel dengan judul."""
        c = self.colors
        frame = tk.LabelFrame(
            parent, text=f"  {title}  ",
            font=("Segoe UI", 9, "bold"),
            bg=c["panel"], fg=c["accent2"],
            bd=1, relief="solid",
            labelanchor="n"
        )
        frame.pack(fill="x", padx=4, pady=4)
        return frame

    def _btn(self, parent, text, command, color=None, icon=""):
        """Buat tombol dengan gaya modern."""
        c  = self.colors
        bg = color or c["accent"]
        btn = tk.Button(
            parent,
            text=f"{icon} {text}".strip(),
            command=command,
            font=("Segoe UI", 9, "bold"),
            bg=bg, fg="white",
            activebackground=bg,
            activeforeground="white",
            relief="flat", cursor="hand2",
            padx=8, pady=6
        )
        btn.pack(fill="x", padx=6, pady=2)
        return btn

    # ─────────────────────────────────────────────
    # Panel Kiri: Tombol Aksi
    # ─────────────────────────────────────────────

    def _build_left_panel(self, parent):
        c = self.colors

        # === SETUP KUNCI ===
        p = self._panel(parent, "🔑 SETUP KUNCI RSA")
        self._btn(p, "Generate Kunci Dosen",    self._gen_dosen_keys,   c["btn_gen"], "🎓")
        self._btn(p, "Generate Kunci Mahasiswa", self._gen_student_keys, c["btn_gen"], "👤")
        self._btn(p, "Load Public Key Dosen",    self._load_dosen_pub,   c["accent2"], "📂")
        self._btn(p, "Load Private Key Dosen",   self._load_dosen_priv,  c["accent2"], "📂")
        self._btn(p, "Load Public Key Mahasiswa", self._load_student_pub, c["accent2"], "📂")
        self._btn(p, "Load Private Key Mhs",     self._load_student_priv,c["accent2"], "📂")

        # === FILE ===
        p2 = self._panel(parent, "📁 FILE TUGAS")
        self._btn(p2, "Pilih File Tugas", self._pick_file, c["accent"], "📄")

        # === ENKRIPSI/DEKRIPSI ===
        p3 = self._panel(parent, "🔒 ENKRIPSI & DEKRIPSI")
        self._btn(p3, "RUN ENKRIPSI",  self._run_encrypt, c["btn_enc"], "🔒")
        self._btn(p3, "RUN DEKRIPSI",  self._run_decrypt, c["btn_dec"], "🔓")

        # === VERIFIKASI ===
        p4 = self._panel(parent, "✅ VERIFIKASI")
        self._btn(p4, "Verifikasi Signature", self._verify_sig,  c["success"],  "✍")
        self._btn(p4, "Cek Hash Integritas",  self._check_hash,  c["success"],  "🔍")

        # === SERANGAN ===
        p5 = self._panel(parent, "⚠️ SIMULASI SERANGAN")
        self._btn(p5, "Manipulasi File .enc", self._attack_file, c["btn_att"], "💀")
        self._btn(p5, "Restore File .enc",    self._restore_file, c["warning"], "♻")

        # === BENCHMARK ===
        p6 = self._panel(parent, "📊 BENCHMARK")
        self._btn(p6, "Benchmark RSA vs Hybrid", self._run_benchmark, c["accent"], "⏱")

        # === CLEAR ===
        p7 = self._panel(parent, "🛠 LAINNYA")
        self._btn(p7, "Bersihkan Log", self._clear_log, c["border"], "🗑")
        self._btn(p7, "Buat File Test", self._make_test_file, c["subtext"], "✏")

    # ─────────────────────────────────────────────
    # Panel Tengah: Info Status
    # ─────────────────────────────────────────────

    def _build_mid_panel(self, parent):
        c = self.colors

        # ── File terpilih ──────────────────────────────────────
        p = self._panel(parent, "📄 File Dipilih")
        self.lbl_file = tk.Label(
            p, textvariable=self.selected_file,
            font=("Segoe UI", 8), bg=c["panel"],
            fg=c["accent2"], wraplength=240, anchor="w", justify="left"
        )
        self.lbl_file.pack(padx=6, pady=4, fill="x")

        # ── Status kunci ───────────────────────────────────────
        p2 = self._panel(parent, "🔑 Status Kunci")
        self.key_labels = {}
        keys_info = [
            ("pub_dosen",    "Public Key Dosen"),
            ("priv_dosen",   "Private Key Dosen"),
            ("pub_mhs",      "Public Key Mahasiswa"),
            ("priv_mhs",     "Private Key Mahasiswa"),
        ]
        for key_id, label in keys_info:
            row = tk.Frame(p2, bg=c["panel"])
            row.pack(fill="x", padx=6, pady=1)
            tk.Label(row, text=label + ":", font=("Segoe UI", 8),
                     bg=c["panel"], fg=c["subtext"], width=20, anchor="w").pack(side="left")
            lbl = tk.Label(row, text="✗ Belum load",
                           font=("Segoe UI", 8, "bold"),
                           bg=c["panel"], fg=c["danger"])
            lbl.pack(side="left")
            self.key_labels[key_id] = lbl

        # ── Status keamanan ────────────────────────────────────
        p3 = self._panel(parent, "🛡 Status Keamanan")

        self.status_labels = {}
        statuses = [
            ("enkripsi",   "Enkripsi AES"),
            ("rsa_enc",    "RSA Encrypt Key"),
            ("hash",       "Hash SHA-256"),
            ("signature",  "Digital Signature"),
            ("integritas", "Integritas File"),
            ("sig_verify", "Verif. Signature"),
        ]
        for sid, slabel in statuses:
            row = tk.Frame(p3, bg=c["panel"])
            row.pack(fill="x", padx=6, pady=1)
            tk.Label(row, text=slabel + ":", font=("Segoe UI", 8),
                     bg=c["panel"], fg=c["subtext"], width=18, anchor="w").pack(side="left")
            lbl = tk.Label(row, text="—", font=("Segoe UI", 8, "bold"),
                           bg=c["panel"], fg=c["subtext"])
            lbl.pack(side="left")
            self.status_labels[sid] = lbl

        # ── Waktu eksekusi ─────────────────────────────────────
        p4 = self._panel(parent, "⏱ Waktu Eksekusi")
        self.time_var = tk.StringVar(value="—")
        tk.Label(p4, textvariable=self.time_var,
                 font=("Courier New", 9), bg=c["panel"],
                 fg=c["success"]).pack(padx=6, pady=4)

        # ── Status akhir ───────────────────────────────────────
        p5 = self._panel(parent, "🏁 Status Akhir")
        self.final_status_var = tk.StringVar(value="Menunggu proses...")
        self.final_status_lbl = tk.Label(
            p5, textvariable=self.final_status_var,
            font=("Segoe UI", 10, "bold"),
            bg=c["panel"], fg=c["subtext"],
            wraplength=240
        )
        self.final_status_lbl.pack(padx=6, pady=6)

    # ─────────────────────────────────────────────
    # Panel Kanan: Log
    # ─────────────────────────────────────────────

    def _build_right_panel(self, parent):
        c = self.colors

        tk.Label(parent, text="📋 LOG PROSES",
                 font=("Segoe UI", 10, "bold"),
                 bg=c["bg"], fg=c["accent2"]).pack(anchor="w", padx=4)

        self.log_text = scrolledtext.ScrolledText(
            parent,
            font=("Courier New", 9),
            bg="#0f0f1a", fg=c["text"],
            insertbackground=c["text"],
            relief="flat", bd=0,
            state="disabled",
            wrap="word"
        )
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)

        # Tag warna log
        self.log_text.tag_config("info",    foreground="#94a3b8")
        self.log_text.tag_config("success", foreground="#10b981")
        self.log_text.tag_config("danger",  foreground="#ef4444")
        self.log_text.tag_config("warning", foreground="#f59e0b")
        self.log_text.tag_config("header",  foreground="#7c3aed", font=("Courier New", 9, "bold"))
        self.log_text.tag_config("cyan",    foreground="#06b6d4")

    # ─────────────────────────────────────────────
    # Fungsi Log
    # ─────────────────────────────────────────────

    def _log(self, message, tag="info"):
        """Tambahkan pesan ke area log dengan timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n", tag)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _log_separator(self, title=""):
        self._log("─" * 50, "header")
        if title:
            self._log(f"  {title}", "header")
            self._log("─" * 50, "header")

    def _clear_log(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")
        self._log("Log dibersihkan.", "info")

    # ─────────────────────────────────────────────
    # Update Status Labels
    # ─────────────────────────────────────────────

    def _set_status(self, key, text, ok=True):
        c = self.colors
        fg = c["success"] if ok else c["danger"]
        self.status_labels[key].config(text=text, fg=fg)

    def _set_key_status(self, key, loaded=True):
        c = self.colors
        if loaded:
            self.key_labels[key].config(text="✓ Loaded", fg=c["success"])
        else:
            self.key_labels[key].config(text="✗ Belum load", fg=c["danger"])

    def _set_final(self, text, ok=True):
        c = self.colors
        fg = c["success"] if ok else c["danger"]
        self.final_status_var.set(text)
        self.final_status_lbl.config(fg=fg)

    # ─────────────────────────────────────────────
    # Callback: Generate Kunci
    # ─────────────────────────────────────────────

    def _gen_dosen_keys(self):
        folder = filedialog.askdirectory(title="Pilih folder simpan kunci dosen",
                                         initialdir="receiver")
        if not folder:
            folder = "receiver"

        def task():
            try:
                self._log_separator("GENERATE KUNCI DOSEN")
                self._log("⏳ Generating RSA keys untuk dosen (512-bit)...", "info")
                self.status_var.set("Generating kunci dosen...")
                self.root.update_idletasks()

                from rsa_module import generate_rsa_keys, save_keys
                t = time.time()
                pub, priv = generate_rsa_keys(bits=512)
                save_keys(pub, priv, folder=folder, prefix="dosen")
                elapsed = time.time() - t

                self.dosen_pub_key.set(os.path.join(folder, "dosen_public.json"))
                self.dosen_priv_key.set(os.path.join(folder, "dosen_private.json"))
                self._set_key_status("pub_dosen",  True)
                self._set_key_status("priv_dosen", True)

                self._log(f"✓ Public Key  : {folder}/dosen_public.json",  "success")
                self._log(f"✓ Private Key : {folder}/dosen_private.json", "success")
                self._log(f"✓ Waktu       : {elapsed:.3f} detik",         "success")
                self.status_var.set(f"Kunci dosen berhasil dibuat ({elapsed:.3f}s)")
                self._set_final("✓ Kunci dosen berhasil dibuat", True)

            except Exception as e:
                self._log(f"✗ Error: {e}", "danger")
                messagebox.showerror("Error", str(e))

        threading.Thread(target=task, daemon=True).start()

    def _gen_student_keys(self):
        from tkinter.simpledialog import askstring
        nama = askstring("Nama Mahasiswa", "Masukkan nama/NIM mahasiswa:")
        if not nama:
            return

        folder = filedialog.askdirectory(title="Pilih folder simpan kunci mahasiswa",
                                          initialdir="sender")
        if not folder:
            folder = "sender"

        def task():
            try:
                self._log_separator(f"GENERATE KUNCI MAHASISWA: {nama}")
                self._log(f"⏳ Generating RSA keys untuk {nama}...", "info")
                self.status_var.set("Generating kunci mahasiswa...")

                from signature_module import generate_student_keys
                t = time.time()
                pub, priv = generate_student_keys(nama, folder=folder, bits=512)
                elapsed = time.time() - t

                prefix = f"mahasiswa_{nama.replace(' ', '_')}"
                self.student_pub_key.set(os.path.join(folder, f"{prefix}_public.json"))
                self.student_priv_key.set(os.path.join(folder, f"{prefix}_private.json"))
                self._set_key_status("pub_mhs",  True)
                self._set_key_status("priv_mhs", True)

                self._log(f"✓ Public Key  : {folder}/{prefix}_public.json",  "success")
                self._log(f"✓ Private Key : {folder}/{prefix}_private.json", "success")
                self._log(f"✓ Waktu       : {elapsed:.3f} detik",            "success")
                self.status_var.set("Kunci mahasiswa berhasil dibuat")
                self._set_final("✓ Kunci mahasiswa berhasil dibuat", True)

            except Exception as e:
                self._log(f"✗ Error: {e}", "danger")
                messagebox.showerror("Error", str(e))

        threading.Thread(target=task, daemon=True).start()

    # ─────────────────────────────────────────────
    # Callback: Load Kunci
    # ─────────────────────────────────────────────

    def _load_dosen_pub(self):
        path = filedialog.askopenfilename(
            title="Pilih Public Key Dosen",
            filetypes=[("JSON Key", "*.json"), ("All", "*.*")]
        )
        if path:
            self.dosen_pub_key.set(path)
            self._set_key_status("pub_dosen", True)
            self._log(f"✓ Public Key Dosen dimuat: {path}", "success")

    def _load_dosen_priv(self):
        path = filedialog.askopenfilename(
            title="Pilih Private Key Dosen",
            filetypes=[("JSON Key", "*.json"), ("All", "*.*")]
        )
        if path:
            self.dosen_priv_key.set(path)
            self._set_key_status("priv_dosen", True)
            self._log(f"✓ Private Key Dosen dimuat: {path}", "success")

    def _load_student_pub(self):
        path = filedialog.askopenfilename(
            title="Pilih Public Key Mahasiswa",
            filetypes=[("JSON Key", "*.json"), ("All", "*.*")]
        )
        if path:
            self.student_pub_key.set(path)
            self._set_key_status("pub_mhs", True)
            self._log(f"✓ Public Key Mahasiswa dimuat: {path}", "success")

    def _load_student_priv(self):
        path = filedialog.askopenfilename(
            title="Pilih Private Key Mahasiswa",
            filetypes=[("JSON Key", "*.json"), ("All", "*.*")]
        )
        if path:
            self.student_priv_key.set(path)
            self._set_key_status("priv_mhs", True)
            self._log(f"✓ Private Key Mahasiswa dimuat: {path}", "success")

    # ─────────────────────────────────────────────
    # Callback: Pilih File
    # ─────────────────────────────────────────────

    def _pick_file(self):
        path = filedialog.askopenfilename(
            title="Pilih File Tugas",
            filetypes=[
                ("Semua File", "*.*"),
                ("PDF",  "*.pdf"),
                ("Word", "*.docx"),
                ("ZIP",  "*.zip"),
                ("Text", "*.txt"),
                ("PowerPoint", "*.pptx"),
            ]
        )
        if path:
            self.selected_file.set(path)
            size = os.path.getsize(path)
            self._log(f"📄 File dipilih: {os.path.basename(path)} ({size} bytes)", "cyan")
            self.status_var.set(f"File: {os.path.basename(path)}")

    # ─────────────────────────────────────────────
    # Callback: RUN ENKRIPSI
    # ─────────────────────────────────────────────

    def _run_encrypt(self):
        file_path  = self.selected_file.get()
        dosen_pub  = self.dosen_pub_key.get()
        student_priv = self.student_priv_key.get()

        if not os.path.exists(file_path):
            messagebox.showwarning("Perhatian", "Pilih file tugas terlebih dahulu!")
            return
        if not dosen_pub or not os.path.exists(dosen_pub):
            messagebox.showwarning("Perhatian", "Load Public Key Dosen terlebih dahulu!")
            return
        if not student_priv or not os.path.exists(student_priv):
            messagebox.showwarning("Perhatian", "Load Private Key Mahasiswa terlebih dahulu!")
            return

        def task():
            try:
                self._log_separator("RUN ENKRIPSI HYBRID")
                self._log("⏳ Memulai proses enkripsi...", "info")
                self.status_var.set("Enkripsi berjalan...")
                self._set_final("Proses enkripsi...", True)

                from hybrid_system import encrypt_assignment

                result = encrypt_assignment(
                    input_file               = file_path,
                    dosen_public_key_path    = dosen_pub,
                    student_private_key_path = student_priv,
                    output_folder            = "encrypted"
                )

                self.last_enc_result = result

                self._log("", "info")
                self._log("✓ AES-256 enkripsi file       : SUKSES", "success")
                self._log("✓ RSA enkripsi AES key        : SUKSES", "success")
                self._log("✓ SHA-256 hash dibuat         : SUKSES", "success")
                self._log("✓ Digital Signature dibuat    : SUKSES", "success")
                self._log(f"✓ File .enc : {result['enc_path']}",  "cyan")
                self._log(f"✓ File .key : {result['key_path']}",  "cyan")
                self._log(f"✓ File .sig : {result['sig_path']}",  "cyan")
                self._log(f"✓ File .hash: {result['hash_path']}", "cyan")
                self._log(f"⏱ Total waktu : {result['total_time']} detik", "warning")

                self._set_status("enkripsi",  "✓ Selesai", True)
                self._set_status("rsa_enc",   "✓ Selesai", True)
                self._set_status("hash",      "✓ Selesai", True)
                self._set_status("signature", "✓ Selesai", True)
                self.time_var.set(f"Enkripsi: {result['total_time']}s")
                self._set_final("✓ ENKRIPSI BERHASIL\nFile siap dikirim ke dosen!", True)
                self.status_var.set("Enkripsi selesai")

            except Exception as e:
                self._log(f"✗ Error enkripsi: {e}", "danger")
                self._set_final(f"✗ ENKRIPSI GAGAL: {e}", False)
                messagebox.showerror("Error Enkripsi", str(e))

        threading.Thread(target=task, daemon=True).start()

    # ─────────────────────────────────────────────
    # Callback: RUN DEKRIPSI
    # ─────────────────────────────────────────────

    def _run_decrypt(self):
        # Pilih file .enc
        enc_file = filedialog.askopenfilename(
            title="Pilih File .enc",
            filetypes=[("Encrypted File", "*.enc"), ("All", "*.*")],
            initialdir="encrypted"
        )
        if not enc_file:
            return

        dosen_priv   = self.dosen_priv_key.get()
        student_pub  = self.student_pub_key.get()

        if not dosen_priv or not os.path.exists(dosen_priv):
            messagebox.showwarning("Perhatian", "Load Private Key Dosen terlebih dahulu!")
            return
        if not student_pub or not os.path.exists(student_pub):
            messagebox.showwarning("Perhatian", "Load Public Key Mahasiswa terlebih dahulu!")
            return

        # Cari file pasangan otomatis
        key_file  = enc_file.replace(".enc", ".key")
        sig_file  = enc_file.replace(".enc", ".sig")
        hash_file = enc_file.replace(".enc", ".hash")

        missing = []
        for f, name in [(key_file, ".key"), (sig_file, ".sig"), (hash_file, ".hash")]:
            if not os.path.exists(f):
                missing.append(name)

        if missing:
            messagebox.showwarning(
                "File Tidak Lengkap",
                f"File berikut tidak ditemukan:\n{', '.join(missing)}\n\n"
                "Pastikan semua file enkripsi berada di folder yang sama."
            )
            return

        def task():
            try:
                self._log_separator("RUN DEKRIPSI + VERIFIKASI")
                self._log("⏳ Memulai proses dekripsi...", "info")
                self.status_var.set("Dekripsi berjalan...")
                self._set_final("Proses dekripsi...", True)

                from hybrid_system import decrypt_assignment

                result = decrypt_assignment(
                    enc_file               = enc_file,
                    key_file               = key_file,
                    sig_file               = sig_file,
                    hash_file_path         = hash_file,
                    dosen_private_key_path = dosen_priv,
                    student_public_key_path = student_pub,
                    output_folder          = "decrypted"
                )

                # Tampilkan hasil
                self._log("", "info")

                # Dekripsi
                ok_dec = result["decryption_ok"]
                self._log(
                    f"{'✓' if ok_dec else '✗'} Dekripsi AES  : {result['decryption_msg']}",
                    "success" if ok_dec else "danger"
                )
                self._set_status("enkripsi", "✓ OK" if ok_dec else "✗ GAGAL", ok_dec)

                # Integritas
                ok_int = result["integrity_ok"]
                self._log(
                    f"{'✓' if ok_int else '✗'} Integritas    : {result['integrity_msg']}",
                    "success" if ok_int else "danger"
                )
                self._set_status("integritas", "✓ OK" if ok_int else "✗ GAGAL", ok_int)

                # Signature
                ok_sig = result["signature_ok"]
                self._log(
                    f"{'✓' if ok_sig else '✗'} Signature     : {result['signature_msg']}",
                    "success" if ok_sig else "danger"
                )
                self._set_status("sig_verify", "✓ Valid" if ok_sig else "✗ GAGAL", ok_sig)

                self._log(f"⏱ Total waktu  : {result['total_time']} detik", "warning")

                # Status akhir
                if result["status"] == "AMAN":
                    self._set_final("✓ FILE AMAN\nIntegritas & Signature Valid!", True)
                    self._log("\n🎉 FILE AMAN - Tugas dapat diterima!", "success")
                    messagebox.showinfo("Dekripsi Berhasil",
                                       "✓ File berhasil didekripsi!\n"
                                       "✓ Integritas terjaga\n"
                                       "✓ Signature valid\n\n"
                                       f"File tersimpan di: {result.get('output_file', 'decrypted/')}")
                else:
                    self._set_final("✗ INTEGRITAS GAGAL!\nFile mungkin dimanipulasi!", False)
                    self._log("\n⚠️ PERINGATAN: FILE BERMASALAH!", "danger")
                    self._log("   Kemungkinan file telah dimanipulasi oleh pihak lain!", "danger")
                    messagebox.showerror("INTEGRITAS GAGAL",
                                         "✗ INTEGRITAS FILE GAGAL!\n\n"
                                         "File mungkin telah dimanipulasi oleh pihak lain.\n"
                                         "Dosen TIDAK dapat menerima file ini.\n\n"
                                         f"Integritas : {result['integrity_msg']}\n"
                                         f"Signature  : {result['signature_msg']}")

                self.time_var.set(f"Dekripsi: {result['total_time']}s")
                self.status_var.set("Dekripsi selesai")

            except Exception as e:
                self._log(f"✗ Error dekripsi: {e}", "danger")
                self._set_final(f"✗ ERROR: {e}", False)
                messagebox.showerror("Error Dekripsi", str(e))

        threading.Thread(target=task, daemon=True).start()

    # ─────────────────────────────────────────────
    # Callback: Verifikasi Signature
    # ─────────────────────────────────────────────

    def _verify_sig(self):
        file_path = filedialog.askopenfilename(
            title="Pilih file yang akan diverifikasi signaturenya",
            initialdir="decrypted"
        )
        if not file_path:
            return

        sig_path = filedialog.askopenfilename(
            title="Pilih file .sig",
            filetypes=[("Signature", "*.sig"), ("All", "*.*")],
            initialdir="encrypted"
        )
        if not sig_path:
            return

        student_pub = self.student_pub_key.get()
        if not student_pub or not os.path.exists(student_pub):
            messagebox.showwarning("Perhatian", "Load Public Key Mahasiswa terlebih dahulu!")
            return

        def task():
            try:
                self._log_separator("VERIFIKASI DIGITAL SIGNATURE")
                from signature_module import verify_signature, load_signature
                from rsa_module import load_public_key

                pub_key   = load_public_key(student_pub)
                sig_data  = load_signature(sig_path)
                sig_bytes = sig_data["signature_bytes"]

                ok, msg = verify_signature(file_path, sig_bytes, pub_key)
                tag = "success" if ok else "danger"
                self._log(f"{'✓' if ok else '✗'} {msg}", tag)
                self._set_status("sig_verify", "✓ Valid" if ok else "✗ GAGAL", ok)
                self._set_final(msg, ok)

                if ok:
                    messagebox.showinfo("Signature Valid", f"✓ {msg}")
                else:
                    messagebox.showerror("Signature GAGAL", f"✗ {msg}")

            except Exception as e:
                self._log(f"✗ Error: {e}", "danger")
                messagebox.showerror("Error", str(e))

        threading.Thread(target=task, daemon=True).start()

    # ─────────────────────────────────────────────
    # Callback: Cek Hash
    # ─────────────────────────────────────────────

    def _check_hash(self):
        file_path = filedialog.askopenfilename(
            title="Pilih file yang akan dicek hashnya",
            initialdir="decrypted"
        )
        if not file_path:
            return

        hash_path = filedialog.askopenfilename(
            title="Pilih file .hash",
            filetypes=[("Hash File", "*.hash"), ("All", "*.*")],
            initialdir="encrypted"
        )
        if not hash_path:
            return

        def task():
            try:
                self._log_separator("CEK HASH SHA-256")
                from hashing_module import verify_integrity, load_hash

                hash_data = load_hash(hash_path)
                expected  = hash_data["sha256"]

                self._log(f"Hash tersimpan  : {expected[:30]}...", "info")

                ok, msg = verify_integrity(file_path, expected)
                tag = "success" if ok else "danger"
                self._log(f"{'✓' if ok else '✗'} {msg}", tag)
                self._set_status("integritas", "✓ OK" if ok else "✗ GAGAL", ok)
                self._set_final(msg, ok)

                if ok:
                    messagebox.showinfo("Integritas Terjaga", f"✓ {msg}")
                else:
                    messagebox.showerror("INTEGRITAS GAGAL", f"✗ {msg}")

            except Exception as e:
                self._log(f"✗ Error: {e}", "danger")
                messagebox.showerror("Error", str(e))

        threading.Thread(target=task, daemon=True).start()

    # ─────────────────────────────────────────────
    # Callback: Simulasi Serangan
    # ─────────────────────────────────────────────

    def _attack_file(self):
        enc_file = filedialog.askopenfilename(
            title="Pilih file .enc yang akan dimanipulasi",
            filetypes=[("Encrypted File", "*.enc"), ("All", "*.*")],
            initialdir="encrypted"
        )
        if not enc_file:
            return

        confirm = messagebox.askyesno(
            "Konfirmasi Serangan",
            f"⚠️ Anda akan mensimulasikan serangan pada:\n{enc_file}\n\n"
            "File .enc akan dimodifikasi sehingga verifikasi akan GAGAL.\n"
            "Backup otomatis akan dibuat.\n\nLanjutkan?"
        )
        if not confirm:
            return

        def task():
            try:
                self._log_separator("SIMULASI SERANGAN MANIPULASI FILE")
                self._log("⚠️ Mensimulasikan serangan byte-flip...", "warning")

                from attack_simulation import backup_file, attack_byte_flip, generate_attack_report

                backup_path = backup_file(enc_file)
                self._log(f"♻ Backup dibuat: {backup_path}", "info")

                info = attack_byte_flip(enc_file, num_bytes=5)

                if info:
                    self._log(f"✗ {info['bytes_changed']} byte berhasil diubah!", "danger")
                    for pos, ori, new in info["positions"]:
                        self._log(f"  Offset 0x{pos:04X}: 0x{ori:02X} → 0x{new:02X}", "danger")

                    self._set_status("integritas", "✗ DISERANG", False)
                    self._set_final("⚠️ File telah dimanipulasi!\nDekripsi akan gagal!", False)
                    messagebox.showwarning(
                        "Serangan Berhasil",
                        "⚠️ File .enc telah dimanipulasi!\n\n"
                        "Jika dosen mendekripsi file ini:\n"
                        "  ✗ Verifikasi AES tag akan GAGAL\n"
                        "  ✗ Hash SHA-256 akan BERBEDA\n"
                        "  ✗ Program akan menampilkan: INTEGRITAS GAGAL\n\n"
                        "Coba jalankan RUN DEKRIPSI untuk melihat hasilnya!"
                    )

            except Exception as e:
                self._log(f"✗ Error: {e}", "danger")
                messagebox.showerror("Error", str(e))

        threading.Thread(target=task, daemon=True).start()

    def _restore_file(self):
        enc_file = filedialog.askopenfilename(
            title="Pilih file .enc yang akan di-restore",
            filetypes=[("Encrypted File", "*.enc"), ("All", "*.*")],
            initialdir="encrypted"
        )
        if not enc_file:
            return

        def task():
            try:
                self._log_separator("RESTORE FILE .enc")
                from attack_simulation import restore_file

                ok = restore_file(enc_file)
                if ok:
                    self._log(f"✓ File berhasil dipulihkan: {enc_file}", "success")
                    self._set_status("integritas", "✓ Restored", True)
                    messagebox.showinfo("Restore Berhasil", f"✓ File berhasil dipulihkan!\n{enc_file}")
                else:
                    self._log("✗ Backup tidak ditemukan!", "danger")
                    messagebox.showerror("Gagal", "File backup tidak ditemukan!")

            except Exception as e:
                self._log(f"✗ Error: {e}", "danger")
                messagebox.showerror("Error", str(e))

        threading.Thread(target=task, daemon=True).start()

    # ─────────────────────────────────────────────
    # Callback: Benchmark
    # ─────────────────────────────────────────────

    def _run_benchmark(self):
        file_path = filedialog.askopenfilename(
            title="Pilih file untuk benchmark",
            initialdir="testfiles"
        )
        if not file_path:
            return

        def task():
            try:
                self._log_separator("BENCHMARK RSA vs HYBRID")
                self._log("⏳ Menjalankan benchmark...", "info")
                self.status_var.set("Benchmark berjalan...")

                from hybrid_system import benchmark_comparison

                result = benchmark_comparison(file_path, rsa_bits=512)

                self._log("", "info")
                self._log(f"{'METODE':<25} {'ENKRIPSI':<12} {'DEKRIPSI':<12}", "header")
                self._log("-" * 50, "header")
                self._log(
                    f"{'Hybrid (AES+RSA)':<25} {result['hybrid_enc_time']:<12} {result['hybrid_dec_time']:<12}",
                    "success"
                )
                self._log(
                    f"{'RSA Murni (est.)':<25} {result['rsa_enc_time_est']:<12} {result['rsa_   dec_time_est']:<12}",
                    "warning"
                )

                if result['rsa_enc_time_est'] > 0:
                    speedup = result['rsa_enc_time_est'] / result['hybrid_enc_time']
                    self._log(f"\nHybrid {speedup:.1f}x lebih cepat dari RSA murni!", "cyan")

                self.status_var.set("Benchmark selesai")

            except Exception as e:
                self._log(f"✗ Error benchmark: {e}", "danger")
                messagebox.showerror("Error Benchmark", str(e))

        threading.Thread(target=task, daemon=True).start()

    # ─────────────────────────────────────────────
    # Callback: Buat File Test
    # ─────────────────────────────────────────────

    def _make_test_file(self):
        from tkinter.simpledialog import askstring
        nama = askstring("File Test", "Nama file test (tanpa ekstensi):", initialvalue="tugas_kriptografi")
        if not nama:
            return

        os.makedirs("testfiles", exist_ok=True)
        path = f"testfiles/{nama}.txt"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"TUGAS KRIPTOGRAFI\n")
            f.write(f"=" * 40 + "\n")
            f.write(f"Nama  : Mahasiswa Test\n")
            f.write(f"NIM   : 12345678\n")
            f.write(f"Kelas : Kriptografi A\n")
            f.write(f"=" * 40 + "\n\n")
            f.write("Implementasi RSA dan AES:\n")
            f.write("RSA adalah algoritma enkripsi asimetris yang menggunakan pasangan kunci.\n" * 10)
            f.write("\n" + "Data dummy: " + "X" * 200 + "\n")

        self.selected_file.set(path)
        size = os.path.getsize(path)
        self._log(f"✓ File test dibuat: {path} ({size} bytes)", "success")
        self._log("  File ini dapat langsung digunakan untuk enkripsi.", "info")
        messagebox.showinfo("File Test Dibuat", f"✓ File test berhasil dibuat:\n{path}\n\nUkuran: {size} bytes")


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

def main():
    """Jalankan aplikasi GUI."""

    # Buat semua folder yang diperlukan
    for folder in ["sender", "receiver", "encrypted", "decrypted", "testfiles"]:
        os.makedirs(folder, exist_ok=True)

    root = tk.Tk()
    app  = HybridEncryptionGUI(root)

    # Ikon jika ada
    try:
        root.iconbitmap("icon.ico")
    except Exception:
        pass

    root.mainloop()


if __name__ == "__main__":
    main()