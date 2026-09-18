# 🧠 Skil AI - AI Behavior Rules System

> Sistem aturan/skill untuk membuat AI coding assistant bekerja lebih **stabil**, **profesional**, dan **terkontrol**.

## 🎯 Masalah yang Diselesaikan

- ❌ AI langsung eksekusi tanpa tanya detail
- ❌ AI ngide sendiri dan mengubah kode sembarangan
- ❌ AI tidak konfirmasi sebelum melakukan perubahan
- ❌ AI tidak memahami konteks project dengan baik

## ✅ Solusi

Skil AI menyediakan **rules/instructions** yang bisa dipasang di:
- **Cline** (VS Code Extension)
- **OpenCode CLI**
- **AI Tools lainnya** yang support custom instructions

## 📁 Struktur Folder

```
Skil AI/
├── README.md                          # Dokumentasi ini
├── rules/
│   ├── .clinerules                    # Rules utama untuk Cline
│   ├── opencode-rules.md             # Rules untuk OpenCode CLI
│   └── universal-rules.md            # Rules universal (bisa dipakai di mana saja)
├── templates/
│   ├── checklist-before-execute.md    # Template checklist sebelum eksekusi
│   ├── change-confirmation.md        # Template konfirmasi perubahan
│   └── task-breakdown.md             # Template breakdown tugas
└── examples/
    ├── good-workflow.md               # Contoh alur kerja yang baik
    └── bad-workflow.md                # Contoh alur kerja yang buruk
```

---

## 🚀 CARA SETUP & PAKAI

### Setup untuk Cline (VS Code Extension)

Cline otomatis membaca file `.clinerules` yang ada di **root folder project** kamu.

**Cara 1: Copy file ke setiap project (Recommended)**

```
1. Buka folder project kamu, misalnya: D:\Project\MyApp
2. Copy file "rules/.clinerules" ke root project kamu
3. Hasilnya jadi: D:\Project\MyApp\.clinerules
4. Selesai! Cline akan otomatis membaca rules ini
```

Contoh langkah di terminal PowerShell:
```powershell
# Misal project kamu di D:\Project\MyApp
Copy-Item "D:\Project\Skil AI\rules\.clinerules" -Destination "D:\Project\MyApp\.clinerules"
```

Setelah copy, struktur project kamu jadi:
```
MyApp/
├── .clinerules          <-- file ini yang dibaca Cline
├── src/
├── package.json
└── ...
```

**Cara 2: Lewat Cline Settings (Global, berlaku untuk semua project)**

```
1. Buka VS Code
2. Klik icon Cline di sidebar kiri
3. Klik icon gear (⚙️) untuk buka Settings
4. Cari bagian "Custom Instructions" atau "System Prompt"
5. Buka file "rules/.clinerules" dengan notepad/VS Code
6. Copy SEMUA isinya
7. Paste ke kotak "Custom Instructions" di Cline Settings
8. Save
9. Selesai! Berlaku untuk semua project
```

**Mana yang lebih baik?**
| Cara | Kelebihan | Kekurangan |
|------|-----------|------------|
| Cara 1 (Copy file) | Bisa beda rules per project | Harus copy ke setiap project |
| Cara 2 (Settings) | Berlaku global, sekali setup | Sama untuk semua project |

---

### Setup untuk OpenCode CLI

OpenCode CLI menggunakan file `AGENTS.md` atau `instructions.md` di root project.

**Cara 1: Pakai file AGENTS.md (Recommended)**

```
1. Buka folder project kamu, misalnya: D:\Project\MyApp
2. Copy file "rules/opencode-rules.md" ke root project dengan nama AGENTS.md
3. Hasilnya jadi: D:\Project\MyApp\AGENTS.md
4. Selesai! OpenCode akan otomatis membaca rules ini
```

Contoh langkah di terminal PowerShell:
```powershell
# Misal project kamu di D:\Project\MyApp
Copy-Item "D:\Project\Skil AI\rules\opencode-rules.md" -Destination "D:\Project\MyApp\AGENTS.md"
```

**Cara 2: Lewat config OpenCode**

```
1. Buka file config OpenCode (biasanya di ~/.config/opencode/config.json)
2. Tambahkan isi dari "rules/opencode-rules.md" ke bagian system prompt
3. Save dan restart OpenCode
```

---

### Setup untuk AI Tools Lainnya (ChatGPT, Claude, Cursor, dll)

```
1. Buka file "rules/universal-rules.md"
2. Copy SEMUA isinya
3. Paste ke bagian:
   - ChatGPT → Custom Instructions
   - Claude → System Prompt / Project Instructions
   - Cursor → Rules for AI (Settings > Rules)
   - AI tool lain → Custom Instructions / System Prompt
4. Save
5. Selesai!
```

---

## 🔄 CARA PAKAI SEHARI-HARI

Setelah setup, kamu tinggal pakai AI seperti biasa. Bedanya sekarang AI akan:

**Sebelum pakai Skil AI:**
```
Kamu: "Buatkan tombol submit"
AI: *langsung bikin kode, install library, refactor file lain* 😱
```

**Sesudah pakai Skil AI:**
```
Kamu: "Buatkan tombol submit"

AI: "Oke, sebelum saya mulai, saya mau tanya dulu:
     1. Tombol ini untuk form apa?
     2. Mau pakai style apa?
     3. Perlu loading state?
     4. Ada validasi yang diperlukan?"

Kamu: "Untuk form login, pakai Tailwind, perlu loading"

AI: "📋 Rencana:
     1. Buat SubmitButton.tsx
     2. Ubah LoginForm.tsx
     Boleh saya lanjut?"

Kamu: "Lanjut"

AI: *mengerjakan sesuai rencana, konfirmasi setiap perubahan* ✅
```

---

## 📖 Prinsip Utama

1. **🔍 Gather First** - Selalu kumpulkan informasi dan konteks dulu
2. **❓ Ask Before Act** - Tanya detail sebelum eksekusi
3. **✅ Confirm Changes** - Konfirmasi setiap perubahan
4. **📋 Plan Then Do** - Buat rencana dulu, baru kerjakan
5. **🔒 No Surprises** - Tidak ada perubahan kejutan/tak terduga
6. **📊 Report Results** - Selalu laporkan hasil akhir

## ❓ FAQ

**Q: Apakah harus setup ulang setiap buat project baru?**
A: Kalau pakai Cara 1 (copy file), iya harus copy `.clinerules` ke project baru.
Kalau pakai Cara 2 (global settings), tidak perlu.

**Q: Bisa pakai untuk Cline dan OpenCode sekaligus?**
A: Bisa! Copy `.clinerules` DAN `AGENTS.md` ke root project yang sama.

**Q: Aturannya bisa dimodifikasi?**
A: Tentu! Edit file rules sesuai kebutuhan kamu. Mau tambah aturan baru juga boleh.

**Q: AI nya masih suka ngide sendiri, gimana?**
A: Pastikan rules sudah ter-load dengan benar. Cek di Cline Settings apakah
Custom Instructions sudah terisi. Kalau masih bandel, tambahkan penekanan
di rules-nya.

## 🤝 Kontribusi

Feel free untuk menambah atau memodifikasi rules sesuai kebutuhan project kamu!

---

**Made with ❤️ untuk developer yang mau AI-nya lebih nurut dan profesional**
