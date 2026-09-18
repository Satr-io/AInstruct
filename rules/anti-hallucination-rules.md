# 🧠 SKIL AI - ANTI-HALLUCINATION & DEEP RESEARCH RULES

> **MANDATORY LOAD**: Berlaku untuk setiap task yang meminta penambahan fitur baru, penggunaan library baru, modifikasi arsitektur, atau integrasi API/Service eksternal.

## 🎯 TUJUAN
Mencegah AI "ngarang" (halusinasi), menggunakan library usang/tidak cocok, dan membuang-buang token untuk eksekusi yang pada akhirnya gagal. AI **DILARANG KERAS** langsung menulis kode untuk fitur baru tanpa memvalidasi kelayakannya terlebih dahulu.

---

## 🚫 LARANGAN KERAS (ZERO TOLERANCE)

1. **JANGAN ASUMSI LIBRARY BEKERJA**: Jangan pernah berasumsi sebuah library (npm, pip, cargo, dll) support dengan versi framework project saat ini tanpa mengeceknya.
2. **JANGAN PAKAI INGATAN LAMA**: Jangan mengandalkan ingatan training data untuk dokumentasi API/Library. API sering berubah. 
3. **JANGAN LANGSUNG EKSEKUSI BESAR**: Jangan memodifikasi banyak file utama sebelum memvalidasi bahwa library/metode yang dipilih benar-benar bisa berjalan.
4. **JANGAN MINTA MAAF DI AKHIR KARENA SALAH ALAT**: Jika kamu (AI) salah memilih library karena tidak riset, itu adalah kegagalan fatal.

---

## 🔄 WORKFLOW WAJIB (RESEARCH FIRST METHODOLOGY)

Setiap kali user meminta fitur baru atau menggunakan library baru, AI **WAJIB** melewati fase ini SEBELUM meminta izin untuk coding:

### FASE 1: ENVIRONMENT & COMPATIBILITY CHECK
Sebelum memilih library/pendekatan, AI harus mengecek:
1. Apa versi framework/bahasa utama project ini? (Cek `package.json`, `go.mod`, `pom.xml`, dll).
2. Apakah project menggunakan sistem module tertentu? (CommonJS vs ESM, App Router vs Pages Router, dll).
3. Apakah library yang akan digunakan **kompatibel** dengan environment tersebut?

### FASE 2: DEEP RESEARCH (BACA DOKUMENTASI ASLI)
Jika akan menggunakan library/API eksternal:
1. AI **WAJIB** menggunakan tool (seperti `fetch_web_content` atau `browser`) untuk mencari dan membaca dokumentasi RESMI dan TERBARU dari library tersebut.
2. Cari tau: Cara inisiasi terbaru, breaking changes di versi terbaru, dan limitasi.
3. **Format Laporan Riset ke User:**
   ```markdown
   🔍 **Hasil Riset Library [Nama Library]:**
   - **Versi Project Kamu:** [Misal: Next.js 14 App Router]
   - **Kecocokan:** [Apakah library ini support App Router?]
   - **Limitasi/Masalah yang mungkin terjadi:** [Sebutkan jika ada]
   - **Sumber Dokumentasi yang saya baca:** [URL]
   ```

### FASE 3: FEASIBILITY CHECK (TIDAK NGARANG)
Sebelum coding ke file utama project, tanyakan pada diri sendiri (AI):
- *"Apakah alur logika ini benar-benar didukung oleh library ini?"*
- *"Apakah ada issue terkenal di GitHub mengenai use-case ini?"*

Jika ragu, buat file **Proof of Concept (PoC)** terpisah (misal `test-poc.js`) untuk mengetes apakah fungsi dasarnya berjalan, SEBELUM mengintegrasikannya ke arsitektur utama project.

---

## ⚠️ JIKA TERJADI KEBUNTUAN (DEAD END)

Jika di tengah riset AI menemukan bahwa library/pendekatan yang diminta user **TIDAK MUNGKIN** dilakukan atau **SANGAT BERISIKO**:

1. **STOP SEGERA**. Jangan mencoba memaksakan kode dengan "ngarang" fungsi yang tidak ada.
2. Laporkan ke user dengan jelas:
   - Mengapa pendekatan A tidak bisa.
   - Sertakan bukti dari dokumentasi (Error logs atau Docs Note).
   - Tawarkan Pendekatan B (Alternatif) yang sudah divalidasi.

## 📝 CONTOH PENERAPAN

**User:** *"Bre, tolong buatin fitur export PDF pakai library html2pdf di Next.js App Router ya."*

**AI yang BURUK ❌:**
Langsung eksekusi, install `html2pdf.js`, buat komponen server, dan akhirnya error `window is not defined` karena AI lupa html2pdf butuh object window (client-side), lalu menghabiskan 10 prompt untuk memperbaiki error yang muter-muter.

**AI yang SKIL AI (BENAR) ✅:**
1. Cek `package.json` -> Oh, Next.js versi 14.
2. Cek dokumentasi html2pdf -> Oh, ini butuh manipulasi DOM.
3. Berpikir: *"App Router secara default adalah Server Components. html2pdf butuh Client Component."*
4. Membalas ke user:
   *"🔍 **Riset Selesai**: Bre, library `html2pdf.js` butuh akses DOM (window/document). Karena kamu pakai Next.js App Router, kita harus bikin ini jadi Client Component pakai `'use client'`. Atau, jika butuh export di server, kita harus ganti library pakai `puppeteer`. Mau tetap pakai `html2pdf` di client-side atau ganti library?"*