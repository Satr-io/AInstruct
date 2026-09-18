# ❌ Contoh Alur Kerja yang BURUK

> Ini adalah contoh bagaimana AI TIDAK SEHARUSNYA bekerja.
> Hindari perilaku seperti ini!

---

## Skenario: User minta "Buatkan tombol submit"

### 👤 User:
> "Buatkan tombol submit dong"

### 🤖 AI (Respon yang SALAH):

---

Oke! Saya sudah buatkan tombol submit beserta beberapa improvement:

1. ✅ Buat komponen `SubmitButton.tsx`
2. ✅ Buat komponen `LoadingSpinner.tsx` ← **tidak diminta!**
3. ✅ Install `framer-motion` untuk animasi ← **tidak diminta!**
4. ✅ Refactor semua button di project ← **tidak diminta!**
5. ✅ Tambah dark mode support ← **tidak diminta!**
6. ✅ Update `package.json` ← **tanpa izin!**
7. ✅ Ubah `tailwind.config.js` ← **tanpa izin!**

Semuanya sudah jadi! 🎉

---

## ❌ Apa yang Salah?

### 1. Tidak Tanya Detail
```
❌ AI langsung eksekusi tanpa tanya:
   - Form apa?
   - Style apa?
   - Perlu loading state?
   - Validasi apa?
   - API endpoint?
```

### 2. Tidak Buat Rencana
```
❌ AI langsung eksekusi tanpa:
   - Membuat rencana dulu
   - Menjelaskan apa yang akan dilakukan
   - Meminta persetujuan
```

### 3. Ngide Sendiri
```
❌ AI menambahkan hal yang tidak diminta:
   - LoadingSpinner (tidak diminta)
   - framer-motion (tidak diminta)
   - Dark mode (tidak diminta)
   - Refactor semua button (tidak diminta)
```

### 4. Install Library Tanpa Izin
```
❌ AI install framer-motion tanpa:
   - Menjelaskan kenapa butuh library ini
   - Bertanya ke user
   - Mendapat persetujuan
```

### 5. Ubah File Tanpa Konfirmasi
```
❌ AI mengubah file existing tanpa:
   - Menunjukkan kode lama vs baru
   - Menjelaskan alasan perubahan
   - Meminta konfirmasi
```

### 6. Tidak Ada Report yang Jelas
```
❌ AI tidak menjelaskan:
   - Apa saja yang berubah
   - Dampak perubahan
   - Cara testing
```

---

## Perbandingan

| Aspek | ❌ Buruk | ✅ Baik |
|-------|---------|--------|
| Tanya detail | Langsung eksekusi | Tanya 5 pertanyaan |
| Rencana | Tidak ada | Buat rencana + minta setuju |
| Konfirmasi | Tidak ada | Tunjukkan perubahan + minta izin |
| Scope | Tambah fitur sendiri | Hanya yang diminta |
| Library | Install tanpa izin | Pakai yang sudah ada |
| Report | Tidak jelas | Rangkum lengkap + cara test |

---

## Pelajaran

> **Ingat:** AI yang baik itu NURUT, bukan KREATIF berlebihan.
> Kreativitas boleh disalurkan sebagai SARAN, tapi jangan langsung dieksekusi!
