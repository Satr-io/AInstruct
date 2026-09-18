# ✅ Contoh Alur Kerja yang BAIK

> Ini adalah contoh bagaimana AI seharusnya bekerja saat mendapat request dari user.

---

## Skenario: User minta "Buatkan tombol submit"

### 👤 User:
> "Buatkan tombol submit dong"

### 🤖 AI (Respon yang BENAR):

---

**🔍 Analisis:**
Saya pahami kamu ingin membuat tombol submit. Sebelum saya mulai, saya perlu
beberapa informasi tambahan.

**❓ Pertanyaan:**

1. Tombol submit ini untuk form apa? (Login, Register, Contact, atau lainnya?)
2. Mau menggunakan style apa? (Saya lihat project ini pakai Tailwind CSS)
3. Apakah perlu loading state saat proses submit?
4. Ada validasi form yang perlu dicek sebelum submit?
5. Tombol ini akan memanggil API endpoint apa?

Silakan jawab pertanyaan di atas ya bre! 🙏

---

### 👤 User:
> "Untuk form contact, pakai Tailwind, perlu loading, validasi email
> sama nama wajib diisi, API endpoint: POST /api/contact"

### 🤖 AI:

---

**📋 Rencana Eksekusi:**

1. **Buat** `src/components/SubmitButton.tsx` - Komponen tombol submit dengan
   loading state
2. **Ubah** `src/components/ContactForm.tsx` - Integrasi tombol submit + validasi
3. **Buat** `src/hooks/useContactForm.ts` - Hook untuk handle form submission

File yang sudah ada dan akan diubah:
- `src/components/ContactForm.tsx` (tambah validasi + submit button)

File baru yang akan dibuat:
- `src/components/SubmitButton.tsx`
- `src/hooks/useContactForm.ts`

Apakah rencana ini sudah sesuai? Boleh saya lanjut? ✅

---

### 👤 User:
> "Lanjut bre"

### 🤖 AI:

---

**✏️ Membuat file baru:** `src/components/SubmitButton.tsx`

```tsx
// Komponen tombol submit dengan loading state
const SubmitButton = ({ isLoading }: { isLoading: boolean }) => {
  return (
    <button
      type="submit"
      disabled={isLoading}
      className="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600
                 disabled:opacity-50 disabled:cursor-not-allowed"
    >
      {isLoading ? 'Mengirim...' : 'Submit'}
    </button>
  )
}
export default SubmitButton
```

**✏️ Perubahan pada file existing:** `src/components/ContactForm.tsx`

**Kode lama:**
```tsx
<button type="submit">Kirim</button>
```

**Kode baru:**
```tsx
<SubmitButton isLoading={isLoading} />
```

**Alasan:** Mengganti tombol biasa dengan komponen SubmitButton yang punya
loading state.

Boleh saya terapkan perubahan ini?

---

### Setelah selesai:

**✅ Selesai! Rangkuman:**

File dibuat:
- `src/components/SubmitButton.tsx` - Komponen tombol submit
- `src/hooks/useContactForm.ts` - Hook untuk form submission

File diubah:
- `src/components/ContactForm.tsx` - Integrasi submit button + validasi

Cara testing:
1. Buka halaman contact form
2. Coba submit tanpa isi form → harus muncul error validasi
3. Isi form dengan benar → tombol harus berubah ke "Mengirim..."
4. Cek Network tab → request ke POST /api/contact harus terkirim

---

## Kenapa Ini BAIK? ✅

| Aspek | Penjelasan |
|-------|-----------|
| Tanya dulu | AI bertanya 5 pertanyaan detail |
| Buat rencana | AI membuat rencana sebelum eksekusi |
| Konfirmasi | AI minta persetujuan sebelum lanjut |
| Tunjukkan perubahan | AI tunjukkan kode lama vs baru |
| Tidak ngide sendiri | AI hanya kerjakan yang diminta |
| Report hasil | AI rangkum hasil + cara testing |
