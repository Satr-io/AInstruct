# ✏️ Template Konfirmasi Perubahan

> Template ini digunakan AI saat ingin mengubah file yang sudah ada.

---

## Format Konfirmasi Perubahan

```markdown
✏️ **Perubahan yang akan dilakukan:**

**File:** `[path/to/file]`

**Alasan:** [Jelaskan kenapa perubahan ini diperlukan]

**Kode Lama (yang akan diubah):**
```[bahasa]
// kode yang akan diganti
```

**Kode Baru (pengganti):**
```[bahasa]
// kode pengganti
```

**Dampak:**
- [Dampak 1]
- [Dampak 2]

Boleh saya terapkan perubahan ini? (Ya/Tidak)
```

---

## Contoh Penggunaan

### Contoh 1: Mengubah Fungsi

```markdown
✏️ **Perubahan yang akan dilakukan:**

**File:** `src/components/Button.tsx`

**Alasan:** Menambahkan loading state pada tombol submit sesuai permintaan.

**Kode Lama:**
```tsx
const Button = ({ label, onClick }) => {
  return <button onClick={onClick}>{label}</button>
}
```

**Kode Baru:**
```tsx
const Button = ({ label, onClick, isLoading = false }) => {
  return (
    <button onClick={onClick} disabled={isLoading}>
      {isLoading ? 'Loading...' : label}
    </button>
  )
}
```

**Dampak:**
- Menambahkan prop `isLoading` dengan default `false`
- Tombol akan disabled saat loading
- Text berubah menjadi "Loading..." saat loading

Boleh saya terapkan perubahan ini? (Ya/Tidak)
```

---

## Tips untuk AI

1. **Selalu tunjukkan konteks** - Jangan hanya tunjukkan 1 baris, tunjukkan cukup konteks
2. **Jelaskan dampak** - User harus tahu apa efek dari perubahan
3. **Satu perubahan per konfirmasi** - Jangan gabung banyak perubahan dalam satu konfirmasi
4. **Tunggu jawaban** - Jangan lanjut sebelum dapat persetujuan
