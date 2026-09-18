# 📋 Template Breakdown Tugas

> Template untuk memecah tugas besar menjadi langkah-langkah kecil.

---

## Format Task Breakdown

```markdown
📋 **Task Breakdown**

**Request:** [Apa yang diminta user]

**Analisis:** [Pemahaman AI tentang request]

---

### Sub-Tasks:

#### 1. [Nama Sub-task]
- **File:** `[path/to/file]`
- **Action:** Buat baru / Ubah / Hapus
- **Deskripsi:** [Apa yang akan dilakukan]
- **Estimasi:** Kecil / Sedang / Besar

#### 2. [Nama Sub-task]
- **File:** `[path/to/file]`
- **Action:** Buat baru / Ubah / Hapus
- **Deskripsi:** [Apa yang akan dilakukan]
- **Estimasi:** Kecil / Sedang / Besar

---

### Urutan Eksekusi:
1. Sub-task 1 (tidak ada dependency)
2. Sub-task 2 (depends on: Sub-task 1)
3. ...

### Dependencies:
- Library yang dibutuhkan: [list atau "Tidak ada"]
- File yang perlu ada: [list]

Apakah breakdown ini sudah sesuai? Mau mulai dari sub-task mana?
```

---

## Contoh Penggunaan

```markdown
📋 **Task Breakdown**

**Request:** "Buatkan halaman login dengan form email & password"

**Analisis:** User ingin halaman login lengkap dengan form validation.

---

### Sub-Tasks:

#### 1. Buat Komponen LoginPage
- **File:** `src/pages/LoginPage.tsx`
- **Action:** Buat baru
- **Deskripsi:** Komponen halaman utama login
- **Estimasi:** Sedang

#### 2. Buat Komponen LoginForm
- **File:** `src/components/LoginForm.tsx`
- **Action:** Buat baru
- **Deskripsi:** Form dengan input email & password + validasi
- **Estimasi:** Sedang

#### 3. Tambah Route Login
- **File:** `src/App.tsx`
- **Action:** Ubah (tambah route)
- **Deskripsi:** Menambahkan route `/login` ke LoginPage
- **Estimasi:** Kecil

---

### Urutan Eksekusi:
1. LoginForm (komponen dasar, tidak ada dependency)
2. LoginPage (depends on: LoginForm)
3. Route (depends on: LoginPage)

### Dependencies:
- Library: Tidak ada tambahan (pakai yang sudah ada)
- File: `src/App.tsx` (untuk routing)

Apakah breakdown ini sudah sesuai? Mau mulai dari sub-task mana?
```
