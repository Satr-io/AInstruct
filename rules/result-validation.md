# Result Validation Rule

## Tujuan

Pastikan setiap perubahan benar-benar sesuai dengan permintaan
sebelum menyatakan task selesai.

## Wajib Validasi

Setelah melakukan perubahan:

1. Periksa kembali code yang diubah.
2. Cocokkan hasil implementasi dengan instruksi pengguna.
3. Pastikan tidak ada bagian yang berubah di luar scope.
4. Pastikan nilai atau spesifikasi yang diberikan pengguna tetap sama.
5. Jika perubahan berkaitan dengan UI/UX, pastikan layout, ukuran,
   posisi, spacing, warna, dan behavior sesuai dengan permintaan.
6. Jalankan verifikasi atau test yang relevan jika memang diperlukan.

## Jangan Menganggap Berhasil

Jangan menyatakan:

- "sudah selesai"
- "sudah sesuai"
- "sudah diperbaiki"
- "sudah berhasil"

hanya karena code berhasil diedit.

Perubahan code harus diperiksa terhadap hasil yang diminta.

## Jika Hasil Tidak Sesuai

Jika hasil validasi belum sesuai:

1. Jangan menyatakan task selesai.
2. Identifikasi bagian yang masih salah.
3. Periksa kembali code yang relevan.
4. Perbaiki hanya bagian yang diperlukan.
5. Validasi ulang.

Ulangi sampai hasil sesuai dengan instruksi pengguna.

## Jangan Mengubah Scope

Validasi bukan alasan untuk melakukan perubahan tambahan.

Jangan memperbaiki, merapikan, refactor, atau mengubah bagian
lain yang tidak diminta pengguna.

## Spesifikasi Literal

Jika pengguna memberikan nilai spesifik, gunakan nilai tersebut
secara tepat.

Contoh:

Pengguna meminta:

600px × 350px

Maka hasil harus:

600px × 350px

Jangan mengganti menjadi ukuran lain berdasarkan penilaian sendiri.

## Prinsip Utama

EDIT ≠ SELESAI

EDIT → VALIDATE → SESUAI → DONE

Jika belum sesuai:

EDIT → VALIDATE → PERBAIKI → VALIDATE → DONE