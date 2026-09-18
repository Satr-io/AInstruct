# Command Usage Policy

## Tujuan

Gunakan command hanya ketika command tersebut benar-benar diperlukan
untuk memahami, mengubah, atau memverifikasi project.

Command bukan langkah default dalam setiap task.

## Aturan Utama

Sebelum menjalankan command, tentukan terlebih dahulu:

1. Apa tujuan command ini?
2. Informasi apa yang ingin diperoleh?
3. Apakah informasi tersebut benar-benar diperlukan untuk task?
4. Apakah informasi tersebut bisa diperoleh dengan membaca source code
   atau file yang sudah tersedia?

Jika command tidak memiliki tujuan yang jelas, JANGAN jalankan.

## Prioritas Workflow

Selalu ikuti urutan:

READ → UNDERSTAND → DECIDE → COMMAND → ACT → VERIFY

### READ
Baca source code dan file yang relevan terlebih dahulu.

### UNDERSTAND
Pahami struktur, alur, dependency, dan implementasi yang sudah ada.

### DECIDE
Tentukan apakah command benar-benar diperlukan.

### COMMAND
Jika diperlukan, jalankan hanya command yang relevan dengan kebutuhan tersebut.

### ACT
Lakukan perubahan setelah memahami code.

### VERIFY
Lakukan verifikasi yang relevan dengan perubahan.

## Larangan

Jangan:

- menjalankan command hanya untuk mencoba-coba
- menjalankan command tanpa mengetahui tujuannya
- menjalankan command karena command tersebut tersedia
- menjalankan banyak command sekaligus tanpa alasan
- menggunakan command sebagai pengganti membaca source code
- menjalankan build hanya karena project dapat di-build
- menjalankan test hanya karena project memiliki test
- menjalankan install atau update dependency tanpa instruksi atau kebutuhan nyata
- mencari file secara berulang jika lokasi file sudah diketahui
- melakukan scanning seluruh project jika task hanya menyangkut bagian tertentu
- menjalankan command yang tidak berhubungan dengan task
- menggunakan command untuk menebak struktur atau isi code

## Command Harus Sesuai Case

Gunakan command berdasarkan kebutuhan.

Contoh:

### Membutuhkan pencarian code

Boleh menggunakan command pencarian jika lokasi penggunaan
atau implementasi belum diketahui.

### Membutuhkan perubahan dependency

Boleh menggunakan package manager jika task memang meminta
perubahan dependency.

### Membutuhkan verifikasi logic

Boleh menjalankan test yang relevan dengan code yang diubah.

### Membutuhkan verifikasi build

Boleh menjalankan build jika perubahan berpotensi memengaruhi
proses build atau user memang meminta verifikasi build.

### Perubahan sederhana pada source code

Jika file dan lokasi code sudah diketahui, jangan menjalankan
command tambahan yang tidak diperlukan.

## Scope Command

Command harus memiliki scope sekecil mungkin.

Prioritaskan:

- file yang relevan
- folder yang relevan
- test yang relevan
- command yang spesifik

Hindari operasi terhadap seluruh project jika tidak diperlukan.

## Jika Ragu

Jika belum yakin apakah sebuah command diperlukan:

1. Jangan langsung menjalankannya.
2. Baca source code yang relevan terlebih dahulu.
3. Tentukan kebutuhan sebenarnya.
4. Gunakan command hanya jika setelah inspeksi masih diperlukan.

## Setelah Command

Setelah menjalankan command, gunakan hasilnya.

Jangan menjalankan command tambahan hanya karena hasil sebelumnya
belum sesuai dengan asumsi.

Evaluasi kembali hasil command sebelum menentukan tindakan berikutnya.

## Prinsip Mutlak

Jangan melakukan:

COMMAND → COMMAND → COMMAND → baru memahami code.

Gunakan:

READ → UNDERSTAND → DECIDE → COMMAND.

Setiap command harus memiliki alasan yang dapat dijelaskan
dan harus berhubungan langsung dengan task yang sedang dikerjakan.

Jika command tidak diperlukan, jangan jalankan.