# Skil AI - Rules Builder Script
# Cara pakai: .\build-rules.ps1 -SourceFolder "D:\Project\MyApp\rules" -OutputFile "D:\Project\MyApp\.clinerules"
# Script ini akan menggabungkan semua file .md di folder source menjadi 1 file .clinerules

param(
    [Parameter(Mandatory=$true)]
    [string]$SourceFolder,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = ".clinerules"
)

# Cek apakah folder source ada
if (-not (Test-Path $SourceFolder)) {
    Write-Host "❌ Folder sumber tidak ditemukan: $SourceFolder" -ForegroundColor Red
    exit 1
}

# Jika OutputFile tidak ada path absolutnya, taruh di parent directory dari SourceFolder
if (-not [System.IO.Path]::IsPathRooted($OutputFile)) {
    $parentDir = (Get-Item $SourceFolder).Parent.FullName
    $OutputFile = Join-Path $parentDir $OutputFile
}

Write-Host "🔄 Menggabungkan rules dari: $SourceFolder" -ForegroundColor Cyan
Write-Host "📦 File tujuan: $OutputFile" -ForegroundColor Cyan

# Ambil semua file .md di folder source
$mdFiles = Get-ChildItem -Path $SourceFolder -Filter "*.md" | Sort-Object Name

if ($mdFiles.Count -eq 0) {
    Write-Host "⚠️ Tidak ada file .md ditemukan di folder $SourceFolder" -ForegroundColor Yellow
    exit 0
}

# Siapkan konten awal
$finalContent = @"
# ==============================================================================
# 🧠 SKIL AI - MASTER RULES (AUTO-GENERATED)
# ==============================================================================
# File ini di-generate otomatis dari penggabungan beberapa file rules modular.
# JANGAN edit file ini langsung jika kamu menggunakan sistem modular.
# Tanggal Generate: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# ==============================================================================

"@

# Loop setiap file .md dan gabungkan isinya
foreach ($file in $mdFiles) {
    Write-Host "  -> Menambahkan: $($file.Name)" -ForegroundColor White
    
    $fileContent = Get-Content -Path $file.FullName -Raw
    
    $finalContent += "`n# ------------------------------------------------------------------------------`n"
    $finalContent += "# 📁 SUMBER: $($file.Name)`n"
    $finalContent += "# ------------------------------------------------------------------------------`n`n"
    $finalContent += $fileContent
    $finalContent += "`n`n"
}

# Tulis ke file output (gunakan UTF8 agar emoji/karakter khusus aman)
Set-Content -Path $OutputFile -Value $finalContent -Encoding UTF8

Write-Host "`n✅ Selesai! $($mdFiles.Count) file berhasil digabungkan menjadi 1 master rule." -ForegroundColor Green
Write-Host "📂 Hasil: $OutputFile" -ForegroundColor Green
