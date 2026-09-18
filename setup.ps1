# Skil AI - Setup Script
# Cara pakai: .\setup.ps1 -ProjectPath "D:\Project\MyApp"
# Script ini akan copy rules ke project tujuan

param(
    [Parameter(Mandatory=$true)]
    [string]$ProjectPath,

    [Parameter(Mandatory=$false)]
    [ValidateSet("cline", "opencode", "both")]
    [string]$Tool = "both"
)

$SkilAIPath = $PSScriptRoot
$RulesPath = Join-Path $SkilAIPath "rules"

# Cek apakah folder project ada
if (-not (Test-Path $ProjectPath)) {
    Write-Host "❌ Folder project tidak ditemukan: $ProjectPath" -ForegroundColor Red
    Write-Host "   Pastikan path-nya benar." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "🧠 Skil AI - Setup Script" -ForegroundColor Cyan
Write-Host "   Project: $ProjectPath" -ForegroundColor White
Write-Host "   Tool   : $Tool" -ForegroundColor White
Write-Host ""

# Setup untuk Cline
if ($Tool -eq "cline" -or $Tool -eq "both") {
    $source = Join-Path $RulesPath ".clinerules"
    $dest = Join-Path $ProjectPath ".clinerules"
    
    if (Test-Path $source) {
        Copy-Item $source -Destination $dest -Force
        Write-Host "✅ Cline rules berhasil di-copy ke: $dest" -ForegroundColor Green
    } else {
        Write-Host "❌ File .clinerules tidak ditemukan di: $source" -ForegroundColor Red
    }
}

# Setup untuk OpenCode
if ($Tool -eq "opencode" -or $Tool -eq "both") {
    $source = Join-Path $RulesPath "opencode-rules.md"
    $dest = Join-Path $ProjectPath "AGENTS.md"
    
    if (Test-Path $source) {
        Copy-Item $source -Destination $dest -Force
        Write-Host "✅ OpenCode rules berhasil di-copy ke: $dest" -ForegroundColor Green
    } else {
        Write-Host "❌ File opencode-rules.md tidak ditemukan di: $source" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "🎉 Setup selesai! AI kamu sekarang lebih nurut dan profesional." -ForegroundColor Cyan
Write-Host ""
