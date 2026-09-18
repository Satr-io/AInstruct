param(
    [Parameter(Mandatory=$true)]
    [string]$SourceFolder,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = ".clinerules"
)

if (-not (Test-Path $SourceFolder)) {
    Write-Host "Error: Source folder not found: $SourceFolder"
    exit 1
}

if (-not [System.IO.Path]::IsPathRooted($OutputFile)) {
    $parentDir = (Get-Item $SourceFolder).Parent.FullName
    $OutputFile = Join-Path $parentDir $OutputFile
}

Write-Host "Merging rules from: $SourceFolder"
Write-Host "Output file: $OutputFile"

$mdFiles = Get-ChildItem -Path $SourceFolder -Filter "*.md" | Sort-Object Name

if ($mdFiles.Count -eq 0) {
    Write-Host "Warning: No .md files found in $SourceFolder"
    exit 0
}

$finalContent = "# ==============================================================================
"
$finalContent += "# SKIL AI - MASTER RULES (AUTO-GENERATED)
"
$finalContent += "# ==============================================================================
"
$finalContent += "# Tanggal Generate: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"
$finalContent += "# ==============================================================================

"

foreach ($file in $mdFiles) {
    Write-Host "  -> Adding: $($file.Name)"
    $fileContent = Get-Content -Path $file.FullName -Raw -Encoding UTF8
    
    $finalContent += "
# ------------------------------------------------------------------------------
"
    $finalContent += "# SUMBER: $($file.Name)
"
    $finalContent += "# ------------------------------------------------------------------------------

"
    $finalContent += $fileContent
    $finalContent += "

"
}

if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }
Set-Content -Path $OutputFile -Value $finalContent -Encoding UTF8

Write-Host "Success! $($mdFiles.Count) files merged into 1 master rule."
Write-Host "Result: $OutputFile"
