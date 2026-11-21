# SecureShip Environment & Path Setup for Windows PowerShell
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  SecureShip DevSecOps Platform - Environment Setup" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$binDir = Join-Path $scriptDir "bin"

# Dynamically discover active Python Scripts directory
$pyScriptsDir = $null
try {
    $pyScriptsDir = (python -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null).Trim()
} catch {}
if (-not $pyScriptsDir) {
    $pyScriptsDir = "$env:USERPROFILE\Python311\Scripts"
}

Write-Host "[*] Adding SecureShip to current PowerShell session PATH..." -ForegroundColor Yellow
$env:Path = "$binDir;$pyScriptsDir;$env:Path"

Write-Host "[*] Registering SecureShip into permanent User PATH environment variables..." -ForegroundColor Yellow
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$toAdd = @($binDir, $pyScriptsDir) | Where-Object { $_ -and ($userPath -notlike "*$_*") }

if ($toAdd) {
    $newUserPath = (($toAdd -join ";") + ";" + $userPath).Trim(";")
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
    Write-Host "[OK] Added to User PATH permanently." -ForegroundColor Green
} else {
    Write-Host "[OK] Already registered in User PATH." -ForegroundColor Green
}

# Ensure engine is installed in editable mode
$pyExe = "$env:USERPROFILE\Python311\python.exe"
if (-not (Test-Path $pyExe)) {
    $pyExe = "python"
}

Write-Host "[*] Ensuring engine dependencies are installed..." -ForegroundColor Yellow
& $pyExe -m pip install -e "$scriptDir\engine" --quiet

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  [OK] SecureShip CLI is ready to use!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Try running:" -ForegroundColor White
Write-Host "  secureship --help" -ForegroundColor Cyan
Write-Host "  secureship scan demo-vulnerable-app" -ForegroundColor Cyan
Write-Host "  secureship scan demo-vulnerable-app --modify-score 65" -ForegroundColor Cyan
Write-Host "  secureship scan demo-vulnerable-app --strict-sca" -ForegroundColor Cyan
Write-Host ""
