$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$parentDir = Split-Path -Parent $scriptDir
$engineDir = Join-Path $parentDir "engine"
if (Test-Path $engineDir) {
    $env:PYTHONPATH = "$engineDir;$env:PYTHONPATH"
}

$pythonExe = $null
$candidates = @(
    "$env:USERPROFILE\Python311\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
    "C:\Python311\python.exe",
    "C:\Python312\python.exe"
)

foreach ($c in $candidates) {
    if (Test-Path $c) {
        $pythonExe = $c
        break
    }
}

if (-not $pythonExe) {
    $cmd = Get-Command "python" -ErrorAction SilentlyContinue
    if ($cmd) {
        $pythonExe = $cmd.Source
    }
}

if (-not $pythonExe) {
    $pythonExe = "python.exe"
}

& $pythonExe -m secureship $args
exit $LASTEXITCODE
