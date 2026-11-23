@echo off
setlocal
echo ========================================================
echo   SecureShip Shift-Left DevSecOps Platform Installer
echo ========================================================
echo.

python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python was not found in your PATH.
    echo Please install Python 3.10+ from https://python.org and check "Add python.exe to PATH".
    pause
    exit /b 1
)

echo [*] Installing SecureShip Engine and CLI dependencies...
python -m pip install -e ./engine

if %ERRORLEVEL% EQU 0 (
    :: Dynamically find active Python Scripts directory and register bin and scripts into permanent User PATH
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$bin = '%~dp0bin'; $pyScripts = (python -c 'import sysconfig; print(sysconfig.get_path(''scripts''))' 2>$null); $userPath = [Environment]::GetEnvironmentVariable('Path', 'User'); $toAdd = @($bin, $pyScripts) | Where-Object { $_ -and ($userPath -notlike ('*' + $_ + '*')) }; if ($toAdd) { $newPath = (($toAdd -join ';') + ';' + $userPath).Trim(';'); [Environment]::SetEnvironmentVariable('Path', $newPath, 'User') }" >nul 2>&1
    echo.
    echo ========================================================
    echo   [OK] SecureShip installed and registered in PATH!
    echo ========================================================
    echo.
    echo Quick Start Commands:
    echo   1. Scan current folder:       secureship scan
    echo   2. Scan specific project:     secureship scan "C:\path\to\project"
    echo   3. Launch Web Dashboard:      secureship serve --port 8787
    echo   4. Install Pre-commit Hook:   secureship install-hook
    echo.
    echo Optional VS Code Extension:
    echo   In VS Code, press Ctrl+Shift+P -^> "Install from VSIX..."
    echo   and select secureship-vscode-1.0.0.vsix
    echo.
) else (
    echo.
    echo [ERROR] Installation failed. Please check pip output above.
)
pause
