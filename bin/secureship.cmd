@echo off
setlocal
set "SCRIPT_DIR=%~dp0.."
if exist "%SCRIPT_DIR%\engine" (
    set "PYTHONPATH=%SCRIPT_DIR%\engine;%PYTHONPATH%"
)

:: 1. Try python in active PATH
python.exe -m secureship %*
if %ERRORLEVEL% EQU 0 exit /b 0

:: 2. Try standard local Python paths
if exist "%USERPROFILE%\Python311\python.exe" (
    "%USERPROFILE%\Python311\python.exe" -m secureship %*
    exit /b %ERRORLEVEL%
)

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" -m secureship %*
    exit /b %ERRORLEVEL%
)

:: 3. Try py launcher
where py.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py.exe -3 -m secureship %*
    exit /b %ERRORLEVEL%
)

:: 4. Fallback
python.exe -m secureship %*
exit /b %ERRORLEVEL%
