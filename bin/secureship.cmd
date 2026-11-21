@echo off
setlocal
set "SCRIPT_DIR=%~dp0.."
if exist "%SCRIPT_DIR%\engine" (
    set "PYTHONPATH=%SCRIPT_DIR%\engine;%PYTHONPATH%"
)

set "PY_EXE="
where python.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PY_EXE=python.exe"
    goto :run
)

if exist "%USERPROFILE%\Python311\python.exe" (
    set "PY_EXE=%USERPROFILE%\Python311\python.exe"
    goto :run
)

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    goto :run
)

where py.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py.exe -3 -m secureship %*
    exit /b %ERRORLEVEL%
)

set "PY_EXE=python.exe"

:run
"%PY_EXE%" -m secureship %*
exit /b %ERRORLEVEL%
