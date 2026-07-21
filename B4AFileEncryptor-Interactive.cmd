@echo off
set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%powershell-tool\B4AFileEncryptor-Interactive.ps1"

if not exist "%PS_SCRIPT%" (
    echo Erro: B4AFileEncryptor-Interactive.ps1 nao encontrado em %PS_SCRIPT%
    pause
    exit /b 1
)

start "B4A File Encryptor" powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"
