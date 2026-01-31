@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem SysRemote Host - Desinstalacao completa (Servico + Firewall + Arquivos)

>nul 2>&1 net session
if %errorlevel% neq 0 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo [SysRemote Host] Parando processos...
taskkill /f /im host.exe >nul 2>&1

echo [SysRemote Host] Parando e removendo servico...
sc stop SysRemoteHost >nul 2>&1
sc delete SysRemoteHost >nul 2>&1

echo [SysRemote Host] Removendo regras de firewall...
netsh advfirewall firewall delete rule name="SysRemote Host" >nul 2>&1
netsh advfirewall firewall delete rule name="SysRemote Port" >nul 2>&1
netsh advfirewall firewall delete rule program="%ProgramFiles%\SysRemote\host.exe" >nul 2>&1
netsh advfirewall firewall delete rule program="%ProgramFiles(x86)%\SysRemote\host.exe" >nul 2>&1

echo [SysRemote Host] Tentando executar desinstalador (se existir)...
set "UNINS="
if exist "%ProgramFiles%\SysRemote\unins000.exe" set "UNINS=%ProgramFiles%\SysRemote\unins000.exe"
if not defined UNINS if exist "%ProgramFiles(x86)%\SysRemote\unins000.exe" set "UNINS=%ProgramFiles(x86)%\SysRemote\unins000.exe"
if defined UNINS (
  "%UNINS%" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART >nul 2>&1
)

echo [SysRemote Host] Removendo pasta de instalacao...
if exist "%ProgramFiles%\SysRemote" rmdir /s /q "%ProgramFiles%\SysRemote" >nul 2>&1
if exist "%ProgramFiles(x86)%\SysRemote" rmdir /s /q "%ProgramFiles(x86)%\SysRemote" >nul 2>&1

echo [SysRemote Host] Limpando chaves de servico remanescentes (se houver)...
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SysRemoteHost" /f >nul 2>&1

echo [SysRemote Host] Concluido.
exit /b 0
