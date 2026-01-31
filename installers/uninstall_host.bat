@echo off
setlocal EnableExtensions EnableDelayedExpansion

title SysRemote Host - Desinstalar

set "SELF=%~f0"
set "LOG_FILE=%TEMP%\sysremote_uninstall_host.log"

> "%LOG_FILE%" echo [%date% %time%] START "%SELF%"
>>"%LOG_FILE%" echo User: %username%
>>"%LOG_FILE%" echo Computer: %computername%
>>"%LOG_FILE%" echo.

if /I "%~1"=="--elevated" goto :elevated

fltmc >nul 2>&1
if %errorlevel% neq 0 (
  >>"%LOG_FILE%" echo [%date% %time%] Requesting elevation...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:ComSpec -ArgumentList '/c','\"\"%SELF%\"\" --elevated' -Verb RunAs -WindowStyle Normal"
  exit /b 0
)

:elevated

set "SERVICE_NAME=SysRemoteHost"

set "APP_DIR=%CommonProgramFiles%\SysRemote"
if not exist "%APP_DIR%\host.exe" (
  if exist "%CommonProgramFiles(x86)%\SysRemote\host.exe" set "APP_DIR=%CommonProgramFiles(x86)%\SysRemote"
)

echo ========================================================
echo Removendo SysRemote Host
echo ========================================================
echo.
echo Pasta detectada: "%APP_DIR%"
echo.
echo Log: "%LOG_FILE%"
echo.

>>"%LOG_FILE%" echo [%date% %time%] APP_DIR="%APP_DIR%"

set "UNINS_EXE=%APP_DIR%\unins000.exe"
if exist "%UNINS_EXE%" (
  echo Rodando desinstalador: "%UNINS_EXE%"
  >>"%LOG_FILE%" echo [%date% %time%] Running uninstaller "%UNINS_EXE%"
  start /wait "" "%UNINS_EXE%" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
)

echo Parando/removendo servico...
>>"%LOG_FILE%" echo [%date% %time%] Stopping/deleting service "%SERVICE_NAME%"
sc stop "%SERVICE_NAME%" >nul 2>nul
sc delete "%SERVICE_NAME%" >nul 2>nul

echo Encerrando processos...
>>"%LOG_FILE%" echo [%date% %time%] Killing host.exe
taskkill /F /IM host.exe >nul 2>nul

echo Removendo regras de firewall...
>>"%LOG_FILE%" echo [%date% %time%] Removing firewall rules
netsh advfirewall firewall delete rule name="SysRemote Host" >nul 2>nul
netsh advfirewall firewall delete rule name="SysRemote Port" >nul 2>nul

echo Apagando pastas...
>>"%LOG_FILE%" echo [%date% %time%] Removing folders
rmdir /S /Q "%APP_DIR%" >nul 2>nul

rmdir /S /Q "%ProgramData%\SysRemote" >nul 2>nul

echo Removendo atalhos...
>>"%LOG_FILE%" echo [%date% %time%] Removing shortcuts
del /F /Q "%Public%\Desktop\SysRemote Host.lnk" >nul 2>nul
del /F /Q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\SysRemote\SysRemote Host.lnk" >nul 2>nul
del /F /Q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\SysRemote\SysRemote Host Logs.lnk" >nul 2>nul

for /f "delims=" %%D in ('dir /ad /b "%ProgramData%\Microsoft\Windows\Start Menu\Programs\SysRemote" 2^>nul') do set "HAS_GROUP_ITEMS=1"
if not defined HAS_GROUP_ITEMS (
  rmdir /S /Q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\SysRemote" >nul 2>nul
)

echo.
echo OK
>>"%LOG_FILE%" echo [%date% %time%] OK
pause
exit /b 0
