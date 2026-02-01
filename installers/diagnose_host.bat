@echo off
setlocal EnableExtensions EnableDelayedExpansion
title SysRemote Host Diagnostics

set "SELF=%~f0"
set "LOG_FILE=%~dp0sysremote_host_diag.log"

> "%LOG_FILE%" echo [%date% %time%] START "%SELF%"
>>"%LOG_FILE%" echo User: %username%
>>"%LOG_FILE%" echo Computer: %computername%
>>"%LOG_FILE%" echo.

if /I "%~1"=="--elevated" goto elevated

fltmc >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:ComSpec -ArgumentList '/c','\"\"%SELF%\"\" --elevated' -Verb RunAs -WindowStyle Normal"
  exit /b 0
)

:elevated

echo ========================================================
echo SysRemote Host Diagnostics
echo ========================================================
echo.
echo Log: "%LOG_FILE%"
echo.

>>"%LOG_FILE%" echo [Profiles]
netsh advfirewall show allprofiles >> "%LOG_FILE%"

>>"%LOG_FILE%" echo.
>>"%LOG_FILE%" echo [Firewall Rules - Program]
netsh advfirewall firewall show rule name="SysRemote Host" verbose >> "%LOG_FILE%"
netsh advfirewall firewall show rule name="SysRemote Viewer" verbose >> "%LOG_FILE%"

>>"%LOG_FILE%" echo.
>>"%LOG_FILE%" echo [Firewall Rules - Port]
netsh advfirewall firewall show rule name="SysRemote Port" verbose >> "%LOG_FILE%"

>>"%LOG_FILE%" echo.
>>"%LOG_FILE%" echo [Service Status]
sc query SysRemoteHost >> "%LOG_FILE%"

>>"%LOG_FILE%" echo.
>>"%LOG_FILE%" echo [Listening Port 5599]
netstat -ano | findstr /R /C:":5599 .*LISTENING" >> "%LOG_FILE%"

>>"%LOG_FILE%" echo.
>>"%LOG_FILE%" echo [Outbound Test - Discovery 192.168.1.238:5600]
powershell -NoProfile -ExecutionPolicy Bypass -Command "$h='192.168.1.238';$p=5600;$c=New-Object Net.Sockets.TcpClient;$c.SendTimeout=2000;$c.ReceiveTimeout=2000;try{$c.Connect($h,$p);Write-Output 'DISCOVERY=OK'}catch{Write-Output ('DISCOVERY=FAILED ' + $_.Exception.Message)}finally{$c.Close()}" >> "%LOG_FILE%"

>>"%LOG_FILE%" echo.
>>"%LOG_FILE%" echo [Local Test - 127.0.0.1:5599]
powershell -NoProfile -ExecutionPolicy Bypass -Command "$h='127.0.0.1';$p=5599;$c=New-Object Net.Sockets.TcpClient;$c.SendTimeout=2000;$c.ReceiveTimeout=2000;try{$c.Connect($h,$p);Write-Output 'LOCAL5599=OK'}catch{Write-Output ('LOCAL5599=FAILED ' + $_.Exception.Message)}finally{$c.Close()}" >> "%LOG_FILE%"

for /f "usebackq tokens=* delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$ip=(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne '127.0.0.1'} | Select-Object -First 1 -ExpandProperty IPAddress); Write-Output $ip"`) do set "LANIP=%%I"

>>"%LOG_FILE%" echo.
>>"%LOG_FILE%" echo [LAN Test - %LANIP%:5599]
powershell -NoProfile -ExecutionPolicy Bypass -Command "$h=$env:LANIP;$p=5599;$c=New-Object Net.Sockets.TcpClient;$c.SendTimeout=2000;$c.ReceiveTimeout=2000;try{$c.Connect($h,$p);Write-Output ('LAN5599=OK ' + $h)}catch{Write-Output ('LAN5599=FAILED ' + $h + ' ' + $_.Exception.Message)}finally{$c.Close()}" >> "%LOG_FILE%"

>>"%LOG_FILE%" echo.
>>"%LOG_FILE%" echo [Firewall Global]
netsh advfirewall show global >> "%LOG_FILE%"

>>"%LOG_FILE%" echo.
>>"%LOG_FILE%" echo [Policy Keys]
reg query "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall" /s >> "%LOG_FILE%" 2>nul

echo ========================================================
echo Completed
echo ========================================================
echo.
echo Log: "%LOG_FILE%"
exit /b 0
