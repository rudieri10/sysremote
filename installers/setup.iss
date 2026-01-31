[Setup]
AppName=SysRemote
AppVersion=1.0
DefaultDirName={commonpf}\SysRemote
DefaultGroupName=SysRemote
OutputBaseFilename=SysRemoteSetup
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#SourcePath}\Output
PrivilegesRequired=admin
WizardStyle=modern
AppPublisher=SysRemote Project
AppPublisherURL=https://github.com/sysremote
AppSupportURL=https://github.com/sysremote/issues
AppUpdatesURL=https://github.com/sysremote/releases

[Components]
Name: "host"; Description: "Host (Servidor/Serviço)"; Flags: exclusive
Name: "viewer"; Description: "Viewer (Cliente)"; Flags: exclusive

[Files]
Source: "{#SourcePath}\..\target\release\host.exe"; DestDir: "{app}"; Flags: ignoreversion; Components: host
Source: "{#SourcePath}\..\target\release\viewer.exe"; DestDir: "{app}"; Flags: ignoreversion; Components: viewer

[Registry]
Root: HKCR; Subkey: "sysremote"; ValueType: string; ValueName: ""; ValueData: "URL:SysRemote Protocol"; Flags: uninsdeletekey; Components: viewer
Root: HKCR; Subkey: "sysremote"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Flags: uninsdeletekey; Components: viewer
Root: HKCR; Subkey: "sysremote\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\viewer.exe,0"; Components: viewer
Root: HKCR; Subkey: "sysremote\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\viewer.exe"" ""%1"""; Components: viewer

[Icons]
Name: "{group}\SysRemote Viewer"; Filename: "{app}\viewer.exe"; Components: viewer
Name: "{group}\SysRemote Host"; Filename: "{app}\host.exe"; Components: host
Name: "{group}\SysRemote Host Logs"; Filename: "{app}\host.exe"; Parameters: "--logs"; Components: host
Name: "{commondesktop}\SysRemote Viewer"; Filename: "{app}\viewer.exe"; Components: viewer
Name: "{commondesktop}\SysRemote Host"; Filename: "{app}\host.exe"; Components: host

[Run]
Filename: "{cmd}"; Parameters: "/C """"{sys}\sc.exe"""" stop SysRemoteHost >nul 2>nul & exit /b 0"""; Flags: runhidden; StatusMsg: "Parando serviço existente..."; Components: host
Filename: "{cmd}"; Parameters: "/C """"{sys}\sc.exe"""" delete SysRemoteHost >nul 2>nul & exit /b 0"""; Flags: runhidden; StatusMsg: "Removendo serviço antigo..."; Components: host
Filename: "{sys}\sc.exe"; Parameters: "create SysRemoteHost binPath= ""{app}\host.exe"" start= auto DisplayName= ""SysRemote Host Service"""; Flags: runhidden; StatusMsg: "Registrando serviço..."; Components: host
Filename: "{sys}\sc.exe"; Parameters: "description SysRemoteHost ""Serviço de acesso remoto SysRemote"""; Flags: runhidden; Components: host
Filename: "{sys}\sc.exe"; Parameters: "start SysRemoteHost"; Flags: runhidden; StatusMsg: "Iniciando serviço..."; Components: host
Filename: "{cmd}"; Parameters: "/C """"{sys}\netsh.exe"""" advfirewall firewall delete rule name=""SysRemote Host"" >nul 2>nul & """"{sys}\netsh.exe"""" advfirewall firewall add rule name=""SysRemote Host"" dir=in action=allow program=""""{app}\host.exe"""" enable=yes"""; Flags: runhidden; Components: host
Filename: "{cmd}"; Parameters: "/C """"{sys}\netsh.exe"""" advfirewall firewall delete rule name=""SysRemote Viewer"" >nul 2>nul & """"{sys}\netsh.exe"""" advfirewall firewall add rule name=""SysRemote Viewer"" dir=in action=allow program=""""{app}\viewer.exe"""" enable=yes"""; Flags: runhidden; Components: viewer
Filename: "{cmd}"; Parameters: "/C """"{sys}\netsh.exe"""" advfirewall firewall delete rule name=""SysRemote Port"" >nul 2>nul & """"{sys}\netsh.exe"""" advfirewall firewall add rule name=""SysRemote Port"" dir=in action=allow protocol=TCP localport=5599"""; Flags: runhidden; Components: host

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C """"{sys}\sc.exe"""" stop SysRemoteHost >nul 2>nul & exit /b 0"""; Flags: runhidden; RunOnceId: "sysremote_stop_service"
Filename: "{cmd}"; Parameters: "/C """"{sys}\sc.exe"""" delete SysRemoteHost >nul 2>nul & exit /b 0"""; Flags: runhidden; RunOnceId: "sysremote_delete_service"
Filename: "{cmd}"; Parameters: "/C """"{sys}\netsh.exe"""" advfirewall firewall delete rule name=""SysRemote Host"" >nul 2>nul & exit /b 0"""; Flags: runhidden; RunOnceId: "sysremote_fw_host"
Filename: "{cmd}"; Parameters: "/C """"{sys}\netsh.exe"""" advfirewall firewall delete rule name=""SysRemote Viewer"" >nul 2>nul & exit /b 0"""; Flags: runhidden; RunOnceId: "sysremote_fw_viewer"
Filename: "{cmd}"; Parameters: "/C """"{sys}\netsh.exe"""" advfirewall firewall delete rule name=""SysRemote Port"" >nul 2>nul & exit /b 0"""; Flags: runhidden; RunOnceId: "sysremote_fw_port"
