[Setup]
AppName=SysRemote
AppVersion=1.0
DefaultDirName={commonpf}\SysRemote
DefaultGroupName=SysRemote
OutputBaseFilename=SysRemote_Setup
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

[Types]
Name: "full"; Description: "Instalação Completa (Host + Viewer)"
Name: "host"; Description: "Apenas Host (Servidor)"
Name: "viewer"; Description: "Apenas Viewer (Cliente)"
Name: "custom"; Description: "Personalizada"; Flags: iscustom

[Components]
Name: "host"; Description: "Host (Servidor/Serviço) - Permite acesso remoto a esta máquina"; Types: full host custom
Name: "viewer"; Description: "Viewer (Cliente) - Permite acessar outras máquinas"; Types: full viewer custom

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
; Parar serviço e firewall antes de instalar (se existir)
Filename: "{cmd}"; Parameters: "/C """"{sys}\sc.exe"""" stop SysRemoteHost >nul 2>nul & exit /b 0"""; Flags: runhidden; StatusMsg: "Parando serviço existente..."; Components: host
Filename: "{cmd}"; Parameters: "/C """"{sys}\sc.exe"""" delete SysRemoteHost >nul 2>nul & exit /b 0"""; Flags: runhidden; StatusMsg: "Removendo serviço antigo..."; Components: host

; Registrar serviço
Filename: "{sys}\sc.exe"; Parameters: "create SysRemoteHost binPath= ""{app}\host.exe"" start= auto DisplayName= ""SysRemote Host Service"""; Flags: runhidden; StatusMsg: "Registrando serviço..."; Components: host
Filename: "{sys}\sc.exe"; Parameters: "description SysRemoteHost ""Serviço de acesso remoto SysRemote"""; Flags: runhidden; Components: host
Filename: "{sys}\sc.exe"; Parameters: "start SysRemoteHost"; Flags: runhidden; StatusMsg: "Iniciando serviço..."; Components: host

; Firewall Host
Filename: "{cmd}"; Parameters: "/C """"{sys}\netsh.exe"""" advfirewall firewall delete rule name=""SysRemote Host"" >nul 2>nul & """"{sys}\netsh.exe"""" advfirewall firewall add rule name=""SysRemote Host"" dir=in action=allow program=""""{app}\host.exe"""" enable=yes"""; Flags: runhidden; Components: host
Filename: "{cmd}"; Parameters: "/C """"{sys}\netsh.exe"""" advfirewall firewall delete rule name=""SysRemote Port"" >nul 2>nul & """"{sys}\netsh.exe"""" advfirewall firewall add rule name=""SysRemote Port"" dir=in action=allow protocol=TCP localport=5599"""; Flags: runhidden; Components: host

; Firewall Viewer
Filename: "{cmd}"; Parameters: "/C """"{sys}\netsh.exe"""" advfirewall firewall delete rule name=""SysRemote Viewer"" >nul 2>nul & """"{sys}\netsh.exe"""" advfirewall firewall add rule name=""SysRemote Viewer"" dir=in action=allow program=""""{app}\viewer.exe"""" enable=yes"""; Flags: runhidden; Components: viewer

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C """"{sys}\sc.exe"""" stop SysRemoteHost >nul 2>nul & exit /b 0"""; Flags: runhidden; RunOnceId: "sysremote_stop_service"
Filename: "{cmd}"; Parameters: "/C """"{sys}\sc.exe"""" delete SysRemoteHost >nul 2>nul & exit /b 0"""; Flags: runhidden; RunOnceId: "sysremote_delete_service"
Filename: "{cmd}"; Parameters: "/C """"{sys}\netsh.exe"""" advfirewall firewall delete rule name=""SysRemote Host"" >nul 2>nul & exit /b 0"""; Flags: runhidden; RunOnceId: "sysremote_fw_host"
Filename: "{cmd}"; Parameters: "/C """"{sys}\netsh.exe"""" advfirewall firewall delete rule name=""SysRemote Viewer"" >nul 2>nul & exit /b 0"""; Flags: runhidden; RunOnceId: "sysremote_fw_viewer"
Filename: "{cmd}"; Parameters: "/C """"{sys}\netsh.exe"""" advfirewall firewall delete rule name=""SysRemote Port"" >nul 2>nul & exit /b 0"""; Flags: runhidden; RunOnceId: "sysremote_fw_port"
