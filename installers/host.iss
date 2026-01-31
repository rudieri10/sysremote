[Setup]
AppId={{A3D72922-0943-4C78-958F-3C48897E6A1B}
AppName=SysRemote Host
AppVersion=1.0
AppPublisher=Rudieri
DefaultDirName={autopf}\SysRemote Host
DefaultGroupName=SysRemote
OutputDir=Output
OutputBaseFilename=SysRemoteHost_Setup
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\target\release\host.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\SysRemote Host"; Filename: "{app}\host.exe"
Name: "{autodesktop}\SysRemote Host"; Filename: "{app}\host.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\host.exe"; Description: "{cm:LaunchProgram,SysRemote Host}"; Flags: nowait postinstall skipifsilent
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""SysRemote Host"" dir=in action=allow program=""{app}\host.exe"" enable=yes"; Flags: runhidden; StatusMsg: "Adicionando exceção ao Firewall..."

[UninstallRun]
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""SysRemote Host"" program=""{app}\host.exe"""; Flags: runhidden
