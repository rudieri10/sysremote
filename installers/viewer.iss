[Setup]
AppId={{B4E83033-1054-4D89-A690-4D59908F7B2C}
AppName=SysRemote Viewer
AppVersion=1.0
AppPublisher=Rudieri
DefaultDirName={autopf}\SysRemote Viewer
DefaultGroupName=SysRemote
OutputDir=Output
OutputBaseFilename=SysRemoteViewer_Setup
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkablealone

[Files]
Source: "..\target\release\viewer.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\SysRemote Viewer"; Filename: "{app}\viewer.exe"
Name: "{autodesktop}\SysRemote Viewer"; Filename: "{app}\viewer.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\viewer.exe"; Description: "{cm:LaunchProgram,SysRemote Viewer}"; Flags: nowait postinstall skipifsilent
