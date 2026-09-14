[Setup]
AppId={{322966B3-4303-4AAD-A4C8-267DBB16B5D0}
AppName=GBF POWER Admin
AppVersion=0.1.2
AppPublisher=GBF independent tools
DefaultDirName={localappdata}\Programs\GBFPowerAdmin
DefaultGroupName=GBF POWER Admin
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=release
OutputBaseFilename=GBFPower-Admin-Setup-0.1.2-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
CloseApplications=yes
RestartApplications=no

[Files]
Source: "dist\GBFPowerAdmin\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\GBF POWER Admin"; Filename: "{app}\GBFPowerAdmin.exe"

[Run]
Filename: "{app}\GBFPowerAdmin.exe"; Description: "Open GBF POWER Admin"; Flags: nowait postinstall skipifsilent
