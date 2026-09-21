[Setup]
AppId={{FD1A81D4-54C9-4B31-AD6A-481F5A8D6392}
AppName=GBF POWER
AppVersion=0.5.3
AppPublisher=GBF Desktop (independent client)
DefaultDirName={localappdata}\Programs\GBFPower
DefaultGroupName=GBF POWER
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=release
OutputBaseFilename=GBFPower-Setup-0.5.3-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\GBFPower.exe
AppMutex=Local\GBFPowerDesktopApp
CloseApplications=yes
RestartApplications=no
DisableProgramGroupPage=yes

[Files]
Source: "dist\GBFPower\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\GBF POWER"; Filename: "{app}\GBFPower.exe"
Name: "{userdesktop}\GBF POWER"; Filename: "{app}\GBFPower.exe"; Tasks: desktopicon

[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"

[Run]
Filename: "{app}\GBFPower.exe"; Description: "Open GBF POWER"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\GBFPower.exe"; Parameters: "--uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveOwnedCertificateTrust"

[Code]
function InitializeUninstall(): Boolean;
begin
  Result := True;
  if CheckForMutexes('Local\GBFPowerDesktopApp') then begin
    MsgBox('Please stop acceleration and exit GBF POWER before uninstalling. Cached files and profiles will be kept.', mbInformation, MB_OK);
    Result := False;
  end;
end;
