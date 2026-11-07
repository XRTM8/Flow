#define MyAppName "FLOW by Otium"
#define MyAppVersion "2.4.3"
#define MyAppPublisher "Otium"
#define MyAppURL "https://github.com/XRTM8/Flow"
#define MyAppExeName "OtiumFlow.exe"

[Setup]
AppId={{8B5C061E-74A2-4BC2-9B7E-772A1461A9F4}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Otium\Flow
DisableProgramGroupPage=yes
OutputBaseFilename=OtiumFlow-v2.4.3-Setup-x64
OutputDir=..\dist
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=yes
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\target\release\otium-flow-app.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion
Source: "..\assets\fonts\OFL.txt"; DestDir: "{app}\licenses"; DestName: "NotoSansArabic-OFL.txt"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}\licenses"; DestName: "Flow-GPL.txt"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Flags: nowait runasoriginaluser; Check: IsFlowUpdate
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent; Check: not IsFlowUpdate

[UninstallDelete]
Type: files; Name: "{app}\.flow-installed"

[Code]
function IsFlowUpdate: Boolean;
var
  I: Integer;
  CloseRequested, RestartRequested: Boolean;
begin
  Result := False;
  CloseRequested := False;
  RestartRequested := False;
  for I := 1 to ParamCount do
  begin
    if CompareText(ParamStr(I), '/FLOWUPDATE=1') = 0 then
    begin
      Result := True;
      Exit;
    end;
    if CompareText(ParamStr(I), '/CLOSEAPPLICATIONS') = 0 then
      CloseRequested := True;
    if CompareText(ParamStr(I), '/RESTARTAPPLICATIONS') = 0 then
      RestartRequested := True;
  end;
  { Compatibility with the updater shipped before /FLOWUPDATE was available. }
  Result := WizardSilent and CloseRequested and RestartRequested;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    if not SaveStringToFile(ExpandConstant('{app}\.flow-installed'),
      'OtiumFlow.Installed|{8B5C061E-74A2-4BC2-9B7E-772A1461A9F4}}', False) then
      Log('The installation marker could not be saved; registry identity remains available.');
end;
