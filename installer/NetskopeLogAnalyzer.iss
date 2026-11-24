; Netskope Log Analyzer - Inno Setup 6
; Compilado por build.ps1:  ISCC /DAppVersion=x.y.z /DSourceDir=<pasta do app> /DOutDir=<dist> NetskopeLogAnalyzer.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\build\app"
#endif
#ifndef OutDir
  #define OutDir "..\dist"
#endif
#define AppName "Netskope Log Analyzer"

[Setup]
AppId={{6F1C9A52-3B7E-4D21-9A8E-2C5B7D104E33}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Suporte de TI
AppPublisherURL=https://github.com/rcalcic/netskope-log-analyzer
DefaultDirName={localappdata}\Programs\NetskopeLogAnalyzer
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutDir}
OutputBaseFilename=NetskopeLogAnalyzer-{#AppVersion}-Setup
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\app.ico
UninstallDisplayName={#AppName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
MinVersion=10.0

[Languages]
Name: "ptbr"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Abre em janela propria (modo aplicativo do Edge). Sem Edge, abre no navegador padrao.
Name: "{autoprograms}\{#AppName}"; Filename: "{code:EdgePath}"; Parameters: "--app=""{code:AppUrl}"" --window-size=1360,900"; IconFilename: "{app}\app.ico"; Check: HasEdge
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\index.html"; IconFilename: "{app}\app.ico"; Check: not HasEdge
Name: "{autodesktop}\{#AppName}"; Filename: "{code:EdgePath}"; Parameters: "--app=""{code:AppUrl}"" --window-size=1360,900"; IconFilename: "{app}\app.ico"; Tasks: desktopicon; Check: HasEdge
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\index.html"; IconFilename: "{app}\app.ico"; Tasks: desktopicon; Check: not HasEdge

[Run]
Filename: "{code:EdgePath}"; Parameters: "--app=""{code:AppUrl}"" --window-size=1360,900"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent; Check: HasEdge
Filename: "{app}\index.html"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent shellexec; Check: not HasEdge

[Code]
function EdgePath(Param: String): String;
begin
  Result := ExpandConstant('{commonpf32}\Microsoft\Edge\Application\msedge.exe');
  if (not FileExists(Result)) and IsWin64 then
    Result := ExpandConstant('{commonpf64}\Microsoft\Edge\Application\msedge.exe');
end;

function HasEdge: Boolean;
begin
  Result := FileExists(EdgePath(''));
end;

function AppUrl(Param: String): String;
begin
  Result := ExpandConstant('{app}') + '\index.html';
  StringChangeEx(Result, '\', '/', True);
  StringChangeEx(Result, ' ', '%20', True);
  Result := 'file:///' + Result;
end;
