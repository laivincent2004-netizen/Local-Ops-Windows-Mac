#ifndef AppVersion
  #error AppVersion must be supplied with /DAppVersion=x.y.z
#endif
#ifndef SourceDir
  #error SourceDir must be supplied with /DSourceDir=path
#endif
#ifndef OutputDir
  #define OutputDir "."
#endif
#ifndef LanguageDir
  #error LanguageDir must be supplied with /DLanguageDir=path
#endif

#define AppName "总控台"
#define AppPublisher "laogou717"
#define AppExeName "总控台.exe"
#define AppId "{{68A9A070-1728-4681-9190-E1C6027A17D9}"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL=https://github.com/laivincent2004-netizen/Local-Ops-Windows-Mac
AppSupportURL=https://github.com/laivincent2004-netizen/Local-Ops-Windows-Mac/issues
AppUpdatesURL=https://github.com/laivincent2004-netizen/Local-Ops-Windows-Mac/releases
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
OutputDir={#OutputDir}
OutputBaseFilename=local-ops-{#AppVersion}-windows-x64-setup
SetupIconFile={#SourceDir}\_internal\static\assets\favicon.ico
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
MinVersion=10.0.19045
CloseApplications=yes
RestartApplications=no
CloseApplicationsFilter={#AppExeName}
AppMutex=Local\LocalOpsTrayInstallerGuard
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Windows x64 installer
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
ChangesAssociations=no
ChangesEnvironment=no
LicenseFile={#SourceDir}\_internal\LICENSE
InfoBeforeFile={#SourceDir}\UNSIGNED_BUILD_NOTICE.txt

[Languages]
Name: "chinesesimplified"; MessagesFile: "{#LanguageDir}\ChineseSimplified.isl"

[Tasks]
Name: "startup"; Description: "登录 Windows 后启动托盘"; GroupDescription: "启动选项："; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{userstartup}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Parameters: "--background"; WorkingDir: "{app}"; Tasks: startup

[Run]
Filename: "{app}\{#AppExeName}"; Description: "启动 {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; User data intentionally remains in {localappdata}\总控台 after uninstall.
Type: filesandordirs; Name: "{app}"

[Code]
const
  InstallerMutex = 'Local\LocalOpsTrayInstallerGuard';
  UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{68A9A070-1728-4681-9190-E1C6027A17D9}_is1';

function InstalledAppExe(): String;
var
  InstallLocation: String;
begin
  Result := ExpandConstant('{localappdata}\Programs\{#AppName}\{#AppExeName}');
  if RegQueryStringValue(HKCU, UninstallKey, 'InstallLocation',
                         InstallLocation) and (InstallLocation <> '') then
    Result := AddBackslash(InstallLocation) + '{#AppExeName}';
end;

function RequestTrayExit(AppExe: String): Boolean;
var
  ExitCode: Integer;
  Attempts: Integer;
begin
  Result := not CheckForMutexes(InstallerMutex);
  if Result or not FileExists(AppExe) then
    exit;
  if not Exec(AppExe, '--quit', ExtractFileDir(AppExe), SW_HIDE,
              ewWaitUntilTerminated, ExitCode) then
    exit;
  for Attempts := 1 to 300 do
  begin
    if not CheckForMutexes(InstallerMutex) then
    begin
      Result := True;
      exit;
    end;
    Sleep(100);
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := IsWin64;
  if not Result then
  begin
    MsgBox('总控台仅支持 Windows 10/11 x64。', mbError, MB_OK);
    exit;
  end;
  { InitializeSetup runs before Setup's AppMutex check.  Ask the existing
    per-user tray to stop gracefully; AppMutex remains the safe fallback if it
    cannot be reached or does not exit before the bounded wait. }
  if CheckForMutexes(InstallerMutex) and
     not RequestTrayExit(InstalledAppExe()) then
    Log('Existing tray did not exit before the Setup AppMutex check.');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usAppMutexCheck) and
     CheckForMutexes(InstallerMutex) and
     not RequestTrayExit(ExpandConstant('{app}\{#AppExeName}')) then
    Log('Existing tray did not exit before the Uninstall AppMutex check.');
end;
