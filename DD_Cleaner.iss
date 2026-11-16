; DD Cleaner installer (Inno Setup).
;
; Installs to {autopf}\DD Cleaner, which Inno Setup resolves to C:\Program Files\DD Cleaner on 64-bit
; Windows: only administrators can write there. This matters here specifically, not just by convention:
; DD Cleaner runs elevated and checks its own folder at every start (ddcleaner.folder_security.folder_risk),
; refusing to continue if a standard user could plant a DLL or swap a file in it. Installing anywhere else
; (Desktop, Downloads, a user-writable folder) would make the program warn and ask to be moved, so the
; installer never offers another location (no "DisableDirPage"/custom dir UI).
;
; PrivilegesRequired=admin: both because the target folder needs admin rights to write to, and because every
; run of DD Cleaner itself asks for elevation (UAC) anyway (see DD_Cleaner.spec, uac_admin=True) - the
; installer asking first is one UAC prompt instead of a confusing silent failure partway through.
;
; Build order: PyInstaller (DD_Cleaner.spec) must have produced dist\DD_Cleaner\ before compiling this
; script - see Build.bat.

#define MyAppName "DD Cleaner"
#define MyAppVersion "3.0"
#define MyAppPublisher "Benoit (BSM) Saint-Moulin"
#define MyAppExeName "DD_Cleaner.exe"
#define MySourceDir "dist\DD_Cleaner"

[Setup]
AppId={{8E6D6F2B-6C8E-4A6E-9A3C-5B6F1C2D8E4A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableWelcomePage=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=dist_installer
OutputBaseFilename=DD_Cleaner_Setup_{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=ddcleaner\data\dd_cleaner.ico
; The portable build is already compressed internally (PyInstaller's own zlib); recompressing it in the
; installer is still worth it for the download size, just don't expect PyInstaller-archive-sized ratios.
LZMAUseSeparateProcess=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
; The whole portable folder, as-is: DD_Cleaner.exe plus its _internal\ runtime. Nothing is modified or
; renamed, so a side-by-side portable copy (USB key, another PC) stays usable and identical to this one.
Source: "{#MySourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; DD Cleaner never writes inside its own install folder at runtime (settings/logs/backups live in the
; protected C:\ProgramData\DD Cleaner, see ddcleaner.common.data_dir and README section 7) - this just
; catches stray *.pyc/__pycache__ that a from-source debug run could have left here, never real app data.
Type: filesandordirs; Name: "{app}\__pycache__"

[Code]
// DD Cleaner has no named mutex to check with CheckForMutexes (it was never built as single-instance), so
// "is it running" is answered the only way that works without changing the app itself: ask tasklist.
function IsAppRunning(): Boolean;
var
  ResultCode: Integer;
  TmpFile: String;
  Output: AnsiString;
begin
  TmpFile := ExpandConstant('{tmp}\tasklist.txt');
  // tasklist has no simple "exit code means found", so redirect its output and look for the exe name in it
  Exec(ExpandConstant('{cmd}'), '/C tasklist /FI "IMAGENAME eq {#MyAppExeName}" /NH > "' + TmpFile + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := False;
  if LoadStringFromFile(TmpFile, Output) then
    Result := Pos('{#MyAppExeName}', Output) > 0;
  DeleteFile(TmpFile);
end;

// Refuse to continue (install or uninstall) while DD Cleaner is open: it keeps its log file open for
// writing, and replacing a running .exe's own folder can leave a half-updated install.
function ConfirmCloseIfRunning(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  if IsAppRunning() then
  begin
    if MsgBox('DD Cleaner is currently running. Close it now to continue?' + #13#10 +
              'Click Yes to close it, or No to cancel.', mbConfirmation, MB_YESNO) = IDYES then
    begin
      Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM {#MyAppExeName} /F', '', SW_HIDE,
          ewWaitUntilTerminated, ResultCode);
      Sleep(500); // let the file handles (log, settings) actually release before Files/UninstallDelete run
    end
    else
      Result := False;
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := ConfirmCloseIfRunning();
end;

function InitializeUninstall(): Boolean;
begin
  Result := ConfirmCloseIfRunning();
end;
