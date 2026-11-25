; DD Cleaner
; © Benoit Saint-Moulin - 2026
; Version du fichier : 1.0.0
; Fonction du fichier : Inno Setup script that builds the DD Cleaner 1.0.0 installer for C:\Tools and asks before closing a running copy.

; Installeur Inno Setup de DD Cleaner 1.0.0 (version C++) : installe dans C:\Tools\DD Cleaner, dossier réservé en écriture aux administrateurs.
; L'installeur va dans D:\Documents\Coding\distributions\DD-Cleaner (BSM_DISTRIBUTIONS pour changer le dossier).
; Données dans %APPDATA%\BSM\DDCleaner : rien n'est écrit dans le dossier d'installation.

#define MyAppName "DD Cleaner 1.0.0"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Benoit (BSM) Saint-Moulin"
#define MyAppExeName "DD_Cleaner.exe"
#define MyBuildDir "build\release"
#define DistRoot GetEnv("BSM_DISTRIBUTIONS")
#if DistRoot == ""
  #define DistRoot "D:\Documents\Coding\distributions"
#endif

[Setup]
AppId={{3B7C5D1E-9A42-4F6B-8C0D-7E2A91F4B6C3}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={sd}\Tools\DD Cleaner
DisableDirPage=yes
UsePreviousAppDir=no
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#DistRoot}\DD-Cleaner
OutputBaseFilename=DD_Cleaner_Setup_{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=data\dd_cleaner.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#MyBuildDir}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyBuildDir}\ddc.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
// "Is it running" is answered with tasklist: the program has no named mutex.
function IsAppRunning(): Boolean;
var
  ResultCode: Integer;
  TmpFile: String;
  Output: AnsiString;
begin
  TmpFile := ExpandConstant('{tmp}\tasklist.txt');
  Exec(ExpandConstant('{cmd}'), '/C tasklist /FI "IMAGENAME eq {#MyAppExeName}" /NH > "' + TmpFile + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := False;
  if LoadStringFromFile(TmpFile, Output) then
    Result := Pos('{#MyAppExeName}', Output) > 0;
  DeleteFile(TmpFile);
end;

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
      Sleep(500);
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

// A copy installed somewhere else (Program Files) is removed first, or its files would stay behind. Silent: user data is kept.
procedure RemoveInstallElsewhere();
var
  Key, Location, Uninstaller: String;
  ResultCode: Integer;
begin
  Key := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{3B7C5D1E-9A42-4F6B-8C0D-7E2A91F4B6C3}_is1';
  if not RegQueryStringValue(HKLM, Key, 'InstallLocation', Location) then Exit;
  if CompareText(RemoveBackslashUnlessRoot(Location), ExpandConstant('{app}')) = 0 then Exit;
  if RegQueryStringValue(HKLM, Key, 'UninstallString', Uninstaller) then
    Exec(RemoveQuotes(Uninstaller), '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function Icacls(const Params: String): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\icacls.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

// C:\Tools lets any signed-in user change what is below it, and this program runs elevated: only administrators may write
// in its folder. Done before the files are copied, so there is no moment when they can be replaced.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Dir, Quoted: String;
  Rec: TFindRec;
  IsLink: Boolean;
begin
  Result := '';
  RemoveInstallElsewhere();
  Dir := ExpandConstant('{app}');
  Quoted := '"' + Dir + '"';
  IsLink := False;
  if FindFirst(Dir, Rec) then
  begin
    IsLink := (Rec.Attributes and $400) <> 0;
    FindClose(Rec);
  end;
  if IsLink or not ForceDirectories(Dir) then
  begin
    Result := 'The folder ' + Dir + ' cannot be used (it is a link or it cannot be created).';
    Exit;
  end;
  if not (Icacls(Quoted + ' /setowner *S-1-5-32-544 /T /L /Q') and Icacls(Quoted + ' /reset /T /L /Q') and
          Icacls(Quoted + ' /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /L /Q')) then
    Result := 'The folder ' + Dir + ' could not be protected. Nothing was installed.';
end;

// ---- user data question (added by the audit, group 2) ----
[CustomMessages]
english.DataAsk=Remove all the user data of %1?%n%nFolder(s):%n%2%nContent: %3 (%4 MB).%n%nYes: the folder(s) are deleted, for good.%nNo: they are kept, you get them back if you reinstall %1.%n%nYour data in D:\Datas is never touched: delete it yourself if you do not want it.
english.DataWhat=the settings, quarantine, registry backups and downloaded lists (antivirus signatures, GeoIP)

[Code]
// Size of a folder in bytes: the dialog tells the user what "Yes" removes.
function FolderBytes(const Dir: String): Int64;
var
  Rec: TFindRec;
begin
  Result := 0;
  if FindFirst(Dir + '\*', Rec) then
  try
    repeat
      if (Rec.Name <> '.') and (Rec.Name <> '..') then
      begin
        if (Rec.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0 then
          Result := Result + FolderBytes(Dir + '\' + Rec.Name)
        else
          Result := Result + (Int64(Rec.SizeHigh) * 4294967296) + Rec.SizeLow;
      end;
    until not FindNext(Rec);
  finally
    FindClose(Rec);
  end;
end;

procedure AddIfExists(var Dirs: TArrayOfString; const Dir: String);
var
  N: Integer;
begin
  if DirExists(Dir) then
  begin
    N := GetArrayLength(Dirs);
    SetArrayLength(Dirs, N + 1);
    Dirs[N] := Dir;
  end;
end;

// One question, Yes or No, No by default: remove all the user data? The program and its technical leftovers are always removed.
// A silent uninstall (/SILENT, /VERYSILENT) asks nothing and keeps the data: /SUPPRESSMSGBOXES does not answer a MsgBox of
// this script, so the uninstaller would wait for a click nobody can make.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Dirs: TArrayOfString;
  Where: String;
  Bytes: Int64;
  I: Integer;
begin
  if CurUninstallStep <> usPostUninstall then Exit;
  if UninstallSilent then Exit;
  SetArrayLength(Dirs, 0);
  AddIfExists(Dirs, ExpandConstant('{userappdata}\BSM\DDCleaner'));
  if GetArrayLength(Dirs) = 0 then Exit;
  Where := '';
  Bytes := 0;
  for I := 0 to GetArrayLength(Dirs) - 1 do
  begin
    if Where <> '' then Where := Where + #13#10;
    Where := Where + Dirs[I];
    Bytes := Bytes + FolderBytes(Dirs[I]);
  end;
  if MsgBox(FmtMessage(CustomMessage('DataAsk'), ['DD Cleaner', Where, CustomMessage('DataWhat'), IntToStr(Integer(Bytes div 1048576))]),
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
  begin
    for I := 0 to GetArrayLength(Dirs) - 1 do
      DelTree(Dirs[I], True, True, True);
    RemoveDir(ExpandConstant('{userappdata}\BSM'));       // only when empty
  end;
end;
