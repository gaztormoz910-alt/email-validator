#define AppNameStr "MailFact"

#ifndef AppVersion
  #define AppVersion Trim(FileRead(FileOpen("VERSION")))
#endif
#ifndef SrcDir
  #define SrcDir "dist\MailFact"
#endif
#ifndef OutDir
  #define OutDir "installer"
#endif

[Setup]
AppId={{DA2BCC50-6779-4561-BC18-C83D41C3A275}
AppName={#AppNameStr}
AppVersion={#AppVersion}
AppVerName={#AppNameStr} {#AppVersion}
VersionInfoVersion={#AppVersion}
AppPublisher={#AppNameStr}

DefaultDirName={localappdata}\Programs\{#AppNameStr}
PrivilegesRequired=lowest

OutputBaseFilename={#AppNameStr}-setup
OutputDir={#OutDir}

SetupIconFile=assets\{#AppNameStr}.ico
UninstallDisplayIcon={app}\{#AppNameStr}.exe
UninstallDisplayName={#AppNameStr} {#AppVersion}

ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

Compression=lzma2/max
SolidCompression=yes

TimeStampsInUTC=yes
WizardStyle=modern
DisableProgramGroupPage=yes
DisableDirPage=auto
DisableWelcomePage=no
ShowLanguageDialog=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительно:"

[Files]
Source: "{#SrcDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppNameStr}"; Filename: "{app}\{#AppNameStr}.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\{#AppNameStr}"; Filename: "{app}\{#AppNameStr}.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppNameStr}.exe"; Description: "Запустить {#AppNameStr}"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\data"
Type: dirifempty;     Name: "{app}"

[Code]

const
  WV2_GUID = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  WV2_URL = 'https://go.microsoft.com/fwlink/p/?LinkId=2124703';

function WebView2Version(Root: Integer; const Key: String): String;
begin
  Result := '';
  if not RegQueryStringValue(Root, Key, 'pv', Result) then
    Result := '';
  if Result = '0.0.0.0' then
    Result := '';
end;

function WebView2Installed(): Boolean;
var
  V: String;
begin
  V := WebView2Version(HKEY_LOCAL_MACHINE,
    'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\' + WV2_GUID);
  if V = '' then
    V := WebView2Version(HKEY_LOCAL_MACHINE,
      'SOFTWARE\Microsoft\EdgeUpdate\Clients\' + WV2_GUID);
  if V = '' then
    V := WebView2Version(HKEY_CURRENT_USER,
      'SOFTWARE\Microsoft\EdgeUpdate\Clients\' + WV2_GUID);
  Result := V <> '';
  if Result then
    Log('WebView2 Runtime найден, версия ' + V)
  else
    Log('WebView2 Runtime НЕ найден ни в одной из трёх веток реестра');
end;

function ForceWebView2(): Boolean;
begin
  Result := ExpandConstant('{param:FORCEWEBVIEW2|0}') <> '0';
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  BootFile: String;
  ExitCode: Integer;
begin
  Result := '';
  if WebView2Installed() and (not ForceWebView2()) then
    exit;

  BootFile := ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe');
  Log('Качаю загрузчик WebView2: ' + WV2_URL);
  try
    
    DownloadTemporaryFile(WV2_URL, 'MicrosoftEdgeWebview2Setup.exe', '', nil);
  except
    
    Log('Скачать загрузчик WebView2 не удалось: ' + GetExceptionMessage);
    if not WizardSilent() then
      MsgBox('Не удалось скачать компонент Microsoft WebView2 — похоже, нет'
        + ' связи с интернетом.' + #13#10#13#10
        + 'MailFact установится, но окно может не открыться.' + #13#10
        + 'Поставьте компонент вручную, он бесплатный:' + #13#10
        + 'https://developer.microsoft.com/microsoft-edge/webview2/',
        mbInformation, MB_OK);
    exit;
  end;

  Log('Ставлю WebView2 Runtime');
  if not Exec(BootFile, '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
  begin
    Log('Загрузчик WebView2 не запустился');
    exit;
  end;
  Log('Загрузчик WebView2 вернул код ' + IntToStr(ExitCode));
  
end;
