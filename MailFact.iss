; Установщик MailFact (Inno Setup 6).
;
; Собирается и на машине разработчика, и на сервере GitHub, где чужих папок
; не существует — поэтому НИ ОДНОГО абсолютного пути. Локальная сборка
; передаёт своё через ключи, CI пользуется значениями по умолчанию:
;
;   ISCC /DAppVersion=1.0.0 /DSrcDir=...\dist\MailFact /DOutDir=...\installer MailFact.iss
;   ISCC MailFact.iss                                  (так делает CI)

#define AppNameStr "MailFact"

#ifndef AppVersion
  ; Версия читается из VERSION — того же файла, что читают окно, свойства .exe
  ; и CI. Разъехаться они физически не могут.
  #define AppVersion Trim(FileRead(FileOpen("VERSION")))
#endif
#ifndef SrcDir
  #define SrcDir "dist\MailFact"
#endif
#ifndef OutDir
  #define OutDir "installer"
#endif

[Setup]
; AppId менять НЕЛЬЗЯ никогда: по нему установщик находит предыдущую версию и
; обновляет её вместо того, чтобы поставить вторую копию рядом.
AppId={{DA2BCC50-6779-4561-BC18-C83D41C3A275}
AppName={#AppNameStr}
AppVersion={#AppVersion}
AppVerName={#AppNameStr} {#AppVersion}
VersionInfoVersion={#AppVersion}
AppPublisher={#AppNameStr}

; В профиль пользователя, а НЕ в Program Files. Причина не в лени: программа
; пишет рядом с собой кэш вердиктов, настройки и скачанные списки доменов, а
; в Program Files без прав администратора запись запрещена — и всё ломалось бы
; МОЛЧА. Побочный плюс: установка не требует UAC, человеку хватает двойного
; клика.
DefaultDirName={localappdata}\Programs\{#AppNameStr}
PrivilegesRequired=lowest

; Имя файла БЕЗ версии. Если бы версия попала в имя, постоянная ссылка
; releases/latest/download/MailFact-setup.exe сломалась бы у всех, кому она
; уже отправлена, при первом же новом релизе.
OutputBaseFilename={#AppNameStr}-setup
OutputDir={#OutDir}

SetupIconFile=assets\{#AppNameStr}.ico
UninstallDisplayIcon={app}\{#AppNameStr}.exe
UninstallDisplayName={#AppNameStr} {#AppVersion}

ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

Compression=lzma2/max
SolidCompression=yes
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
; Рекурсивно вся папка сборки PyInstaller: сам .exe плюс _internal со всем,
; что ему нужно.
Source: "{#SrcDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; WorkingDir задан явно. Без него ярлык унаследовал бы каталог, из которого
; его создавали, и программа искала бы свои данные не там.
Name: "{autoprograms}\{#AppNameStr}"; Filename: "{app}\{#AppNameStr}.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\{#AppNameStr}"; Filename: "{app}\{#AppNameStr}.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppNameStr}.exe"; Description: "Запустить {#AppNameStr}"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Установщик знает только то, что положил сам. Всё, что программа создаёт уже
; во время работы — кэш вердиктов, долгая память, журнал аварий, настройки,
; скачанные свежие списки доменов, временные таблицы результатов, — ему
; неизвестно, и без этого раздела осталось бы на диске после удаления.
Type: filesandordirs; Name: "{app}\data"
Type: dirifempty;     Name: "{app}"

[Code]
{ ------------------------------------------------------------------------
  WebView2 Runtime — движок, которым рисуется окно программы.

  ЗАЧЕМ ЭТО ЗДЕСЬ. В Windows 11 рантайм есть всегда, в Windows 10 — не
  обязательно. Без него окно не открывается вовсе: человек ставит программу,
  запускает, и ничего не происходит. Установщик обязан закрыть эту дыру сам,
  а не оставлять её пользователю.

  Проверка идёт по реестру, как советует сама Microsoft: ключ клиента
  EdgeUpdate с GUID рантайма, значение pv. Пустое значение и "0.0.0.0"
  означают «не установлен» — так помечается снесённый рантайм.

  Ключ смотрим В ТРЁХ местах: 64-битная ветка машины, 32-битная ветка машины
  и ветка пользователя. Рантайм ставится по-разному в зависимости от того,
  были ли права администратора, и проверка одного места дала бы ложное
  «не установлен» на машине, где он есть.
  ------------------------------------------------------------------------ }

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

{ Ключ /FORCEWEBVIEW2 существует только для проверки: он заставляет пройти
  ветку доставки рантайма на машине, где рантайм уже стоит. Иначе эту ветку
  нельзя было бы испытать вообще — только на чистой Windows 10, которой у
  разработчика нет. Обычному пользователю ключ не нужен и не мешает. }
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
    { Хеш не задаём: Microsoft обновляет загрузчик, и зафиксированная сумма
      сломала бы установку у всех при первом же их обновлении. }
    DownloadTemporaryFile(WV2_URL, 'MicrosoftEdgeWebview2Setup.exe', '', nil);
  except
    { Нет интернета или ссылка не ответила. Это НЕ повод отменять установку:
      программа поставится, а про рантайм скажет сама при запуске. Молчать
      здесь нельзя — человек должен знать, что осталось доделать. }
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
  { Код возврата смотрим, но установку из-за него НЕ отменяем: даже без
    рантайма человеку лучше получить установленную программу с понятным
    сообщением, чем откат на середине. }
end;
