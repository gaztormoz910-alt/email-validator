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
