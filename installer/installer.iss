; AppProxySwitch installer (Inno Setup 6).
; UTF-8 with BOM: Chinese strings are kept as-is.
#define MyAppName "AppProxySwitch"
#define MyAppVersion "1.3.7"
#define MyAppExeName "AppProxySwitch.exe"

[Setup]
AppId={{7E1F4A8B-3C2D-4E5F-9A1B-6D8C2E4F5A6B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=AppProxySwitch Contributors
DefaultDirName={localappdata}\Programs\AppProxySwitch
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; No admin needed for the installer itself: the app elevates its own engine
; on demand (and ships the signed WinDivert driver as a data file).
PrivilegesRequired=lowest
OutputDir=..\dist
OutputBaseFilename=AppProxySwitch-Setup-{#MyAppVersion}-x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=..\resources\AppProxySwitch.ico
LicenseFile=..\LICENSE
VersionInfoVersion={#MyAppVersion}
VersionInfoDescription=AppProxySwitch 单应用代理开关

[Languages]
Name: "chinesesimplified"; MessagesFile: "ChineseSimplified.isl"

[Files]
; The distributable layout (exe + official WinDivert dll/sys + docs).
Source: "..\dist\AppProxySwitch-{#MyAppVersion}.0-win-x64\AppProxySwitch.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\AppProxySwitch-{#MyAppVersion}.0-win-x64\WinDivert.dll"; DestDir: "{app}"; Flags: ignoreversion
; WinDivert64.sys carries its own 2.2 version resource.  Do not use
; ignoreversion here: the driver may remain locked briefly after APS exits, and
; forcing an identical overwrite makes every in-place upgrade fail needlessly.
; Inno's normal version comparison skips the installed driver when the bundled
; version is unchanged, while still replacing it on a real driver upgrade.
Source: "..\dist\AppProxySwitch-{#MyAppVersion}.0-win-x64\WinDivert64.sys"; DestDir: "{app}"
Source: "..\dist\AppProxySwitch-{#MyAppVersion}.0-win-x64\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\AppProxySwitch-{#MyAppVersion}.0-win-x64\scripts\*.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "..\dist\AppProxySwitch-{#MyAppVersion}.0-win-x64\*.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\AppProxySwitch-{#MyAppVersion}.0-win-x64\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\AppProxySwitch-{#MyAppVersion}.0-win-x64\LICENSES\*"; DestDir: "{app}\LICENSES"; Flags: ignoreversion recursesubdirs
Source: "..\dist\AppProxySwitch-{#MyAppVersion}.0-win-x64\docs\*.md"; DestDir: "{app}\docs"; Flags: ignoreversion skipifsourcedoesntexist

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务："; Flags: checkedonce

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "立即运行 {#MyAppName}"; Flags: nowait postinstall skipifsilent
