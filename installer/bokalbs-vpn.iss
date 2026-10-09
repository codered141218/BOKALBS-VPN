; Inno Setup script for BOKALBS VPN.
; Built by .github/workflows/build.yml:  iscc /DAppVersion=1.0.0 /DSourceDir=..\dist installer\bokalbs-vpn.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist"
#endif

[Setup]
AppId={{6B6F6B61-6C62-7376-706E-000000000001}
AppName=BOKALBS VPN
AppVersion={#AppVersion}
AppVerName=BOKALBS VPN {#AppVersion}
AppPublisher=BOKALBS
AppPublisherURL=https://github.com/codered141218/BOKALBS-VPN
DefaultDirName={autopf}\BOKALBS VPN
DefaultGroupName=BOKALBS VPN
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=BOKALBS-VPN-Setup-{#AppVersion}
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\bokalbs-vpn.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\bokalbs-vpn.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\bokalbs-vpn-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "{#SourceDir}\WINTUN-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\BOKALBS VPN"; Filename: "{app}\bokalbs-vpn.exe"
Name: "{group}\Uninstall BOKALBS VPN"; Filename: "{uninstallexe}"
Name: "{autodesktop}\BOKALBS VPN"; Filename: "{app}\bokalbs-vpn.exe"; Tasks: desktopicon

[Run]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=BOKALBS-VPN-program"; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=BOKALBS-VPN-program dir=in action=allow profile=any enable=yes program=""{app}\bokalbs-vpn.exe"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=BOKALBS-VPN-program dir=in action=allow profile=any enable=yes program=""{app}\bokalbs-vpn-cli.exe"""; Flags: runhidden
Filename: "{app}\bokalbs-vpn.exe"; Description: "{cm:LaunchProgram,BOKALBS VPN}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM bokalbs-vpn.exe"; Flags: runhidden; RunOnceId: "StopApp"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=BOKALBS-VPN-members"; Flags: runhidden; RunOnceId: "RemoveFirewallRule"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=BOKALBS-VPN-program"; Flags: runhidden; RunOnceId: "RemoveProgramRule"

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\BOKALBS-VPN\WebView2"
