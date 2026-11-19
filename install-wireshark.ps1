# install-wireshark.ps1 - Instala Wireshark vía winget (requiere administrador)
$log = "C:\Users\yatoG\Documents\Qoder\2026-11-18\70141794\lab\wireshark-install.log"
"=== winget install Wireshark $(Get-Date) ===" | Out-File $log -Encoding utf8
winget install --id WiresharkFoundation.Wireshark -e --accept-package-agreements --accept-source-agreements --silent *>&1 | Tee-Object -FilePath $log -Append
"=== fin $(Get-Date) ===" | Out-File $log -Append
