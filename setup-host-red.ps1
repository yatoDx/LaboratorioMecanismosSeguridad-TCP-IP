# setup-host-red.ps1 - Configura la red solo-anfitrión del analista (host Windows)
# Requisito: ejecutar como administrador.
$ErrorActionPreference = "Stop"
$log = "C:\Users\yatoG\Documents\Qoder\2026-11-18\70141794\lab\setup-host-red.log"
Start-Transcript -Path $log -Force

Write-Host "=== Configuración de la red del analista (192.168.50.0/24) ==="

$iface = Get-NetAdapter -ErrorAction SilentlyContinue |
  Where-Object { $_.InterfaceDescription -like "*VirtualBox Host-Only*" } |
  Select-Object -First 1
if (-not $iface) { $iface = Get-NetAdapter -Name "Ethernet 2" -ErrorAction SilentlyContinue }

if (-not $iface) {
  Write-Host "[FALTA] No se encontró el adaptador solo-anfitrión."
  Stop-Transcript
  exit 1
}
Write-Host "Adaptador detectado: $($iface.Name) - $($iface.InterfaceDescription)"

# 1. Quitar IPs IPv4 existentes (VirtualBox lo deja en 192.168.56.1 por defecto)
Get-NetIPAddress -InterfaceIndex $iface.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Remove-NetIPAddress -Confirm:$false

# 2. Asignar la IP del analista
New-NetIPAddress -InterfaceIndex $iface.ifIndex -IPAddress 192.168.50.10 -PrefixLength 24 | Out-Null

# 3. Servidor DNS del laboratorio
Set-DnsClientServerAddress -InterfaceIndex $iface.ifIndex -ServerAddresses 192.168.50.53

# 4. Deshabilitar el DHCP del host-only de VirtualBox (usamos IPs estáticas)
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" dhcpserver modify `
  --netname "HostInterfaceNetworking-VirtualBox Host-Only Ethernet Adapter" --disable

Write-Host "--- IP resultante ---"
Get-NetIPAddress -InterfaceIndex $iface.ifIndex -AddressFamily IPv4 |
  Format-Table IPAddress, PrefixLength -AutoSize

Write-Host "--- DNS resultante ---"
Get-DnsClientServerAddress -InterfaceIndex $iface.ifIndex -AddressFamily IPv4 |
  Format-Table ServerAddresses -AutoSize

Write-Host "[OK] Red del analista configurada: 192.168.50.10/24, DNS 192.168.50.53"
Stop-Transcript
