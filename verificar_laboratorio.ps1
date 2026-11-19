# verificar_laboratorio.ps1 -Rol analista
# Ejecutar:  powershell -ExecutionPolicy Bypass -File verificar_laboratorio.ps1 -Rol analista
param(
  [string]$Rol = "analista"
)

$ErrorActionPreference = "Continue"

$OK   = @()
$FAIL = @()
$WARN = @()

function Ok($m)   { Write-Host "[OK]   $m" -ForegroundColor Green;  $script:OK   += $m }
function Fail($m) { Write-Host "[FALTA] $m" -ForegroundColor Red;    $script:FAIL += $m }
function Warn($m) { Write-Host "[?]    $m" -ForegroundColor Yellow;  $script:WARN += $m }

Write-Host "=============================================="
Write-Host " Verificacion de laboratorio - rol: $Rol"
Get-Date
Write-Host "=============================================="

# --- 1. Interfaz host-only e IP ---
$iface = Get-NetAdapter -ErrorAction SilentlyContinue |
  Where-Object { $_.InterfaceDescription -like "*VirtualBox Host-Only*" -or $_.Name -like "Ethernet 2" } |
  Select-Object -First 1

if ($iface) {
  Write-Host "`nInterfaz host-only detectada: $($iface.Name) ($($iface.InterfaceDescription))"
  $ip = Get-NetIPAddress -InterfaceIndex $iface.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
  if ($ip -and $ip.IPAddress -eq "192.168.50.10") {
    Ok "IP 192.168.50.10 en $($iface.Name)"
  } elseif ($ip) {
    Fail "IP en $($iface.Name) es $($ip.IPAddress), se esperaba 192.168.50.10"
  } else {
    Fail "Sin IPv4 en $($iface.Name)"
  }
  $dns = Get-DnsClientServerAddress -InterfaceIndex $iface.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
  if ($dns -and ($dns.ServerAddresses -contains "192.168.50.53")) {
    Ok "DNS 192.168.50.53 configurado"
  } else {
    Warn "DNS 192.168.50.53 NO configurado en $($iface.Name)"
  }
} else {
  Fail "No se detecto adaptador host-only"
}

# --- 2. Conectividad ---
Write-Host "`nConectividad:"
function Ping-T($ip, $desc) {
  if (Test-Connection -ComputerName $ip -Count 1 -Quiet) { Ok "$desc ($ip) responde" }
  else { Fail "$desc ($ip) NO responde" }
}
Ping-T 192.168.50.1  "gateway"
Ping-T 192.168.50.20 "web"
Ping-T 192.168.50.53 "dns"
Ping-T 192.168.50.30 "xmpp"

# --- 3. Aislamiento ---
Write-Host "`nAislamiento:"
if (Test-Connection -ComputerName 192.0.2.1 -Count 1 -Quiet -ErrorAction SilentlyContinue) {
  Fail "192.0.2.1 responde (aislamiento roto)"
} else {
  Ok "192.0.2.1 no responde (aislado)"
}

# --- 4. Servicios TCP ---
Write-Host "`nServicios (TCP):"
function Port-T($ip, $port, $desc) {
  $r = Test-NetConnection -ComputerName $ip -Port $port -WarningAction SilentlyContinue
  if ($r.TcpTestSucceeded) { Ok "$desc ($ip`:$port) abierto" }
  else { Fail "$desc ($ip`:$port) cerrado" }
}
Port-T 192.168.50.20 80   "HTTP"
Port-T 192.168.50.53 53   "DNS"
Port-T 192.168.50.30 5222 "XMPP"

# --- 5. Herramientas del analista ---
Write-Host "`nHerramientas:"
$wsDir = 'C:\Program Files\Wireshark'
if (Get-Command wireshark -ErrorAction SilentlyContinue) { Ok "Wireshark instalado" }
elseif (Test-Path (Join-Path $wsDir 'Wireshark.exe')) {
    $env:Path += ";$wsDir"   # solo para esta sesion: tshark y dumpcap quedan disponibles
    Ok "Wireshark instalado en $wsDir (no esta en el PATH del sistema; anadido a esta sesion)"
}
else { Warn "Wireshark no detectado (ni en PATH ni en $wsDir)" }
if (Get-Command python -ErrorAction SilentlyContinue) { Ok "Python: $(python --version 2>&1)" }
else { Warn "Python no detectado" }

# --- Resumen ---
Write-Host "`n=============================================="
Write-Host " Resumen: $($OK.Count) OK | $($FAIL.Count) FALTA | $($WARN.Count) advertencias"
Get-Date
Write-Host "=============================================="
