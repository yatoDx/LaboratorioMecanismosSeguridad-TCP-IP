# Configura la sincronizacion de hora del host (analista) con el gateway 192.168.50.1
$ErrorActionPreference = 'Continue'
$out = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'analista-w32tm.txt'

$log = @()
$log += "=== Configuracion NTP del host (analista) ==="
$log += (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

$log += "`n-- 1. w32tm /config (peer 192.168.50.1) --"
$log += (w32tm /config /manualpeerlist:"192.168.50.1" /syncfromflags:manual /reliable:yes /update 2>&1 | Out-String)

$log += "-- 2. Arrancar servicio w32time --"
Set-Service w32time -StartupType Automatic -ErrorAction SilentlyContinue
$log += (net start w32time 2>&1 | Out-String)

$log += "-- 3. Forzar resincronizacion --"
$log += (w32tm /resync /force 2>&1 | Out-String)
Start-Sleep -Seconds 4

$log += "-- 4. w32tm /query /status --"
$log += (w32tm /query /status 2>&1 | Out-String)

$log += "-- 5. w32tm /query /peers --"
$log += (w32tm /query /peers 2>&1 | Out-String)

$log += "=== fin ==="
$log | Out-File -FilePath $out -Encoding utf8
Write-Host "salida guardada en $out"
