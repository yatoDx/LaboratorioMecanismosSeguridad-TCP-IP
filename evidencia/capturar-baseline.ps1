param(
    [string]$Out = "evidencia\baseline-normal.pcapng",
    [int]$DurationSec = 300,
    [int]$IfNum = 5
)
$ErrorActionPreference = 'Continue'

$root    = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)  # lab/
$outFull = Join-Path $root $Out
$outDir  = Split-Path -Parent $outFull
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
if (Test-Path $outFull) { Remove-Item $outFull -Force }

$tshark = "C:\Program Files\Wireshark\tshark.exe"
if (-not (Test-Path $tshark)) { throw "tshark no encontrado en $tshark" }

$cap = Start-Process -FilePath $tshark `
    -ArgumentList "-i", "$IfNum", "-w", $outFull, "-a", "duration:$DurationSec" `
    -PassThru -WindowStyle Hidden
Write-Host "Captura iniciada (PID $($cap.Id)): $DurationSec s en interfaz $IfNum -> $outFull"

$end = (Get-Date).AddSeconds($DurationSec)
$iter = 0
while ((Get-Date) -lt $end) {
    $iter++
    foreach ($ip in '192.168.50.1','192.168.50.20','192.168.50.53','192.168.50.30') {
        & ping.exe -n 1 -w 500 $ip | Out-Null
    }
    try { Invoke-WebRequest -Uri 'http://192.168.50.20/' -UseBasicParsing -TimeoutSec 3 | Out-Null } catch {}
    & nslookup.exe web.lab.local 192.168.50.53 | Out-Null
    & nslookup.exe xmpp.lab.local 192.168.50.53 | Out-Null
    $r = Test-NetConnection -ComputerName 192.168.50.30 -Port 5222 -WarningAction SilentlyContinue
    if ($iter % 6 -eq 0) { Write-Host "iter $iter - $(Get-Date -Format 'HH:mm:ss')" }
    Start-Sleep -Seconds 5
}

Write-Host "Trafico generado ($iter iteraciones). Esperando fin de captura..."
$cap.WaitForExit(90000) | Out-Null

if (Test-Path $outFull) {
    $sz = (Get-Item $outFull).Length
    Write-Host "PCAP guardado: $outFull ($sz bytes)"
} else {
    Write-Host "ERROR: no se genero el pcapng"
}
