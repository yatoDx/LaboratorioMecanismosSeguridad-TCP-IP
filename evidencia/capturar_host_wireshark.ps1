param(
    [string]$Out = "evidencia\pantallazos\host-wireshark.png",
    [int]$WaitCaptureSec = 8
)
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class W {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
"@

# 0. Desactivar comprobacion de actualizaciones (evita el dialogo de novedades)
$prefsDir = Join-Path $env:APPDATA 'Wireshark'
if (-not (Test-Path $prefsDir)) { New-Item -ItemType Directory -Path $prefsDir | Out-Null }
$prefsFile = Join-Path $prefsDir 'preferences'
$lines = @()
if (Test-Path $prefsFile) { $lines = Get-Content $prefsFile | Where-Object { $_ -notmatch '^gui\.update' } }
$lines += 'gui.update.enabled: FALSE'
Set-Content -Path $prefsFile -Value $lines -Encoding Ascii
Write-Host "Update check desactivado"

# 1. Localizar la interfaz solo-anfitrion (la que tiene 192.168.50.10)
$ifAlias = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq '192.168.50.10' }).InterfaceAlias
if (-not $ifAlias) { throw "No se encontro la interfaz con 192.168.50.10" }
Write-Host "Interfaz Windows: $ifAlias"

$tshark = "C:\Program Files\Wireshark\tshark.exe"
$ifList = & $tshark -D 2>$null
$ifLine = $ifList | Where-Object { $_ -like "*($ifAlias)*" } | Select-Object -First 1
if (-not $ifLine) { throw "Interfaz no encontrada en tshark -D" }
$ifNum = ($ifLine -split '\.')[0]
Write-Host "Interfaz tshark: $ifNum -> $ifLine"

# 2. Cerrar Wireshark previo
Get-Process Wireshark -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# 3. Lanzar Wireshark capturando
$ws = "C:\Program Files\Wireshark\Wireshark.exe"
Start-Process -FilePath $ws -ArgumentList "-k","-i",$ifNum
Write-Host "Wireshark lanzado..."
Start-Sleep -Seconds 7

# 4. Cerrar cualquier dialogo modal (ESC) y maximizar la ventana principal
$proc = Get-Process Wireshark -ErrorAction Stop | Select-Object -First 1
$hwnd = $proc.MainWindowHandle
if ($hwnd -eq [IntPtr]::Zero) { throw "No se encontro la ventana de Wireshark" }
[W]::ShowWindow($hwnd, 3) | Out-Null          # SW_MAXIMIZE
[W]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 500
[System.Windows.Forms.SendKeys]::SendWait('{ESC}')
Start-Sleep -Milliseconds 500
[W]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 500

# 5. Generar trafico del laboratorio
Write-Host "Generando trafico..."
for ($i = 0; $i -lt 3; $i++) {
    & nslookup web.lab.local 192.168.50.53 | Out-Null
    Test-Connection -ComputerName 192.168.50.1 -Count 1 -Quiet | Out-Null
    Test-Connection -ComputerName 192.168.50.20 -Count 1 -Quiet | Out-Null
    Test-Connection -ComputerName 192.168.50.53 -Count 1 -Quiet | Out-Null
    Test-Connection -ComputerName 192.168.50.30 -Count 1 -Quiet | Out-Null
}
try { Invoke-WebRequest -Uri "http://192.168.50.20/" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {}
try { Invoke-WebRequest -Uri "http://192.168.50.20/" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {}

Start-Sleep -Seconds $WaitCaptureSec

# 6. Traer Wireshark al frente y capturar su ventana
[W]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 600

$rect = New-Object W+RECT
[W]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
Write-Host "Ventana: ${w}x${h}"

$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
[W]::PrintWindow($hwnd, $hdc, 2) | Out-Null
$g.ReleaseHdc($hdc)
$g.Dispose()

$outDir = Split-Path -Parent $Out
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
$bmp.Save((Join-Path (Get-Location) $Out), [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host "Captura guardada: $Out"
