param(
    [Parameter(Mandatory=$true)][string]$Pcap,
    [string]$Filter = '',
    [Parameter(Mandatory=$true)][string]$Out,
    [int]$WaitSec = 5,
    [switch]$RawTcpSequence
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class CaptureWindow {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int command);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
"@
$pcapFull = (Resolve-Path $Pcap).Path
$outFull = [System.IO.Path]::GetFullPath($Out)
if (Test-Path $outFull) { throw "La captura ya existe; use un nombre nuevo: $outFull" }
if ($Filter.Contains('"')) { throw 'El filtro no debe contener comillas dobles.' }
$arguments = '-r "' + $pcapFull + '"'
if ($Filter) { $arguments += ' -Y "' + $Filter + '"' }
if ($RawTcpSequence) { $arguments += ' -o tcp.relative_sequence_numbers:FALSE' }
$proc = Start-Process -FilePath 'C:\Program Files\Wireshark\Wireshark.exe' -ArgumentList $arguments -PassThru
try {
    Start-Sleep -Seconds $WaitSec
    $proc.Refresh()
    if ($proc.HasExited) { throw "Wireshark termino: $($proc.ExitCode)" }
    $hwnd = $proc.MainWindowHandle
    if ($hwnd -eq [IntPtr]::Zero) { throw 'No se encontro la ventana creada.' }
    [CaptureWindow]::ShowWindow($hwnd, 3) | Out-Null
    [CaptureWindow]::SetForegroundWindow($hwnd) | Out-Null
    Start-Sleep -Milliseconds 1200
    $rect = New-Object CaptureWindow+RECT
    if (-not [CaptureWindow]::GetWindowRect($hwnd, [ref]$rect)) { throw 'No se pudo medir la ventana.' }
    $bmp = New-Object System.Drawing.Bitmap(($rect.Right - $rect.Left), ($rect.Bottom - $rect.Top))
    try {
        $graphics = [System.Drawing.Graphics]::FromImage($bmp)
        $hdc = $graphics.GetHdc()
        try { $ok = [CaptureWindow]::PrintWindow($hwnd, $hdc, 2) }
        finally { $graphics.ReleaseHdc($hdc); $graphics.Dispose() }
        if (-not $ok) { throw 'PrintWindow fallo; no se guardara evidencia vacia.' }
        $bmp.Save($outFull, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally { $bmp.Dispose() }
    Write-Host "Pantallazo real: $outFull"
} finally {
    if (-not $proc.HasExited) { $proc.CloseMainWindow() | Out-Null }
}
