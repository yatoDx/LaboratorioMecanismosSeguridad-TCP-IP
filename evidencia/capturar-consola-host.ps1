param(
    [ValidateSet('w32tm','verificacion')][string]$Which = 'w32tm'
)
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class W {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lp);
    [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr wParam, IntPtr lParam);
    public delegate bool EnumWindowsProc(IntPtr h, IntPtr lp);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }

    public static IntPtr FindByTitle(string needle) {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr h, IntPtr lp) {
            if (!IsWindowVisible(h)) return true;
            var s = new StringBuilder(256);
            GetWindowText(h, s, 256);
            if (s.ToString().IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) {
                found = h;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
"@

$root   = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)  # lab/
$evi    = Join-Path $root 'evidencia'
$outDir = Join-Path $evi 'pantallazos'
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

$cfg = @{
    w32tm        = @{ Title='ANALISTA-NTP';  Bat='mostrar-w32tm.bat';        Out='host-w32tm.png';                Wait=5  }
    verificacion = @{ Title='ANALISTA-VERIF'; Bat='mostrar-verificacion.bat'; Out='host-verificacion-analista.png'; Wait=48 }
}
$c = $cfg[$Which]

# Cerrar ventanas previas con el mismo titulo (WM_CLOSE = 0x0010)
$prev = [W]::FindByTitle($c.Title)
while ($prev -ne [IntPtr]::Zero) {
    [W]::PostMessage($prev, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    Start-Sleep -Milliseconds 600
    $prev = [W]::FindByTitle($c.Title)
}

$bat = Join-Path $evi $c.Bat
Start-Process -FilePath $bat -WorkingDirectory $root | Out-Null
Start-Sleep -Seconds $c.Wait

$hwnd = [W]::FindByTitle($c.Title)
if ($hwnd -eq [IntPtr]::Zero) { throw "No se encontro la ventana con titulo $($c.Title)" }

[W]::ShowWindow($hwnd, 3) | Out-Null          # SW_MAXIMIZE
[W]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 1500

$rect = New-Object W+RECT
[W]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
if ($w -le 0 -or $h -le 0) { throw "Dimensiones de ventana invalidas: ${w}x${h}" }
Write-Host "Ventana: ${w}x${h}"

$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g   = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
[W]::PrintWindow($hwnd, $hdc, 2) | Out-Null
$g.ReleaseHdc($hdc)
$g.Dispose()
$bmp.Save((Join-Path $outDir $c.Out), [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host "Captura guardada: $($c.Out)"
