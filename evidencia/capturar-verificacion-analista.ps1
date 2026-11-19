# Captura la salida de verificar_laboratorio.ps1 -Rol analista a UTF-8
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$root = Split-Path -Parent $MyInvocation.MyCommand.Path   # evidencia/
$script = Join-Path (Split-Path -Parent $root) 'verificar_laboratorio.ps1'
$out = Join-Path $root 'verificacion-analista.txt'

& $script -Rol analista *>&1 | Out-File -FilePath $out -Encoding utf8
Write-Host "salida guardada en $out"
