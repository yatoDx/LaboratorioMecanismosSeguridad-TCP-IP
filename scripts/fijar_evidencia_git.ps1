# fijar_evidencia_git.ps1 - Corrección de entrega.
# Ejecutar en la raíz del repositorio, en el equipo Windows donde se generó la
# entrega, DESPUÉS de aplicar el parche (git am). Guarda la evidencia byte a
# byte según .gitattributes, para que el manifiesto SHA-256 coincida en
# cualquier clon (Windows o Linux).
$ErrorActionPreference = 'Stop'

Write-Host '0/4 Restaurando saltos de linea CRLF originales (Git los dejo en LF)...'
# Restaura lo reproducible y registra como ENMIENDAS en el manifiesto los 4 archivos
# de saltos mixtos que Git ya alteró (con su huella original y la actual).
python scripts/reparar_evidencia.py --aplicar --enmendar
if ($LASTEXITCODE -ne 0) { throw 'No se pudo reparar la evidencia. No se cambia nada en Git.' }

Write-Host '1/4 Verificando las copias locales contra el manifiesto...'
python scripts/cerrar_parte_i.py --verificar
if ($LASTEXITCODE -ne 0) {
    throw 'Las copias locales no coinciden con el manifiesto. No se cambia nada.'
}

Write-Host '2/4 Registrando la evidencia sin conversión de saltos de línea...'
git add --renormalize -- evidencia entrega-parte-i evidencia.log
git status --short
git commit -m "Guardar la evidencia byte a byte (.gitattributes) para que el manifiesto coincida en cualquier clon"
if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear el commit.' }

Write-Host '3/4 Comprobando en un clon limpio...'
$tmp = Join-Path $env:TEMP ('verif-entrega-' + [guid]::NewGuid().ToString('N'))
git clone --quiet --no-local . $tmp
python (Join-Path $tmp 'scripts/cerrar_parte_i.py') --verificar --paquete (Join-Path $tmp 'entrega-parte-i')
$ok = ($LASTEXITCODE -eq 0)
Remove-Item -Recurse -Force $tmp
if (-not $ok) { throw 'El clon limpio no verifica. No hagas push; revisa la salida anterior.' }

Write-Host '4/4 Listo. El clon limpio verifica. Publica con: git push origin HEAD'
