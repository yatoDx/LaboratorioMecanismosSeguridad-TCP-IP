@echo off
title EVIDENCIA-CASO10-FINAL
chcp 65001 >nul
type evidencia\casos\caso10-resumen.txt
echo.
findstr /C:"New, TLS" /C:"Verified peername" evidencia\casos\caso10-confianza_explicita.txt
echo.
echo Evidencia guardada de pruebas reales; no es una nueva ejecucion.
pause
