@echo off
title ANALISTA-VERIF
powershell -NoProfile -ExecutionPolicy Bypass -Command "$Host.UI.RawUI.WindowTitle='ANALISTA-VERIF'; & '.\verificar_laboratorio.ps1' -Rol analista"
echo.
pause
