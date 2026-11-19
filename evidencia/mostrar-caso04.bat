@echo off
title ANALISTA-CASO04-ML
python scripts\caso04_ml.py
echo.
echo --- Primeras filas del dataset ---
powershell -NoProfile -Command "Import-Csv evidencia\casos\caso04-dataset.csv | Select-Object -First 6 | Format-Table"
pause
