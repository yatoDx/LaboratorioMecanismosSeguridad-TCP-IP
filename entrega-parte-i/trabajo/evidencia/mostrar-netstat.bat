@echo off
title ANALISTA-NETSTAT
netstat -ano | findstr LISTENING
echo.
echo --- Conexiones establecidas (lab) ---
netstat -ano | findstr 192.168.50
pause
