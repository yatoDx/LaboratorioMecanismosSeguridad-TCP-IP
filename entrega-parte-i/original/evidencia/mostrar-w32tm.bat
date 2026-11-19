@echo off
title ANALISTA-NTP
w32tm /query /status
w32tm /query /peers
echo.
pause
