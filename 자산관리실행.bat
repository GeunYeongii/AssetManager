@echo off
chcp 65001 > nul
mode con: cols=140 lines=40
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0AssetManager.ps1"
pause