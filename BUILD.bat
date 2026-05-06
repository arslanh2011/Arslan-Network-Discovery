@echo off
title Network Info - Build Tool
color 0B
echo.
echo  ================================================
echo    Network Info App - One-Click Builder
echo  ================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found!
    echo  Please install Python 3.10+ from https://python.org
    echo  Make sure to check "Add to PATH" during install.
    pause
    exit /b 1
)

echo  [1/4] Python found.

:: Install dependencies
echo  [2/4] Installing dependencies (scapy + pyinstaller)...
python -m pip install scapy pyinstaller --quiet
if errorlevel 1 (
    echo  [ERROR] pip install failed. Check your internet connection.
    pause
    exit /b 1
)
echo        Done.

:: Build EXE using python -m PyInstaller (works even when PATH is missing)
echo  [3/4] Building EXE (this takes ~60 seconds)...
python -m PyInstaller --onefile --windowed --name "NetworkInfo" network_info.py
if errorlevel 1 (
    echo  [ERROR] Build failed. See above for details.
    pause
    exit /b 1
)

:: Copy EXE to current folder for convenience
copy /Y dist\NetworkInfo.exe NetworkInfo.exe >nul 2>&1

echo  [4/4] Build complete!
echo.
echo  ================================================
echo   Your EXE is ready:
echo   NetworkInfo.exe  (in THIS folder)
echo  ================================================
echo.
echo  IMPORTANT: Right-click NetworkInfo.exe
echo             and choose "Run as administrator"
echo             for LLDP switch detection to work.
echo.
pause
