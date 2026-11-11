@echo off
setlocal EnableExtensions
cd /d "%~dp0"

REM Build WoL Host and WoL Remote as Windows x64 onedir applications.
REM Requires Python 3 (64-bit) and an internet connection for installing build dependencies.

if not exist "wol_host.py" (
    echo ERROR: wol_host.py was not found. Run this script from the repository folder.
    exit /b 1
)
if not exist "wol_pc.py" (
    echo ERROR: wol_pc.py was not found. Run this script from the repository folder.
    exit /b 1
)
where py >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python Launcher 'py' was not found. Install 64-bit Python 3 and try again.
    exit /b 1
)

if not exist ".venv-build\Scripts\python.exe" (
    echo Creating build environment...
    py -3 -m venv .venv-build
    if errorlevel 1 goto :failed
)
call ".venv-build\Scripts\activate.bat"

python -m pip install --upgrade pip
if errorlevel 1 goto :failed
python -m pip install --upgrade pyinstaller PySide6 pywebview customtkinter
if errorlevel 1 goto :failed

if exist "build\WoL-Host" rmdir /s /q "build\WoL-Host"
if exist "build\WoL-Remote" rmdir /s /q "build\WoL-Remote"
if exist "dist\WoL-Host" rmdir /s /q "dist\WoL-Host"
if exist "dist\WoL-Remote" rmdir /s /q "dist\WoL-Remote"

 echo.
echo Building WoL Host...
python -m PyInstaller --noconfirm --clean --onedir --windowed --name WoL-Host --distpath dist --workpath build\WoL-Host --contents-directory _internal --collect-all PySide6 --collect-all shiboken6 --collect-all customtkinter --hidden-import PySide6.QtWebEngineCore --hidden-import PySide6.QtWebEngineWidgets --hidden-import PySide6.QtWebChannel --hidden-import PySide6.QtNetwork wol_host.py
if errorlevel 1 goto :failed

 echo.
echo Building WoL Remote...
python -m PyInstaller --noconfirm --clean --onedir --windowed --name WoL-Remote --distpath dist --workpath build\WoL-Remote --contents-directory _internal --collect-all webview --collect-all customtkinter --hidden-import webview.platforms.edgechromium wol_pc.py
if errorlevel 1 goto :failed

echo.
echo Build succeeded.
echo WoL Host:   dist\WoL-Host\WoL-Host.exe
echo WoL Remote: dist\WoL-Remote\WoL-Remote.exe
echo.
echo Copy each complete application folder, not only the .exe, when distributing.
echo Tailscale, Sunshine, Moonlight, and WebView2 are installed or supplied separately at runtime as appropriate.
exit /b 0

:failed
echo.
echo BUILD FAILED. Review the error above. The source files have not been changed.
exit /b 1
