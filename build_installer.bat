@echo off
rem Builds DD Cleaner end to end: PyInstaller (portable dist\DD_Cleaner) then Inno Setup (the .exe installer).
rem Run from a normal (non-admin) prompt with the venv/Python on PATH; Inno Setup itself needs no elevation
rem to compile a script, only to later RUN the resulting installer.

setlocal
cd /d "%~dp0"

echo [1/2] PyInstaller build (DD_Cleaner.spec)...
python -m PyInstaller DD_Cleaner.spec --noconfirm
if errorlevel 1 goto :fail

echo.
echo [2/2] Inno Setup installer (DD_Cleaner.iss)...
set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
    echo Inno Setup not found. Install it from https://jrsoftware.org/isdl.php and rerun this script,
    echo or compile DD_Cleaner.iss yourself ^(File ^> Compile in the Inno Setup IDE^).
    goto :fail
)
"%ISCC%" DD_Cleaner.iss
if errorlevel 1 goto :fail

echo.
echo Done: dist_installer\DD_Cleaner_Setup_*.exe
exit /b 0

:fail
echo.
echo Build failed.
exit /b 1
