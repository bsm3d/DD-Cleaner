@echo off
REM DD Cleaner
REM ?? Benoit Saint-Moulin - 2026
REM Version du fichier : 1.0.0
REM Fonction du fichier : Builds DD Cleaner 1.0.0 with MSYS2 and CMake in Release mode, then runs Inno Setup to produce the installer.

rem Builds DD Cleaner 1.0.0 (C++): Release build with MSYS2 + CMake, then the Inno Setup installer.
rem The installer lands in D:\Documents\Coding\distributions\DD-Cleaner, or in %BSM_DISTRIBUTIONS%\DD-Cleaner (see DD_Cleaner.iss).

setlocal
cd /d "%~dp0"
set "PATH=C:\msys64\ucrt64\bin;C:\Program Files\CMake\bin;%PATH%"

echo [1/2] Release build...
cmake -S . -B build\release -G Ninja -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 goto :fail
cmake --build build\release --target DD_Cleaner ddc
if errorlevel 1 goto :fail

echo.
echo [2/2] Inno Setup installer...
set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
    echo Inno Setup not found. Install it from https://jrsoftware.org/isdl.php
    goto :fail
)
"%ISCC%" DD_Cleaner.iss
if errorlevel 1 goto :fail

echo.
if defined BSM_DISTRIBUTIONS (
    echo Done: %BSM_DISTRIBUTIONS%\DD-Cleaner\DD_Cleaner_Setup_1.0.0.exe
) else (
    echo Done: D:\Documents\Coding\distributions\DD-Cleaner\DD_Cleaner_Setup_1.0.0.exe
)
exit /b 0

:fail
echo.
echo Build failed.
exit /b 1
