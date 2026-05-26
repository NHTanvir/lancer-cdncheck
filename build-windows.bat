@echo off
REM Windows release build for lancer-cdncheck.
REM Output: dist\lancer-cdncheck-windows-x86_64\bin\lancer-cdncheck.exe

echo === Building lancer-cdncheck (release) for Windows x86_64 ===
cargo build --release
if errorlevel 1 exit /b 1

echo === Packaging ===
set DIST=dist\lancer-cdncheck-windows-x86_64
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"
mkdir "%DIST%\bin"

copy target\release\lancer-cdncheck.exe "%DIST%\bin\" >nul
copy LICENSE "%DIST%\" >nul 2>nul
copy README.md "%DIST%\" >nul 2>nul

echo === Done. Binary: %DIST%\bin ===
dir "%DIST%\bin"
exit /b 0
