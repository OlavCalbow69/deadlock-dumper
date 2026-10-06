@echo off
setlocal
cd /d "%~dp0"
if defined VCINSTALLDIR goto compile
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%I"
)
if defined VSROOT goto setup
if exist "%ProgramFiles%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" set "VSROOT=%ProgramFiles%\Microsoft Visual Studio\18\Community"
if not defined VSROOT (
    echo Visual Studio C++ build tools were not found.
    echo Install the Desktop development with C++ workload, or use an x64 Native Tools command prompt.
    exit /b 1
)
:setup
call "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
:compile
cl /nologo /std:c++17 /EHsc /O2 /MT /utf-8 /W3 /Fe:"DeadlockDumper.exe" "DeadlockDumper.cpp" advapi32.lib /link /INCREMENTAL:NO /MANIFEST:EMBED /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'"
exit /b %errorlevel%
