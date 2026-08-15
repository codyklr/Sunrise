@echo off
setlocal

set "VSDEVCMD=D:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
if not exist "%VSDEVCMD%" (
    echo Visual Studio Developer Command Prompt setup was not found:
    echo %VSDEVCMD%
    exit /b 1
)

call "%VSDEVCMD%" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b %errorlevel%

set "CL_MPCount=1"
msbuild "%~dp0Sunrise.sln" /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143
if errorlevel 1 exit /b %errorlevel%

copy /Y "%~dp0build\x64\Release\steam_api64.dll" "E:\Gaming\Games\Sunrise_Destiny2\bin\x64\steam_api64.dll"
if errorlevel 1 exit /b %errorlevel%

echo.
echo Build and deployment succeeded.
endlocal
