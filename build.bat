@echo off
setlocal
cd /d "%~dp0"

set MSBUILD=
if exist "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" (
  set "MSBUILD=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
) else if exist "%WINDIR%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" (
  set "MSBUILD=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
)

if "%MSBUILD%"=="" (
  echo [ERROR] 未找到 .NET Framework 4.0 MSBuild。
  echo 请安装 .NET Framework 4.0/4.5+ 开发包或完整框架。
  exit /b 1
)

echo Using: %MSBUILD%
"%MSBUILD%" "%~dp0LanShareDiag.sln" /t:Rebuild /p:Configuration=Release /p:Platform="Any CPU" /v:minimal
if errorlevel 1 (
  echo Build failed.
  exit /b 1
)

echo.
echo OK: LanShareDiag\bin\Release\LanShareDiag.exe
explorer "%~dp0LanShareDiag\bin\Release"
endlocal
