@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "NODE_SECRET_INPUT="

if /I "%~1"=="--generate" goto generate_secret
if "%~1"=="" goto ask_secret
set "NODE_SECRET_INPUT=%~1"
goto validate_secret

:ask_secret
set /p NODE_SECRET_INPUT=Enter NODE_SECRET value (minimum 24 chars recommended): 
goto validate_secret

:generate_secret
set "NODE_SECRET_INPUT=%RANDOM%%RANDOM%%RANDOM%%RANDOM%%RANDOM%%RANDOM%%RANDOM%%RANDOM%%RANDOM%%RANDOM%%RANDOM%%RANDOM%%RANDOM%%RANDOM%%RANDOM%%RANDOM%"
goto validate_secret

:validate_secret
if "%NODE_SECRET_INPUT%"=="" goto usage

setx NODE_SECRET "%NODE_SECRET_INPUT%" >nul
if errorlevel 1 goto save_failed

set "NODE_SECRET=%NODE_SECRET_INPUT%"
echo.
echo NODE_SECRET saved for current user profile.
echo Current cmd session is updated too.
echo.
echo Next steps:
echo   1) Reopen terminal if you run commands from another window
echo   2) Run start.bat or rebuild.bat
echo.
pause
exit /b 0

:usage
echo.
echo ERROR: NODE_SECRET is empty.
echo Usage:
echo   setup_node_secret.bat --generate
echo   setup_node_secret.bat your_long_random_secret
echo.
pause
exit /b 1

:save_failed
echo.
echo ERROR: failed to save NODE_SECRET via setx.
echo Try running this script as your normal user session (not restricted shell).
echo.
pause
exit /b 1
