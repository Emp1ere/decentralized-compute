@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
cd /d "%~dp0"
set NODE_SECRET=
set "PY_CMD="
set "VENV_DIR=.venv"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"

echo Starting Desktop Agent...
where py >nul 2>&1
if not errorlevel 1 set "PY_CMD=py -3"
where python >nul 2>&1
if "%PY_CMD%"=="" if not errorlevel 1 set "PY_CMD=python"
if not "%PY_CMD%"=="" goto ensure_venv

echo.
echo ERROR: Python was not found in PATH.
echo Install Python 3 and run again.
echo.
pause
exit /b 1

:ensure_venv
if exist "%VENV_PY%" goto install_deps
echo Creating local virtual environment...
%PY_CMD% -m venv "%VENV_DIR%"
if errorlevel 1 goto venv_failed

:install_deps
echo Checking Python SSL support...
"%VENV_PY%" -c "import ssl; print(ssl.OPENSSL_VERSION)" >nul 2>&1
if errorlevel 1 goto ssl_failed

echo Installing/updating dependencies...
"%VENV_PY%" -m pip install --upgrade pip wheel setuptools
if errorlevel 1 goto deps_failed
"%VENV_PY%" -m pip install -r requirements.txt
if errorlevel 1 goto deps_failed

echo Running Desktop Agent...
"%VENV_PY%" desktop_agent_app.py
if errorlevel 1 goto run_failed
goto done

:venv_failed
echo.
echo ERROR: failed to create virtual environment.
echo Try manually:
echo   %PY_CMD% -m venv .venv
echo.
pause
exit /b 1

:deps_failed
echo.
echo ERROR: dependency installation failed.
echo Try manually:
echo   "%VENV_PY%" -m pip install --upgrade pip wheel setuptools
echo   "%VENV_PY%" -m pip install -r requirements.txt
echo.
pause
exit /b 1

:ssl_failed
echo.
echo ERROR: Python SSL module is not available in this environment.
echo pip cannot download packages from HTTPS sources without SSL.
echo.
echo Recommended fix:
echo   1) Install/reinstall official Python 3.11+ from python.org
echo   2) During install enable:
echo      - "Add python.exe to PATH"
echo      - "Install launcher for all users (py.exe)"
echo   3) Reopen terminal and run start_desktop_agent.bat again
echo.
echo Quick check command:
echo   py -3 -c "import ssl; print(ssl.OPENSSL_VERSION)"
echo.
pause
exit /b 1

:run_failed
echo.
echo Desktop Agent stopped with error.
echo Check crash log file:
echo   desktop_agent_crash.log
echo.
pause
exit /b 1

:done
echo.
echo Desktop Agent finished.
pause
exit /b 0
