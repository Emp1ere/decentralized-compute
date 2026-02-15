@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
cd /d "%~dp0"
set NODE_SECRET=

echo Starting Desktop Agent...
where py >nul 2>&1
if not errorlevel 1 goto run_with_py
where python >nul 2>&1
if not errorlevel 1 goto run_with_python

echo.
echo ERROR: Python was not found in PATH.
echo Install Python 3 and run again.
echo.
pause
exit /b 1

:run_with_py
py -3 desktop_agent_app.py
if errorlevel 1 goto run_failed
goto done

:run_with_python
python desktop_agent_app.py
if errorlevel 1 goto run_failed
goto done

:run_failed
echo.
echo Desktop Agent stopped with error.
echo Check dependency installation:
echo   py -3 -m pip install -r requirements.txt
echo or:
echo   python -m pip install -r requirements.txt
echo.
pause
exit /b 1

:done
echo.
echo Desktop Agent finished.
pause
exit /b 0
