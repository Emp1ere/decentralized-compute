@echo off
chcp 65001 >nul
cd /d "%~dp0orchestrator_node"
if not exist "tests" (
    echo orchestrator_node/tests not found.
    pause
    exit /b 1
)

rem На Windows лучше использовать лаунчер py; если его нет — python
where py >nul 2>nul && set PY=py || set PY=python

echo Installing test dependencies...
%PY% -m pip install -r requirements-test.txt -q 2>nul

echo.
echo Running tests...
%PY% -m pytest tests/ -v --tb=short

echo.
pause
exit /b %ERRORLEVEL%
