@echo off
chcp 65001 >nul
cd /d "%~dp0orchestrator_node"
if not exist "tests" (
    echo orchestrator_node/tests not found.
    exit /b 1
)
pip install -r requirements-test.txt -q 2>nul
python -m pytest tests/ -v --tb=short
exit /b %ERRORLEVEL%
