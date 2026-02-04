@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist "tests" (
    echo No tests folder. Run from orchestrator_node directory.
    exit /b 1
)
pip install -r requirements-test.txt -q 2>nul
python -m pytest tests/ -v --tb=short
exit /b %ERRORLEVEL%
