@echo off
start cmd /k "cd /d ^"%~dp0^" & call ^"%~dp0run_fabric_setup_wsl.bat^" _run"
