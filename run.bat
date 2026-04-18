@echo off
setlocal

REM Run the project with the local virtual environment.
set SCRIPT_DIR=%~dp0
"%SCRIPT_DIR%.venv\Scripts\python.exe" "%SCRIPT_DIR%main.py" %*
