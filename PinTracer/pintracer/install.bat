@echo off

REM ======================================
REM BATCH FILES SUCK...
REM ======================================

echo ==================================================
echo This crappy batch script will try to help you
echo installing the PinTracer tool (part of JARVIS)
echo You will need Python 2.7.9+ and Intel PIN 2.14+
echo -
echo If you already have PySide installed you can completely
echo skip this step and go ahead
echo ==================================================

set /p python_dir= Python 2.7.9+ installation dir? (ex: C:\Python27):

REM Install and prepare the Virtual Environment
%python_dir%\Scripts\pip.exe install virtualenv
mkdir .\JARVISVE
cd .\JARVISVE
%python_dir%\Scripts\virtualenv.exe venv
call venv\Scripts\activate

REM We are inside the virtualenv now (hopefully)
pip install PySide
pip install psutil

echo ================================================
echo PySide should be installed within a virtualenv
echo inside .\JARVISVE

call venv\Scripts\deactivate
cd..
