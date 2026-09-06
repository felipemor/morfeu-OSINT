@echo off
echo ============================================
echo  AI Pentest — Scanner Backend
echo  http://localhost:8000
echo  Docs: http://localhost:8000/docs
echo ============================================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERRO] Python nao encontrado!
    echo Instale em: https://python.org
    pause
    exit /b 1
)

cd /d "%~dp0scanner"

if not exist ".venv" (
    echo Criando ambiente virtual...
    python -m venv .venv
)

echo Ativando ambiente virtual...
call .venv\Scripts\activate.bat

echo Instalando dependencias...
pip install -r requirements.txt -q

echo.
echo Iniciando scanner backend...
python main.py
