@echo off
title morfeusec OSINT — Plataforma Autonomous Pentest
color 0A

echo =========================================================================
echo               🛡️ MORFEUSEC OSINT — AUTONOMOUS PENTEST PLATFORM
echo =========================================================================
echo.
echo [1/4] Verificando requisitos do sistema...

:: Check Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERRO CRITICO] Node.js nao foi encontrado!
    echo Por favor, instale o Node.js LTS em: https://nodejs.org
    echo.
    pause
    exit /b 1
)

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERRO CRITICO] Python nao foi encontrado!
    echo Por favor, instale o Python 3.10+ em: https://python.org
    echo.
    pause
    exit /b 1
)

echo [OK] Node.js: 
node --version
echo [OK] Python:
python --version
echo.

:: -------------------------------------------------------------------------
:: [2/4] Preparar Backend & Scanner
:: -------------------------------------------------------------------------
echo [2/4] Verificando ambiente Python do Scanner Backend (Porta 8000)...
cd /d "%~dp0scanner"

if not exist ".venv" (
    echo [INFO] Criando ambiente virtual Python (.venv)...
    python -m venv .venv
)

call .venv\Scripts\activate.bat

if exist "requirements.txt" (
    echo [INFO] Verificando dependencias do Python...
    pip install -r requirements.txt -q
)

cd /d "%~dp0"

echo.
echo [INFO] Iniciando Scanner Backend em segundo plano (http://localhost:8000)...
start "morfeusec Scanner Backend (Porta 8000)" cmd /k "cd /d "%~dp0scanner" && call .venv\Scripts\activate.bat && python main.py"

:: -------------------------------------------------------------------------
:: [3/4] Preparar Frontend Next.js
:: -------------------------------------------------------------------------
echo.
echo [3/4] Preparando Frontend Next.js (Porta 3000)...
cd /d "%~dp0frontend"

if not exist "node_modules" (
    echo [INFO] Primeira execucao detectada. Instalando pacotes npm...
    call npm install
)

:: -------------------------------------------------------------------------
:: [4/4] Abrir Navegador & Subir Frontend
:: -------------------------------------------------------------------------
echo.
echo [4/4] Aguardando boot dos servidores (5 segundos)...
timeout /t 5 /nobreak >nul

echo Abrindo navegador em http://localhost:3000...
start "" "http://localhost:3000"

echo.
echo =========================================================================
echo 🚀 APLICACAO INICIADA COM SUCESSO!
echo -------------------------------------------------------------------------
echo  Frontend UI : http://localhost:3000
echo  Backend API : http://localhost:8000
echo  Swagger Docs: http://localhost:8000/docs
echo =========================================================================
echo.
echo Pressione Ctrl + C no terminal para encerrar o frontend.
echo.

call npm run dev

pause
