@echo off
echo ============================================
echo  AI Autonomous Pentest Platform - Setup
echo ============================================
echo.

:: Check Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERRO] Node.js nao encontrado!
    echo.
    echo Instale o Node.js em: https://nodejs.org
    echo Baixe a versao LTS, instale, feche e reabra este terminal.
    echo.
    pause
    exit /b 1
)

echo [OK] Node.js encontrado: 
node --version

echo.
echo Instalando dependencias...
cd /d "%~dp0frontend"
call npm install

echo.
echo ============================================
echo  Iniciando servidor de desenvolvimento...
echo  Acesse: http://localhost:3000
echo  Login: qualquer email + qualquer senha
echo ============================================
echo.
call npm run dev
