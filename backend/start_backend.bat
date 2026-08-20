@echo off
echo.
echo =============================================
echo    AuditShield Backend - Inicio Local
echo =============================================
echo.

cd /d "%~dp0"

:: Verificar si el entorno virtual existe
if not exist "venv\Scripts\activate.bat" (
    echo [INFO] Creando entorno virtual Python...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] No se pudo crear el entorno virtual. Asegurate de tener Python 3.10+
        pause
        exit /b 1
    )
    echo [OK] Entorno virtual creado.
)

:: Activar entorno virtual
call venv\Scripts\activate.bat

:: Instalar dependencias si es necesario
echo [INFO] Verificando dependencias...
pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo [INFO] Instalando dependencias (primera vez)...
    pip install -r requirements-dev.txt -q
    if errorlevel 1 (
        echo [ERROR] Fallo al instalar dependencias.
        pause
        exit /b 1
    )
    echo [OK] Dependencias instaladas.
) else (
    echo [OK] Dependencias ya instaladas.
)

:: Configurar variables de entorno para desarrollo local (SQLite)
set DATABASE_URL=sqlite+aiosqlite:///./auditshield_dev.db
set REDIS_URL=redis://localhost:6379/0
set SECRET_KEY=dev-auditshield-secret-key-2026
set ENVIRONMENT=development

echo.
echo [INFO] Iniciando AuditShield API...
echo [INFO] Base de datos: SQLite (auditshield_dev.db)
echo [INFO] API disponible en: http://localhost:8000
echo [INFO] Documentacion: http://localhost:8000/docs
echo.

:: Iniciar servidor
python -m uvicorn dev_server:app --host 0.0.0.0 --port 8000 --reload

pause
