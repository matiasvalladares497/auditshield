@echo off
echo ===================================================
echo   AuditShield - Subir Proyecto a GitHub
echo ===================================================
echo.
echo [INFO] Conectando repositorio con matiasvalladares497/auditshield...
git remote set-url origin https://github.com/matiasvalladares497/auditshield.git
git branch -M main

echo [INFO] Subiendo codigo y render.yaml a GitHub...
git push -u origin main

if errorlevel 1 (
    echo.
    echo [ERROR] No se pudo subir. Asegurate de tener conexion a internet y permisos en GitHub.
) else (
    echo.
    echo ===================================================
    echo  [EXITO] Proyecto subido a GitHub correctamente!
    echo ===================================================
)

pause
