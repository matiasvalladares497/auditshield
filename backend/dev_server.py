"""
AuditShield - Backend de Desarrollo Local (sin Docker)
Usa SQLite + ejecución directa de tareas (sin Redis/Celery).
Perfectamente funcional para desarrollo y pruebas locales.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import logging
import os

# Override DATABASE_URL to use SQLite for local dev
if not os.getenv("DATABASE_URL"):
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./auditshield_dev.db"
if not os.getenv("REDIS_URL"):
    os.environ["REDIS_URL"] = "redis://localhost:6379/0"
if not os.getenv("SECRET_KEY"):
    os.environ["SECRET_KEY"] = "dev-secret-key-change-in-production-2026"

from app.core.database import engine, Base
from app.api import auth, audits, assets, reports, users, websocket
from app.core.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 AuditShield API iniciando...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Base de datos lista")
    logger.info("🌐 API disponible en: http://localhost:8000")
    logger.info("📚 Documentación en: http://localhost:8000/docs")
    yield
    logger.info("🛑 AuditShield API detenida.")


app = FastAPI(
    title="AuditShield API",
    description="Plataforma Profesional de Auditoría de Ciberseguridad",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir rutas
app.include_router(auth.router, prefix="/api/auth", tags=["Autenticación"])
app.include_router(users.router, prefix="/api/users", tags=["Usuarios"])
app.include_router(audits.router, prefix="/api/audits", tags=["Auditorías"])
app.include_router(assets.router, prefix="/api/assets", tags=["Activos"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reportes"])
app.include_router(websocket.router, prefix="/ws", tags=["WebSocket"])


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "AuditShield API",
        "version": "1.0.0",
        "mode": "development"
    }


@app.get("/")
async def root():
    return {
        "message": "AuditShield API corriendo correctamente",
        "docs": "http://localhost:8000/docs",
        "health": "http://localhost:8000/health"
    }
