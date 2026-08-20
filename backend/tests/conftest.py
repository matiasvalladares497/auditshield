# conftest.py — Configuración de pytest para AuditShield

import pytest
import asyncio
import os

# Configurar variables de entorno para tests
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-testing-only")
os.environ.setdefault("ALGORITHM", "HS256")
os.environ.setdefault("ENVIRONMENT", "testing")


@pytest.fixture(scope="session")
def event_loop():
    """Event loop compartido para tests asíncronos."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
