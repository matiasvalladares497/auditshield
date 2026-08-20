from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "AuditShield"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    SECRET_KEY: str = "change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://auditshield:auditshield_secret@localhost:5432/auditshield"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"

    # External APIs (optional)
    SHODAN_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    NVD_API_KEY: Optional[str] = None

    # Reports
    REPORTS_DIR: str = "/reports"
    TEMPLATES_DIR: str = "/reports/templates"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
