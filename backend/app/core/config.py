"""
Core Configuration — all settings loaded from environment / .env
"""
from functools import lru_cache
from typing import Literal, Optional, List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, computed_field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    APP_NAME: str = "Heimdall Security Platform"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"

    # Security
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_use_openssl_rand_hex_32"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Admin bootstrap
    ADMIN_EMAIL: str = "admin@heimdall.security"
    ADMIN_PASSWORD: str = "changeme123!"
    ADMIN_FULL_NAME: str = "Platform Admin"

    # Database
    DATABASE_URL: Optional[str] = None
    DATABASE_URL_SYNC: Optional[str] = None
    INTERNAL_DATABASE_URL: Optional[str] = None
    EXTERNAL_DATABASE_URL: Optional[str] = None
    DB_HOST: Optional[str] = None
    DB_PORT: int = 5432
    DB_USER: Optional[str] = None
    DB_PASSWORD: Optional[str] = None
    DB_NAME: Optional[str] = None

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # CORS
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    # File storage
    SCREENSHOTS_DIR: str = "/data/screenshots"
    REPORTS_DIR: str = "/data/reports"

    # LLM (optional)
    LLM_PROVIDER: Literal["openai", "anthropic", "gemini", "ollama", "disabled"] = "disabled"
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    OLLAMA_BASE_URL: str = "http://ollama:11434"
    OLLAMA_MODEL: str = "llama3.2"

    # Rate limiting
    GLOBAL_RATE_LIMIT_PER_MINUTE: int = 60

    @computed_field
    @property
    def raw_db_url(self) -> str:
        """Resolves the raw database URL from various environment sources."""
        if self.DATABASE_URL:
            return self.DATABASE_URL
        if self.EXTERNAL_DATABASE_URL:
            return self.EXTERNAL_DATABASE_URL
        if self.INTERNAL_DATABASE_URL:
            return self.INTERNAL_DATABASE_URL
        if self.DB_HOST and self.DB_USER and self.DB_NAME:
            pwd = f":{self.DB_PASSWORD}" if self.DB_PASSWORD else ""
            return f"postgresql://{self.DB_USER}{pwd}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        return "postgresql://pentest:changeme_in_production@localhost:5432/pentest"

    @computed_field
    @property
    def async_database_url(self) -> str:
        """Converts any postgres:// or postgresql:// URL to postgresql+asyncpg:// format."""
        url = self.raw_db_url
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+asyncpg://", 1)
        elif url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif not url.startswith("postgresql+asyncpg://"):
            url = f"postgresql+asyncpg://{url.split('://', 1)[-1]}" if "://" in url else url
        
        # Strip ?sslmode=require from URL for asyncpg as it handles SSL in connect_args
        if "sslmode=" in url:
            base, *query = url.split("?", 1)
            query_params = [p for p in query[0].split("&") if not p.startswith("sslmode=")] if query else []
            url = f"{base}?{'&'.join(query_params)}" if query_params else base
        return url

    @computed_field
    @property
    def sync_database_url(self) -> str:
        """Returns standard postgresql:// URL for Alembic migrations and sync drivers."""
        if self.DATABASE_URL_SYNC:
            return self.DATABASE_URL_SYNC
        url = self.raw_db_url
        if url.startswith("postgresql+asyncpg://"):
            url = url.replace("postgresql+asyncpg://", "postgresql://", 1)
        elif url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        return url

    @computed_field
    @property
    def is_ssl_required(self) -> bool:
        """Detects if connection requires SSL (e.g. Render external PostgreSQL or sslmode query)."""
        raw = self.raw_db_url.lower()
        return "render.com" in raw or "sslmode=require" in raw or "ssl=true" in raw

    @computed_field
    @property
    def allowed_origins_list(self) -> List[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    @computed_field
    @property
    def llm_enabled(self) -> bool:
        return self.LLM_PROVIDER != "disabled"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
