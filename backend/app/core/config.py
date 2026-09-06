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
    APP_NAME: str = "AI Autonomous Pentest Platform"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"

    # Security
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_use_openssl_rand_hex_32"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Admin bootstrap
    ADMIN_EMAIL: str = "admin@pentest.local"
    ADMIN_PASSWORD: str = "changeme123!"
    ADMIN_FULL_NAME: str = "Platform Admin"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://pentest:changeme_in_production@localhost:5432/pentest"
    DATABASE_URL_SYNC: str = "postgresql://pentest:changeme_in_production@localhost:5432/pentest"

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
