"""
Nexus AI — Configuration & Settings
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import List


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False
    )

    # Security
    secret_key: str = Field(default="dev-secret-key", alias="SECRET_KEY")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440

    # CORS
    cors_origins: str = Field(default="*", alias="CORS_ORIGINS")

    # Server
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8001, alias="PORT")

    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./nexus_ai.db",
        alias="DATABASE_URL"
    )

    # Vector DB
    chroma_db_path: str = Field(default="./chroma_db", alias="CHROMA_DB_PATH")

    # Embeddings
    embedding_model: str = Field(default="all-MiniLM-L6-v2", alias="EMBEDDING_MODEL")

    # AI Model
    anomaly_threshold: float = Field(default=0.75, alias="ANOMALY_THRESHOLD")

    def get_cors_origins(self) -> List[str]:
        if self.cors_origins == "*":
            return ["*"]
        return [origin.strip() for origin in self.cors_origins.split(",")]


settings = Settings()
