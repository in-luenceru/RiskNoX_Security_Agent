"""
Application settings using Pydantic Settings
"""

from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""
    
    # Basic settings
    DEBUG: bool = Field(default=False, description="Enable debug mode")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    ALLOWED_HOSTS: List[str] = Field(default=["*"], description="Allowed host headers")
    
    model_config = {
        # Ignore extra fields from environment (old Flask settings)
        "extra": "ignore",
        "env_file": ".env"
    }
    
    # Database settings
    DATABASE_URL: str = Field(
        default="postgresql://manager:password@localhost:5432/manager",
        description="PostgreSQL database URL"
    )
    DATABASE_POOL_SIZE: int = Field(default=20, description="Database connection pool size")
    DATABASE_ECHO: bool = Field(default=False, description="Echo SQL queries")
    
    # Redis settings
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis URL for caching and sessions"
    )
    
    # Celery settings
    CELERY_BROKER_URL: str = Field(
        default="redis://localhost:6379/1", 
        description="Celery broker URL"
    )
    CELERY_RESULT_BACKEND: str = Field(
        default="redis://localhost:6379/2",
        description="Celery result backend URL"
    )
    
    # S3/MinIO settings
    S3_ENDPOINT: str = Field(
        default="http://localhost:9000",
        description="S3 compatible storage endpoint"
    )
    S3_ACCESS_KEY: str = Field(
        default="dev_access_key",
        description="S3 access key"
    )
    S3_SECRET_KEY: str = Field(
        default="dev_secret_key",
        description="S3 secret key"
    )
    S3_BUCKET: str = Field(
        default="risknox-manager",
        description="S3 bucket name for artifacts"
    )
    S3_REGION: str = Field(default="us-east-1", description="S3 region")
    
    # Security settings
    JWT_SECRET_KEY: str = Field(
        default="dev_jwt_secret_key_change_in_production",
        description="JWT secret key for token signing"
    )
    JWT_ALGORITHM: str = Field(default="HS256", description="JWT signing algorithm")
    JWT_EXPIRE_MINUTES: int = Field(default=480, description="JWT token expiration (minutes)")
    
    # Certificate Authority settings
    CA_PRIVATE_KEY_PATH: Optional[str] = Field(
        default=None,
        description="Path to CA private key for signing agent certificates"
    )
    CA_CERTIFICATE_PATH: Optional[str] = Field(
        default=None,
        description="Path to CA certificate for agent verification"
    )
    CA_KEY_PASSWORD: Optional[str] = Field(
        default=None,
        description="CA private key password"
    )
    CERT_VALIDITY_DAYS: int = Field(
        default=90,
        description="Agent certificate validity period (days)"
    )
    
    # WebSocket settings
    WS_MAX_CONNECTIONS: int = Field(
        default=10000,
        description="Maximum concurrent WebSocket connections"
    )
    WS_HEARTBEAT_INTERVAL: int = Field(
        default=30,
        description="WebSocket heartbeat interval (seconds)"
    )
    WS_CONNECTION_TIMEOUT: int = Field(
        default=300,
        description="WebSocket connection timeout (seconds)"
    )
    
    # Command settings
    COMMAND_TTL_SECONDS: int = Field(
        default=3600,
        description="Command time-to-live (seconds)"
    )
    COMMAND_MAX_RETRIES: int = Field(
        default=3,
        description="Maximum command delivery retries"
    )
    
    # Monitoring settings
    PROMETHEUS_ENABLED: bool = Field(
        default=True,
        description="Enable Prometheus metrics"
    )
    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[str] = Field(
        default=None,
        description="OpenTelemetry OTLP exporter endpoint"
    )
    
    # Admin UI settings
    ADMIN_UI_URL: str = Field(
        default="http://localhost:3000",
        description="Admin UI URL for CORS"
    )
    



# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get application settings (singleton)"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings