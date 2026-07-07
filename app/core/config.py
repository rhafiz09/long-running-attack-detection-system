import os
from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

# Load environment variables from .env file using python-dotenv
load_dotenv()


class Settings(BaseSettings):
    """
    Application Core Configuration Settings.
    Strictly typed configuration loaded from environment variables and .env file.
    """
    PROJECT_NAME: str = "Cybersecurity Log Monitoring Pipeline API"
    API_V1_STR: str = "/api"
    DEBUG: bool = True

    # Database Configuration
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/security_logs"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()
