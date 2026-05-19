from pydantic_settings import BaseSettings
from typing import Literal


class Settings(BaseSettings):
    app_name: str = "ReconOps"
    app_version: str = "1.0.0"
    environment: Literal["development", "production"] = "development"
    log_level: str = "INFO"

    max_concurrent_scans: int = 3
    scan_timeout_seconds: int = 300
    allowed_targets: str = "" 

    reports_dir: str = "./reports"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
