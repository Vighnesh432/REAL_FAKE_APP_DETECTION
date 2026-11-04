import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]


class Settings:
    APP_NAME = "Real-Time Fake App Detection System"
    VERSION = "1.0.0"

    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-change-me-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("TOKEN_EXPIRE_MINUTES", "720"))

    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'app.db'}")

    CORS_ORIGINS: list[str] = os.getenv(
        "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")

    DATASET_PATH: str = os.getenv("DATASET_PATH", str(BASE_DIR / "data" / "apps_dataset.csv"))
    MODEL_DIR: Path = BASE_DIR / "models_store"

    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "admin@appxray.io")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "admin12345")

    MAX_BATCH_SIZE: int = 500


settings = Settings()
