from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_KIT_PATH = (
    PROJECT_ROOT
    / "sde-startup-kit-20261118T102601Z-1-001"
    / "sde-startup-kit"
    / "dependency-watch-starter-kit"
    / "dependency-watch-starter-kit"
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    kit_path: Path = DEFAULT_KIT_PATH
    feed_url: str = "http://localhost:7100"
    webhook_url: str = "http://localhost:9900"
    database_url: str = f"sqlite:///{(PROJECT_ROOT / 'dependency-watch.db').as_posix()}"


settings = Settings()
