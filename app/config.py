from pathlib import Path
from dataclasses import dataclass
import os

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class Settings:
    cowrie_json_path: str
    offset_path: str

    model_path: str
    imputer_path: str
    feature_columns_path: str
    threshold_path: str

    db_host: str
    db_port: int
    db_name: str
    db_user: str
    db_password: str

    poll_interval_seconds: int
    store_only_anomalies: bool

    geolocation_enabled: bool
    geolocation_url: str
    geolocation_timeout_seconds: int


def get_settings() -> Settings:
    return Settings(
        cowrie_json_path=os.getenv(
            "COWRIE_JSON_PATH",
            "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
        ),
        offset_path=os.getenv(
            "OFFSET_PATH",
            str(BASE_DIR / "cowrie_offset.json"),
        ),

        model_path=os.getenv(
            "MODEL_PATH",
            str(BASE_DIR / "models" / "isolation_forest_model.pkl"),
        ),
        imputer_path=os.getenv(
            "IMPUTER_PATH",
            str(BASE_DIR / "models" / "simple_imputer.pkl"),
        ),
        feature_columns_path=os.getenv(
            "FEATURE_COLUMNS_PATH",
            str(BASE_DIR / "models" / "feature_columns.pkl"),
        ),
        threshold_path=os.getenv(
            "THRESHOLD_PATH",
            str(BASE_DIR / "models" / "threshold_anomaly_score.pkl"),
        ),

        db_host=os.getenv("DB_HOST", "127.0.0.1"),
        db_port=int(os.getenv("DB_PORT", "3306")),
        db_name=os.getenv("DB_NAME", ""),
        db_user=os.getenv("DB_USER", ""),
        db_password=os.getenv("DB_PASSWORD", ""),

        poll_interval_seconds=int(os.getenv("POLL_INTERVAL_SECONDS", "10")),
        store_only_anomalies=_bool_env("STORE_ONLY_ANOMALIES", False),

        geolocation_enabled=_bool_env("GEOLOCATION_ENABLED", True),
        geolocation_url=os.getenv("GEOLOCATION_URL", "http://ip-api.com/json"),
        geolocation_timeout_seconds=int(os.getenv("GEOLOCATION_TIMEOUT_SECONDS", "5")),
    )