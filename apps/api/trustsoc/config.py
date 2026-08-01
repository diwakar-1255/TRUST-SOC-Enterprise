from functools import lru_cache
from typing import Annotated, Literal

from pydantic import AnyHttpUrl, EmailStr, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="TRUSTSOC_", extra="ignore")

    env: Literal["development", "test", "staging", "production"] = "development"
    domain: str = "localhost"
    log_level: str = "INFO"
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost"]
    )
    jwt_secret: str = Field(min_length=32)
    encryption_key: str = Field(min_length=32)
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    bootstrap_admin_email: EmailStr = "admin@example.com"
    bootstrap_admin_password: str = Field(min_length=12)
    bootstrap_org_name: str = "TRUST-SOC Lab"

    database_url: str = "postgresql+asyncpg://trustsoc:trustsoc@postgres:5432/trustsoc"
    redis_url: str = "redis://redis:6379/0"

    wazuh_enabled: bool = False
    wazuh_url: AnyHttpUrl = "https://host.docker.internal:55000"
    wazuh_username: str = "wazuh-wui"
    wazuh_password: str = ""
    wazuh_verify_tls: bool = False

    wazuh_indexer_url: AnyHttpUrl = "https://host.docker.internal:9200"
    wazuh_indexer_username: str = "admin"
    wazuh_indexer_password: str = ""
    wazuh_indexer_verify_tls: bool = False
    wazuh_alert_index: str = "wazuh-alerts-*"

    wazuh_sync_enabled: bool = True
    wazuh_sync_interval_seconds: int = Field(default=60, ge=30, le=3600)
    wazuh_alert_lookback_hours: int = Field(default=24, ge=1, le=720)
    wazuh_alert_batch_size: int = Field(default=500, ge=1, le=2000)

    honeypot_enabled: bool = False
    honeypot_api_url: AnyHttpUrl = "http://host.docker.internal:18000"
    honeypot_grafana_url: AnyHttpUrl = "https://52.237.90.251/grafana/"
    honeypot_verify_tls: bool = False
    honeypot_api_token: str = ""
    honeypot_api_token_header: str = "X-TRUSTSOC-Token"  # noqa: S105
    honeypot_sync_enabled: bool = True
    honeypot_sync_interval_seconds: int = Field(default=60, ge=30, le=3600)
    honeypot_event_batch_size: int = Field(default=250, ge=1, le=1000)
    honeypot_alert_batch_size: int = Field(default=250, ge=1, le=1000)
    honeypot_attacker_batch_size: int = Field(default=100, ge=1, le=1000)

    alert_aggregation_window_minutes: int = Field(default=15, ge=1, le=1440)
    auto_incident_enabled: bool = True
    auto_incident_min_rule_level: int = Field(default=12, ge=0, le=20)
    auto_incident_repetition_threshold: int = Field(default=10, ge=2, le=10000)
    incident_sla_critical_hours: int = Field(default=1, ge=1, le=168)
    incident_sla_high_hours: int = Field(default=4, ge=1, le=336)
    incident_sla_medium_hours: int = Field(default=24, ge=1, le=720)
    incident_sla_low_hours: int = Field(default=72, ge=1, le=2160)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_origins(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
