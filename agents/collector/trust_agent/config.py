from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="agent.env", env_prefix="TRUSTSOC_AGENT_", extra="ignore"
    )
    api_url: str = "http://localhost/api"
    source_id: str
    shared_secret: str
    source_type: str = "linux"
    heartbeat_seconds: int = 60
    verify_tls: bool = True
    spool_path: Path = Path("./runtime/spool.jsonl")
    state_path: Path = Path("./runtime/state.json")
