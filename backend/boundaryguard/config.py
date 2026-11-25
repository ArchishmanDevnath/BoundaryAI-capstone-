"""Runtime settings, read from environment variables and an optional backend/.env file."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
BENCHMARK_DIR = BACKEND_ROOT / "benchmark"
DATA_DIR = BACKEND_ROOT.parent / "data"
MODELS_DIR = BACKEND_ROOT / "models"


def _load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


@dataclass(frozen=True)
class Settings:
    db_path: str
    runs_dir: str
    frontend_origin: str
    ollama_url: str
    ollama_model: str
    openai_base_url: str
    openai_api_key: str
    openai_model: str
    agent_timeout_s: float
    assessor_timeout_s: float
    approval_timeout_s: float
    allowed_hosts: tuple[str, ...]
    model_dir: str = str(MODELS_DIR)
    ml_timeout_s: float = 2.0


def load_settings(**overrides) -> Settings:
    file_values = _load_dotenv(BACKEND_ROOT / ".env")

    def get(name: str, default: str) -> str:
        return os.environ.get(name, file_values.get(name, default))

    var = BACKEND_ROOT / "var"
    values = dict(
        db_path=get("BG_DB_PATH", str(var / "boundaryguard.sqlite3")),
        runs_dir=get("BG_RUNS_DIR", str(var / "runs")),
        frontend_origin=get("BG_FRONTEND_ORIGIN", "http://localhost:3000"),
        ollama_url=get("BG_OLLAMA_URL", "http://127.0.0.1:11434"),
        ollama_model=get("BG_OLLAMA_MODEL", "qwen2.5:7b"),
        openai_base_url=get("BG_OPENAI_BASE_URL", ""),
        openai_api_key=get("BG_OPENAI_API_KEY", ""),
        openai_model=get("BG_OPENAI_MODEL", ""),
        agent_timeout_s=float(get("BG_AGENT_TIMEOUT", "300")),
        assessor_timeout_s=float(get("BG_ASSESSOR_TIMEOUT", "60")),
        approval_timeout_s=float(get("BG_APPROVAL_TIMEOUT", "300")),
        model_dir=get("BG_MODEL_DIR", str(MODELS_DIR)),
        ml_timeout_s=float(get("BG_ML_TIMEOUT", "2")),
        allowed_hosts=tuple(
            h.strip() for h in get("BG_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",") if h.strip()
        ),
    )
    values.update(overrides)
    return Settings(**values)
