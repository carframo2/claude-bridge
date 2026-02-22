import os
from dataclasses import dataclass
from typing import Set

def _set_from_env(name: str) -> Set[str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return set()
    return set(x.strip() for x in raw.split(",") if x.strip())

@dataclass(frozen=True)
class Settings:
    DEFAULT_PROVIDER: str = os.environ.get("DEFAULT_PROVIDER", "groq").strip().lower()
    DEFAULT_MODEL: str = os.environ.get("DEFAULT_MODEL", "llama-3.3-70b-versatile").strip()
    DEFAULT_TEMPERATURE: float = float(os.environ.get("DEFAULT_TEMPERATURE", "0.2"))
    DEFAULT_MAX_TOKENS: int = int(os.environ.get("DEFAULT_MAX_TOKENS", "600"))
    MAX_CONTEXT_CHARS: int = int(os.environ.get("MAX_CONTEXT_CHARS", "20000"))

    BRIDGE_TOKEN: str = os.environ.get("BRIDGE_TOKEN", "").strip()
    RATE_LIMIT_PER_MIN: int = int(os.environ.get("RATE_LIMIT_PER_MIN", "60"))

    ALLOWED_MODELS_GROQ: Set[str] = _set_from_env("ALLOWED_MODELS_GROQ")
    ALLOWED_MODELS_OPENAI: Set[str] = _set_from_env("ALLOWED_MODELS_OPENAI")

    # GitHub uploads (releases assets)
    GH_OWNER: str = os.environ.get("GH_OWNER", "").strip()
    GH_REPO: str = os.environ.get("GH_REPO", "").strip()
    GITHUB_TOKEN: str = os.environ.get("GITHUB_TOKEN", "").strip()
    UPLOAD_SECRET: str = os.environ.get("UPLOAD_SECRET", "").strip()  # opcional, si no, usa BRIDGE_TOKEN
