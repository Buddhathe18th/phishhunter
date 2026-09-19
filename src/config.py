"""Settings from the environment (and a local .env). Secrets are excluded from repr so they can't leak into logs."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    return default if raw is None else raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, lo: int, hi: int) -> int:
    value = int(os.getenv(name, str(default)))
    if not lo <= value <= hi:
        raise ValueError(f"{name} must be between {lo} and {hi}")
    return value


def _csv(name: str, default: str) -> frozenset[str]:
    return frozenset(p.strip().lower() for p in os.getenv(name, default).split(",") if p.strip())


def _url(name: str) -> str | None:
    """A service URL from the environment. https only (http allowed for localhost), no inline credentials."""
    raw = os.getenv(name, "").strip().rstrip("/")
    if not raw:
        return None
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{name} must be an http(s) URL")
    if parsed.scheme == "http" and parsed.hostname not in LOOPBACK:
        raise ValueError(f"{name} must use https (plain http is only allowed for localhost)")
    if parsed.username or parsed.password:
        raise ValueError(f"{name} must not contain credentials; use an API key variable instead")
    return raw


def _secret(name: str) -> str | None:
    return os.getenv(name, "").strip() or None


@dataclass(frozen=True)
class Settings:
    demo: bool = False
    threshold: int = 40
    # --- API security ---
    api_token: str = field(default="", repr=False)
    token_generated: bool = False
    allowed_hosts: frozenset[str] = frozenset({"localhost", "127.0.0.1"})
    allowed_origins: frozenset[str] = frozenset()
    enable_docs: bool = False
    rate_limit_per_min: int = 120
    heavy_rate_limit_per_min: int = 10
    # --- Elastic ---
    elastic_url: str | None = None
    elastic_api_key: str | None = field(default=None, repr=False)
    elastic_ca_certs: str | None = None
    kibana_url: str | None = None
    kibana_api_key: str | None = field(default=None, repr=False)
    jina_api_key: str | None = field(default=None, repr=False)
    embed_inference_id: str = "doppel-jina-embed"
    rerank_inference_id: str = "doppel-jina-rerank"
    semantic: bool = False          # hybrid BM25 + Jina vectors + rerank (needs inference endpoints)
    agent_id: str = "doppel-analyst"
    # --- agent behaviour ---
    auto_investigate: bool = True
    investigate_score: int = 60
    triage_fetch: bool = False      # fetching suspect pages is opt-in
    auto_actions: bool = False      # agent-proposed actions run without a human only when this is on
    auto_score: int = 85
    webhook_url: str | None = field(default=None, repr=False)
    outbox_dir: str = "outbox"
    # --- optional integrations (all no-ops when unset) ---
    gemini_api_key: str | None = field(default=None, repr=False)
    gemini_model: str = "gemini-3.6-flash"
    sentry_dsn: str | None = field(default=None, repr=False)


def load() -> Settings:
    token = _secret("API_TOKEN")
    generated = False
    if token is None:
        token, generated = secrets.token_urlsafe(32), True
    elif len(token) < 24:
        raise ValueError("API_TOKEN must be at least 24 characters "
                         "(try: python -c \"import secrets;print(secrets.token_urlsafe(32))\")")

    jina = _secret("JINA_API_KEY")
    return Settings(
        demo=_bool("DEMO"),
        threshold=_int("THRESHOLD", 40, 1, 100),
        api_token=token,
        token_generated=generated,
        allowed_hosts=_csv("ALLOWED_HOSTS", "localhost,127.0.0.1"),
        allowed_origins=_csv("ALLOWED_ORIGINS", ""),
        enable_docs=_bool("ENABLE_DOCS"),
        rate_limit_per_min=_int("RATE_LIMIT_PER_MIN", 120, 1, 100_000),
        heavy_rate_limit_per_min=_int("HEAVY_RATE_LIMIT_PER_MIN", 10, 1, 10_000),
        elastic_url=_url("ELASTIC_URL"),
        elastic_api_key=_secret("ELASTIC_API_KEY"),
        elastic_ca_certs=os.getenv("ELASTIC_CA_CERTS") or None,
        kibana_url=_url("KIBANA_URL"),
        kibana_api_key=_secret("KIBANA_API_KEY") or _secret("ELASTIC_API_KEY"),
        jina_api_key=jina,
        embed_inference_id=os.getenv("JINA_EMBED_INFERENCE_ID", "doppel-jina-embed"),
        rerank_inference_id=os.getenv("JINA_RERANK_INFERENCE_ID", "doppel-jina-rerank"),
        semantic=_bool("SEMANTIC_SEARCH", default=jina is not None),
        agent_id=os.getenv("AGENT_ID", "doppel-analyst"),
        auto_investigate=_bool("AUTO_INVESTIGATE", True),
        investigate_score=_int("INVESTIGATE_SCORE", 60, 1, 100),
        triage_fetch=_bool("TRIAGE_FETCH"),
        auto_actions=_bool("AUTO_ACTIONS"),
        auto_score=_int("AUTO_SCORE", 85, 1, 100),
        webhook_url=_url("ACTION_WEBHOOK_URL"),
        outbox_dir=os.getenv("OUTBOX_DIR", "outbox"),
        gemini_api_key=_secret("GEMINI_API_KEY"),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-3.6-flash"),
        sentry_dsn=_secret("SENTRY_DSN"),
    )
