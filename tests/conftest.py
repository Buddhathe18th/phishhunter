from dataclasses import replace

import pytest

from src import investigate
from src.actions import ActionEngine
from src.config import Settings
from src.investigate import Investigator
from src.rdap import RdapResult
from src.score import score_domain
from src.seed import seed
from src.store import MemoryStore, hit_doc

TOKEN = "t" * 32


@pytest.fixture(autouse=True)
def no_real_rdap_calls(monkeypatch):
    """RDAP hits real registry servers over the network; tests get a fast, offline no-op by default.
    Tests that care about the domain-age signal specifically monkeypatch this again with a real value.
    """
    monkeypatch.setattr(investigate, "lookup_domain_age", lambda domain: RdapResult(error="disabled in tests"))


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(demo=True, api_token=TOKEN, allowed_hosts=frozenset({"localhost", "testserver"}),
                    outbox_dir=str(tmp_path / "outbox"))


@pytest.fixture
def store() -> MemoryStore:
    s = MemoryStore()
    seed(s)
    return s


def add_hit(store: MemoryStore, domain: str, issuer: str = "Let's Encrypt", **extra) -> dict:
    doc = {**hit_doc(score_domain(domain), issuer), **extra}
    store.upsert_hit(domain, doc)
    return doc


def make_engine(store, settings, **overrides):
    """An engine wired to a real Investigator, like the app does."""
    settings = replace(settings, **overrides)
    holder = {}
    engine = ActionEngine(store, settings, lambda d: holder["i"].signals_for(d), lambda d: holder["i"].report_for(d))
    holder["i"] = Investigator(store, engine, settings)
    return engine, holder["i"]
