from src.config import Settings
from src.store import ElasticStore, MemoryStore, ensure_indices

TOKEN = "t" * 32


class FakeIndicesClient:
    def __init__(self, existing: set[str]):
        self.existing = existing
        self.created: list[str] = []
        self.mapped: list[tuple[str, dict]] = []

    def exists(self, index: str) -> bool:
        return index in self.existing

    def create(self, index: str, **body) -> None:
        self.created.append(index)

    def put_mapping(self, index: str, properties: dict) -> None:
        self.mapped.append((index, properties))


class FakeEs:
    def __init__(self, existing: set[str]):
        self.indices = FakeIndicesClient(existing)


ALL_INDICES = {"phish-hits", "phish-evidence", "phish-actions", "phish-users"}


def test_missing_indices_are_created():
    es = FakeEs(existing=set())
    store = ElasticStore(es, Settings(api_token=TOKEN))
    created = ensure_indices(store)
    assert set(created) == ALL_INDICES
    assert es.indices.mapped == []


def test_existing_indices_get_new_fields_via_put_mapping_not_recreated():
    """A field added to the Python mapping after the index already exists must reach the live index - dynamic:
    strict silently rejects unmapped fields otherwise, which only ever surfaces as a write failure in production.
    """
    es = FakeEs(existing=ALL_INDICES)
    store = ElasticStore(es, Settings(api_token=TOKEN))
    created = ensure_indices(store)
    assert created == []
    mapped_indices = {name for name, _ in es.indices.mapped}
    assert mapped_indices == ALL_INDICES
    hits_props = next(props for name, props in es.indices.mapped if name == "phish-hits")
    assert "domain_age_days" in hits_props
    users_props = next(props for name, props in es.indices.mapped if name == "phish-users")
    assert "token_hash" in users_props


def test_memory_store_user_round_trip():
    store = MemoryStore()
    assert store.get_user("alex") is None
    assert store.find_user_by_token_hash("deadbeef") is None
    store.save_user({"username": "alex", "token_hash": "deadbeef", "password_hash": "x", "password_salt": "y"})
    assert store.get_user("alex")["token_hash"] == "deadbeef"
    assert store.find_user_by_token_hash("deadbeef")["username"] == "alex"
    assert store.find_user_by_token_hash("not-a-real-hash") is None
