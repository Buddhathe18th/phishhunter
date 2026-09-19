from src.config import Settings
from src.store import ElasticStore, ensure_indices

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


def test_missing_indices_are_created():
    es = FakeEs(existing=set())
    store = ElasticStore(es, Settings(api_token=TOKEN))
    created = ensure_indices(store)
    assert set(created) == {"phish-hits", "phish-evidence", "phish-actions"}
    assert es.indices.mapped == []


def test_existing_indices_get_new_fields_via_put_mapping_not_recreated():
    """A field added to the Python mapping after the index already exists must reach the live index - dynamic:
    strict silently rejects unmapped fields otherwise, which only ever surfaces as a write failure in production.
    """
    es = FakeEs(existing={"phish-hits", "phish-evidence", "phish-actions"})
    store = ElasticStore(es, Settings(api_token=TOKEN))
    created = ensure_indices(store)
    assert created == []
    mapped_indices = {name for name, _ in es.indices.mapped}
    assert mapped_indices == {"phish-hits", "phish-evidence", "phish-actions"}
    hits_props = next(props for name, props in es.indices.mapped if name == "phish-hits")
    assert "domain_age_days" in hits_props
