"""Load the bundled (synthetic, multilingual) lure corpus into a store. `python -m src.seed` targets Elasticsearch."""
from __future__ import annotations

import json
from pathlib import Path

from .store import Store, clean_evidence

LURES_PATH = Path(__file__).resolve().parent.parent / "data" / "lures.jsonl"


def seed(store: Store, path: Path = LURES_PATH) -> int:
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            doc = clean_evidence(json.loads(line))
            if doc["text"]:
                store.add_evidence(doc)
                count += 1
    return count


if __name__ == "__main__":
    from .config import load
    from .store import ElasticStore, ensure_indices, make_client

    settings = load()
    store = ElasticStore(make_client(settings), settings)
    ensure_indices(store)
    print(f"seeded {seed(store)} lure documents")
