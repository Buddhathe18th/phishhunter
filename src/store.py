"""Storage: ElasticStore (the real context layer) and MemoryStore (offline demo + tests). Same interface."""
from __future__ import annotations

import hashlib
import re
import uuid
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from rapidfuzz import fuzz

from . import esq
from .config import Settings
from .score import Score, split_domain
from .security import clean_domain, clean_text


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def since_iso(hours: int) -> str:
    return (datetime.now(UTC) - timedelta(hours=hours)).isoformat()


def hit_doc(score: Score, issuer: str | None = None) -> dict:
    _, registered, tld = split_domain(score.domain)
    label = registered.rsplit(".", 1)[0] if "." in registered else registered
    doc: dict[str, Any] = {
        "@timestamp": now_iso(), "domain": score.domain, "registered_domain": registered, "label": label,
        "tld": tld, "brand": score.brand, "score": score.score, "reasons": score.reasons,
    }
    if issuer:
        doc["issuer"] = issuer
    return doc


def evidence_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:32]


class Store(ABC):
    semantic = False

    # hits
    @abstractmethod
    def upsert_hit(self, domain: str, doc: dict) -> None: ...
    @abstractmethod
    def get_hit(self, domain: str) -> dict | None: ...
    @abstractmethod
    def recent_hits(self, limit: int = 100) -> list[dict]: ...
    @abstractmethod
    def lookalikes(self, label: str, exclude: str, size: int = 10) -> list[dict]: ...
    @abstractmethod
    def campaigns(self, hours: int = 24, min_domains: int = 2) -> list[dict]: ...
    @abstractmethod
    def brand_window(self, brand: str, hours: int = 24) -> list[dict]: ...
    @abstractmethod
    def volume(self, hours: int = 24) -> list[dict]: ...
    # evidence
    @abstractmethod
    def add_evidence(self, doc: dict) -> str: ...
    @abstractmethod
    def search_evidence(self, query: str, brand: str | None = None, size: int = 5) -> list[dict]: ...
    @abstractmethod
    def reported(self, domain: str, registered: str) -> list[dict]: ...
    # actions
    @abstractmethod
    def save_action(self, action: dict) -> None: ...
    @abstractmethod
    def get_action(self, action_id: str) -> dict | None: ...
    @abstractmethod
    def list_actions(self, status: str | None = None, limit: int = 100) -> list[dict]: ...
    # users
    @abstractmethod
    def save_user(self, user: dict) -> None: ...
    @abstractmethod
    def get_user(self, username: str) -> dict | None: ...
    @abstractmethod
    def find_user_by_token_hash(self, token_hash: str) -> dict | None: ...

    def new_action_id(self) -> str:
        return uuid.uuid4().hex


class MemoryStore(Store):
    """Dict-backed. Lexical search only (no dense vectors), so cross-language matching needs Elastic."""

    def __init__(self) -> None:
        self.hits: dict[str, dict] = {}
        self.evidence: dict[str, dict] = {}
        self.actions: dict[str, dict] = {}
        self.users: dict[str, dict] = {}

    def upsert_hit(self, domain: str, doc: dict) -> None:
        self.hits[domain] = {**self.hits.get(domain, {}), **doc}

    def get_hit(self, domain: str) -> dict | None:
        return self.hits.get(domain)

    def recent_hits(self, limit: int = 100) -> list[dict]:
        return sorted(self.hits.values(), key=lambda h: h["@timestamp"], reverse=True)[:limit]

    def lookalikes(self, label: str, exclude: str, size: int = 10) -> list[dict]:
        found = [h for d, h in self.hits.items() if d != exclude and fuzz.ratio(h.get("label", ""), label) >= 70]
        return [{k: h.get(k) for k in ("domain", "brand", "score")} for h in found[:size]]

    def campaigns(self, hours: int = 24, min_domains: int = 2) -> list[dict]:
        cutoff = since_iso(hours)
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for h in self.hits.values():
            if h["@timestamp"] >= cutoff and h.get("brand"):
                groups[(h["brand"], h.get("issuer"), h.get("tld"))].append(h)
        rows = [{"brand": b, "issuer": i, "tld": t, "domains": len(v), "top_score": max(x["score"] for x in v),
                 "first_seen": min(x["@timestamp"] for x in v), "last_seen": max(x["@timestamp"] for x in v)}
                for (b, i, t), v in groups.items() if len(v) >= min_domains]
        return sorted(rows, key=lambda r: -r["domains"])[:20]

    def brand_window(self, brand: str, hours: int = 24) -> list[dict]:
        cutoff = since_iso(hours)
        counts = Counter(h.get("tld") for h in self.hits.values() if h.get("brand") == brand and h["@timestamp"] >= cutoff)
        return [{"tld": t, "domains": n} for t, n in counts.most_common(10)]

    def volume(self, hours: int = 24) -> list[dict]:
        cutoff = since_iso(hours)
        buckets: dict[str, list[int]] = defaultdict(list)
        for h in self.hits.values():
            if h["@timestamp"] >= cutoff:
                buckets[h["@timestamp"][:13] + ":00:00+00:00"].append(h["score"])
        return [{"bucket": b, "flagged": len(v), "max_score": max(v)} for b, v in sorted(buckets.items())]

    def add_evidence(self, doc: dict) -> str:
        eid = evidence_id(doc["text"])
        self.evidence[eid] = {"@timestamp": now_iso(), **doc}
        return eid

    def search_evidence(self, query: str, brand: str | None = None, size: int = 5) -> list[dict]:
        q = set(re.findall(r"\w+", query.lower()))
        scored = []
        for doc in self.evidence.values():
            if brand and doc.get("brand") != brand:
                continue
            overlap = len(q & set(re.findall(r"\w+", doc["text"].lower())))
            if overlap:
                scored.append((overlap, doc))
        scored.sort(key=lambda t: -t[0])
        return [{**d, "_score": float(s)} for s, d in scored[:size]]

    def reported(self, domain: str, registered: str) -> list[dict]:
        named = [d for d in self.evidence.values() if {domain, registered} & set(d.get("domains", []))]
        return [d for d in named if d.get("source") != "triage"][:3]

    def save_action(self, action: dict) -> None:
        self.actions[action["id"]] = action

    def get_action(self, action_id: str) -> dict | None:
        return self.actions.get(action_id)

    def list_actions(self, status: str | None = None, limit: int = 100) -> list[dict]:
        rows = [a for a in self.actions.values() if status is None or a["status"] == status]
        return sorted(rows, key=lambda a: a.get("created", ""), reverse=True)[:limit]

    def save_user(self, user: dict) -> None:
        self.users[user["username"]] = user

    def get_user(self, username: str) -> dict | None:
        return self.users.get(username)

    def find_user_by_token_hash(self, token_hash: str) -> dict | None:
        return next((u for u in self.users.values() if u.get("token_hash") == token_hash), None)


def _esql_rows(resp: Any) -> list[dict]:
    cols = [c["name"] for c in resp["columns"]]
    return [dict(zip(cols, row, strict=True)) for row in resp["values"]]


class ElasticStore(Store):
    def __init__(self, client: Any, settings: Settings) -> None:
        self.es = client
        self.settings = settings
        self.semantic = settings.semantic

    def _search(self, index: str, body: dict) -> list[dict]:
        resp = self.es.search(index=index, **body)
        return [{**h["_source"], "_score": h.get("_score")} for h in resp["hits"]["hits"]]

    def _esql(self, query: str, params: list[dict]) -> list[dict]:
        return _esql_rows(self.es.esql.query(query=query, params=params, format="json"))

    def upsert_hit(self, domain: str, doc: dict) -> None:
        self.es.update(index=esq.HITS_INDEX, id=domain, doc=doc, doc_as_upsert=True)

    def get_hit(self, domain: str) -> dict | None:
        resp = self.es.options(ignore_status=404).get(index=esq.HITS_INDEX, id=domain).body
        return resp["_source"] if resp.get("found") else None

    def recent_hits(self, limit: int = 100) -> list[dict]:
        return self._search(esq.HITS_INDEX, {"size": limit, "sort": [{"@timestamp": "desc"}], "query": {"match_all": {}}})

    def lookalikes(self, label: str, exclude: str, size: int = 10) -> list[dict]:
        return self._search(esq.HITS_INDEX, esq.lookalike_body(label, exclude, size))

    def campaigns(self, hours: int = 24, min_domains: int = 2) -> list[dict]:
        return self._esql(esq.ESQL_CAMPAIGNS, [{"since": since_iso(hours)}, {"min_domains": min_domains}])

    def brand_window(self, brand: str, hours: int = 24) -> list[dict]:
        return self._esql(esq.ESQL_BRAND_WINDOW, [{"brand": brand}, {"since": since_iso(hours)}])

    def volume(self, hours: int = 24) -> list[dict]:
        return self._esql(esq.ESQL_VOLUME, [{"since": since_iso(hours)}])

    def add_evidence(self, doc: dict) -> str:
        eid = evidence_id(doc["text"])
        body = {"@timestamp": now_iso(), **doc}
        if self.semantic:
            body["text_semantic"] = doc["text"]
        self.es.index(index=esq.EVIDENCE_INDEX, id=eid, document=body)
        return eid

    def search_evidence(self, query: str, brand: str | None = None, size: int = 5) -> list[dict]:
        body = esq.evidence_search_body(
            query, brand=brand, size=size, semantic=self.semantic,
            rerank_inference_id=self.settings.rerank_inference_id if self.semantic else None)
        return self._search(esq.EVIDENCE_INDEX, body)

    def reported(self, domain: str, registered: str) -> list[dict]:
        return self._search(esq.EVIDENCE_INDEX, esq.reported_domain_body(domain, registered))

    def save_action(self, action: dict) -> None:
        self.es.index(index=esq.ACTIONS_INDEX, id=action["id"], document={k: v for k, v in action.items() if k != "id"},
                      refresh="wait_for")

    def get_action(self, action_id: str) -> dict | None:
        resp = self.es.options(ignore_status=404).get(index=esq.ACTIONS_INDEX, id=action_id).body
        return {"id": action_id, **resp["_source"]} if resp.get("found") else None

    def list_actions(self, status: str | None = None, limit: int = 100) -> list[dict]:
        query = {"term": {"status": status}} if status else {"match_all": {}}
        resp = self.es.search(index=esq.ACTIONS_INDEX, size=limit, sort=[{"created": "desc"}], query=query)
        return [{"id": h["_id"], **h["_source"]} for h in resp["hits"]["hits"]]

    def save_user(self, user: dict) -> None:
        self.es.index(index=esq.USERS_INDEX, id=user["username"], document=user, refresh="wait_for")

    def get_user(self, username: str) -> dict | None:
        resp = self.es.options(ignore_status=404).get(index=esq.USERS_INDEX, id=username).body
        return resp["_source"] if resp.get("found") else None

    def find_user_by_token_hash(self, token_hash: str) -> dict | None:
        resp = self.es.search(index=esq.USERS_INDEX, size=1, query={"term": {"token_hash": token_hash}})
        hits = resp["hits"]["hits"]
        return hits[0]["_source"] if hits else None


def clean_evidence(doc: dict) -> dict:
    """Normalise an incoming evidence doc: strip control chars, cap lengths, drop unknown keys."""
    out = {
        "type": doc.get("type") if doc.get("type") in esq.EVIDENCE_TYPES else "feed_report",
        "text": clean_text(doc.get("text"), 4000).strip(),
    }
    for key, cap in (("language", 8), ("source", 60), ("brand", 40)):
        if val := clean_text(doc.get(key), cap).strip():
            out[key] = val
    if isinstance(doc.get("domains"), list):
        out["domains"] = [d for d in map(clean_domain, doc["domains"][:10]) if d]
    if doc.get("synthetic"):
        out["synthetic"] = True
    return out


def make_client(settings: Settings) -> Any:
    """Elasticsearch client: TLS verification always on, API-key auth, bounded timeouts."""
    from elasticsearch import Elasticsearch

    if not settings.elastic_url:
        raise RuntimeError("ELASTIC_URL is not set")
    return Elasticsearch(settings.elastic_url, api_key=settings.elastic_api_key, ca_certs=settings.elastic_ca_certs,
                         request_timeout=20, max_retries=2, retry_on_timeout=True)


def ensure_indices(store: ElasticStore) -> list[str]:
    """Create any missing index with its strict mapping. For an index that already exists, add any new fields
    the mapping has grown since it was created - `dynamic: strict` rejects unmapped fields outright, so a field
    added to the Python source without this step passing would only surface as a write failure in production.
    Returns the names created (not the ones just patched with new fields).
    """
    wanted = {
        esq.HITS_INDEX: esq.hits_index_body(),
        esq.EVIDENCE_INDEX: esq.evidence_index_body(store.settings.embed_inference_id if store.semantic else None),
        esq.ACTIONS_INDEX: esq.actions_index_body(),
        esq.USERS_INDEX: esq.users_index_body(),
    }
    created = []
    for name, body in wanted.items():
        if store.es.indices.exists(index=name):
            store.es.indices.put_mapping(index=name, properties=body["mappings"]["properties"])
        else:
            store.es.indices.create(index=name, **body)
            created.append(name)
    return created
