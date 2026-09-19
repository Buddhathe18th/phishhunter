"""Elasticsearch index mappings and query builders.

Pure functions that return plain dicts, so they are unit-testable without a cluster. User-influenced values only
ever travel as ES|QL parameters or as query-DSL values, never as concatenated query text.
"""
from __future__ import annotations

HITS_INDEX = "phish-hits"
EVIDENCE_INDEX = "phish-evidence"
ACTIONS_INDEX = "phish-actions"

EVIDENCE_TYPES = ("lure_email", "lure_sms", "page_text", "forum_post", "feed_report")
EVIDENCE_SOURCE_FIELDS = ["text", "language", "type", "brand", "source", "domains", "@timestamp"]


def hits_index_body() -> dict:
    """One doc per flagged domain. `label.ngram` powers fuzzy lookalike search around a brand name."""
    return {
        "settings": {
            "analysis": {
                "tokenizer": {"domain_ngram_tok": {"type": "ngram", "min_gram": 3, "max_gram": 4,
                                                   "token_chars": ["letter", "digit"]}},
                "analyzer": {"domain_ngram": {"type": "custom", "tokenizer": "domain_ngram_tok",
                                              "filter": ["lowercase"]}},
            }
        },
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "@timestamp": {"type": "date"},
                "domain": {"type": "keyword"},
                "registered_domain": {"type": "keyword"},
                "label": {"type": "keyword", "fields": {"ngram": {"type": "text", "analyzer": "domain_ngram"}}},
                "tld": {"type": "keyword"},
                "brand": {"type": "keyword"},
                "score": {"type": "integer"},
                "reasons": {"type": "text"},
                "issuer": {"type": "keyword"},
                "ip": {"type": "ip"},
                "page_title": {"type": "text"},
                "has_login_form": {"type": "boolean"},
                "page_fingerprint": {"type": "keyword"},
            },
        },
    }


def evidence_index_body(embed_inference_id: str | None) -> dict:
    """Messy real-world text: lure emails/SMS, scraped page text, forum posts, feed reports (any language).

    `text_semantic` (Jina dense vectors via an inference endpoint) is only mapped when semantic search is on.
    """
    props: dict = {
        "@timestamp": {"type": "date"},
        "text": {"type": "text"},
        "language": {"type": "keyword"},
        "type": {"type": "keyword"},
        "source": {"type": "keyword"},
        "brand": {"type": "keyword"},
        "domains": {"type": "keyword"},
        "synthetic": {"type": "boolean"},
    }
    if embed_inference_id:
        props["text_semantic"] = {"type": "semantic_text", "inference_id": embed_inference_id}
    return {"mappings": {"dynamic": "strict", "properties": props}}


def actions_index_body() -> dict:
    """Audit log of every proposed/executed action. History and detail are stored but not indexed."""
    return {
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "domain": {"type": "keyword"},
                "kind": {"type": "keyword"},
                "status": {"type": "keyword"},
                "source": {"type": "keyword"},
                "rationale": {"type": "text"},
                "created": {"type": "date"},
                "updated": {"type": "date"},
                "policy": {"type": "object", "enabled": False},
                "history": {"type": "object", "enabled": False},
            },
        }
    }


def evidence_search_body(query: str, *, brand: str | None = None, size: int = 5, semantic: bool = False,
                         rerank_inference_id: str | None = None, window: int = 50) -> dict:
    """Hybrid retrieval: BM25 + Jina dense vectors fused with RRF, then a Jina reranker.

    Falls back to plain BM25 when semantic search isn't configured.
    """
    filters = [{"term": {"brand": brand}}] if brand else []
    if not semantic:
        return {
            "size": size,
            "_source": EVIDENCE_SOURCE_FIELDS,
            "query": {"bool": {"must": [{"match": {"text": query}}], "filter": filters}},
        }
    lexical = {"standard": {"query": {"match": {"text": query}}, "filter": filters}}
    dense = {"standard": {"query": {"semantic": {"field": "text_semantic", "query": query}}, "filter": filters}}
    retriever: dict = {"rrf": {"retrievers": [lexical, dense], "rank_window_size": window, "rank_constant": 20}}
    if rerank_inference_id:
        retriever = {
            "text_similarity_reranker": {
                "retriever": retriever,
                "field": "text",
                "inference_id": rerank_inference_id,
                "inference_text": query,
                "rank_window_size": window,
            }
        }
    return {"retriever": retriever, "size": size, "_source": EVIDENCE_SOURCE_FIELDS}


def reported_domain_body(domain: str, registered: str) -> dict:
    """Has this exact domain already been named in a report or lure? (Our own page fetches don't count.)"""
    return {
        "size": 3,
        "_source": EVIDENCE_SOURCE_FIELDS,
        "query": {"bool": {"filter": [{"terms": {"domains": [domain, registered]}}],
                           "must_not": [{"term": {"source": "triage"}}]}},
    }


def lookalike_body(label: str, exclude_domain: str, size: int = 10) -> dict:
    """Other flagged domains whose registered label is fuzzily/ngram-similar to this one."""
    return {
        "size": size,
        "_source": ["domain", "brand", "score", "@timestamp"],
        "query": {
            "bool": {
                "should": [
                    {"match": {"label.ngram": {"query": label, "minimum_should_match": "70%"}}},
                    {"fuzzy": {"label": {"value": label, "fuzziness": "AUTO"}}},
                ],
                "minimum_should_match": 1,
                "must_not": [{"term": {"domain": exclude_domain}}],
            }
        },
    }


# ES|QL. Every variable is a ?param, never spliced into the string.
ESQL_CAMPAIGNS = (
    f"FROM {HITS_INDEX} | WHERE @timestamp >= ?since AND brand IS NOT NULL "
    "| STATS domains = COUNT(*), top_score = MAX(score), first_seen = MIN(@timestamp), "
    "last_seen = MAX(@timestamp) BY brand, issuer, tld "
    "| WHERE domains >= ?min_domains | SORT domains DESC | LIMIT 20"
)
ESQL_VOLUME = (
    f"FROM {HITS_INDEX} | WHERE @timestamp >= ?since "
    "| STATS flagged = COUNT(*), max_score = MAX(score) BY bucket = BUCKET(@timestamp, 1 hour) | SORT bucket | LIMIT 200"
)
ESQL_BRAND_WINDOW = (
    f"FROM {HITS_INDEX} | WHERE brand == ?brand AND @timestamp >= ?since "
    "| STATS domains = COUNT(*) BY tld | SORT domains DESC | LIMIT 10"
)
