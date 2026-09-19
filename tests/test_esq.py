import json

from src import esq


def test_hybrid_search_is_rrf_then_rerank():
    body = esq.evidence_search_body("paypal verify", brand="paypal", semantic=True, rerank_inference_id="rr", size=3)
    rerank = body["retriever"]["text_similarity_reranker"]
    assert rerank["inference_id"] == "rr" and rerank["inference_text"] == "paypal verify"
    legs = rerank["retriever"]["rrf"]["retrievers"]
    assert "match" in legs[0]["standard"]["query"]            # BM25 leg
    assert "semantic" in legs[1]["standard"]["query"]         # Jina dense-vector leg
    assert all(leg["standard"]["filter"] == [{"term": {"brand": "paypal"}}] for leg in legs)
    assert body["size"] == 3


def test_hybrid_without_reranker_stops_at_rrf():
    body = esq.evidence_search_body("q", semantic=True)
    assert "rrf" in body["retriever"]


def test_falls_back_to_bm25_without_semantic():
    body = esq.evidence_search_body("q", semantic=False)
    assert "retriever" not in body and body["query"]["bool"]["must"][0] == {"match": {"text": "q"}}


def test_user_input_is_data_not_query_structure():
    nasty = '"}}, {"match_all": {}}//'
    body = json.dumps(esq.evidence_search_body(nasty, brand=nasty, semantic=True, rerank_inference_id="r"))
    assert json.loads(body)  # still valid JSON, the payload stayed inside string values
    lookalike = esq.lookalike_body(nasty, nasty)
    assert lookalike["query"]["bool"]["should"][0]["match"]["label.ngram"]["query"] == nasty


def test_esql_uses_params_only():
    for query in (esq.ESQL_CAMPAIGNS, esq.ESQL_VOLUME, esq.ESQL_BRAND_WINDOW):
        assert "?" in query and "'" not in query and '"' not in query


def test_mappings_are_strict():
    assert esq.hits_index_body()["mappings"]["dynamic"] == "strict"
    assert esq.evidence_index_body(None)["mappings"]["dynamic"] == "strict"
    assert esq.actions_index_body()["mappings"]["dynamic"] == "strict"
    assert "text_semantic" not in esq.evidence_index_body(None)["mappings"]["properties"]
    assert esq.evidence_index_body("jina")["mappings"]["properties"]["text_semantic"]["inference_id"] == "jina"
