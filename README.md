# Doppel

Watches the public Certificate Transparency stream for newly issued certificates and flags the ones that look
like they're impersonating a known brand. For anything flagged, it pulls up similar lures in any language, groups
related domains into a campaign, checks the live page, and writes up a verdict with a proposed action sitting
behind a policy gate. Built at Hack the North 2026.

It's defensive only. Everything it reads is public, and everything it produces is a report a person reviews. It
won't touch a third-party site unless you turn on the hardened page fetch, and it never files a takedown by itself.

## What Elasticsearch is actually doing here

| Need | Elastic feature |
|---|---|
| Messy multilingual text (lure emails/SMS, scraped page text, forum and feed reports) | `phish-evidence` index with a BM25 `text` field and a Jina `semantic_text` field |
| Finding the same lure worded differently, or in another language | Hybrid retrieval: BM25 + Jina dense vectors fused with RRF, then a Jina reranker (`text_similarity_reranker`) |
| Typosquats and homoglyph neighbours of a domain | `label.ngram` custom analyzer + fuzzy query on `phish-hits` |
| Campaign structure and issuance bursts | ES\|QL aggregations by brand / issuer / TLD and `BUCKET()` time series |
| A reasoning agent with tools | Agent Builder: 5 ES\|QL tools + platform search + a workflow tool, registered by `setup_elastic` |
| Closing the loop | Workflows: `propose_action` writes to the audit index; a policy gate decides what actually runs |
| Keeping a record | `phish-actions` index logs every proposal, decision, and who made it |

```
CT stream ─► score ─► phish-hits ─┐
                                  ├─► Investigator ─► verdict ─► propose action ─► POLICY GATE ─► block / notify / report
lures, pages, reports ─► phish-evidence ─┘   ▲                                          │
                                  Agent Builder agent (LLM, read-only tools)       human approves the rest
```

The LLM agent can only propose an action. Whether it actually runs unattended comes down to fixed rules checked
against signals recomputed from the data, not anything the agent says, so a poisoned lure or page can't talk its
way into a takedown.

If `KIBANA_URL` isn't set (or Agent Builder errors), the analyst write-up falls back to a direct OpenAI call
grounded only in evidence the deterministic pipeline already gathered - no tool access, so there's nothing for a
poisoned lure to redirect. Either source is narrative only; the dashboard credits whichever one actually answered.

The dashboard also clusters the last 24h of hits into campaigns (same brand, issuer and TLD), and for any domain
with a recognised brand, suggests a handful of lookalikes nobody's registered yet - the scorer run in reverse, so a
defender has something to pre-emptively watch instead of only ever reacting after a certificate is issued.

## Quick start (no cluster needed)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env            # then set API_TOKEN (see below) and DEMO=1
pytest                            # 100+ tests
uvicorn src.api:create_app --factory --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 and paste your `API_TOKEN`. Generate one with
`python -c "import secrets; print(secrets.token_urlsafe(32))"`; if you leave it unset, one is generated and printed
when the server starts. Demo mode replays canned domains and uses an in-memory store with the bundled synthetic
lure corpus (`data/lures.jsonl`), so investigations work offline (lexical search only).

## With Elasticsearch

1. Create an Elastic Cloud deployment or serverless project and an API key. For the running app use a
   least-privilege key (read/write on `phish-*`); for the one-off setup step use one that can also manage
   inference endpoints and Kibana tools.
2. Fill in `.env`: `ELASTIC_URL`, `ELASTIC_API_KEY`, optionally `KIBANA_URL` and `JINA_API_KEY`.
3. One-time setup (idempotent):
   ```powershell
   python -m src.setup_elastic --seed
   ```
   This creates the Jina embedding and rerank inference endpoints (if `JINA_API_KEY` is set), the three indices with
   strict mappings, loads the lure corpus, and registers the Agent Builder tools and agent.
4. Optional, for agent-triggered proposals: import `elastic/workflows/propose_action.yaml` in Kibana → Workflows,
   then `python -m src.setup_elastic --workflow-id <id>` to expose it to the agent as a tool.
   `elastic/workflows/campaign_digest.yaml` is a second workflow that has the agent summarise recent campaigns.
5. Run the app as above with `DEMO=0` for the live stream, or `DEMO=1` to replay.

Without `JINA_API_KEY` everything still works with BM25-only retrieval. `SEMANTIC_SEARCH=1` reuses inference
endpoints that already exist (for example Elastic Inference Service ones).

## Autonomy and safety

| Setting | Default | Effect |
|---|---|---|
| `AUTO_INVESTIGATE` | on | Investigate hits scoring ≥ `INVESTIGATE_SCORE` |
| `TRIAGE_FETCH` | off | Plain, SSRF-hardened GET of flagged domains to detect password forms |
| `AUTO_ACTIONS` | off | Let policy run `block_domain` / `notify` unattended (needs score ≥ `AUTO_SCORE` and ≥ 2 corroborating signals) |

`file_report` (anything addressed to a third party) always waits for a person, and even then only writes a report
to `outbox/` for you to submit. Approve or reject pending actions in the dashboard. `GET /blocklist.txt` (token
required) serves the domains blocked by executed actions. Full threat model in [SECURITY.md](SECURITY.md).

## Optional integrations

Both are no-ops until you set the key; nothing else changes if you skip them.

| Variable | Enables |
|---|---|
| `OPENAI_API_KEY` (+ optional `OPENAI_MODEL`, default `gpt-4o-mini`) | Analyst write-up fallback when Kibana Agent Builder isn't configured or fails |
| `SENTRY_DSN` | Exception capture and light performance tracing for the pipeline, investigator and API (`send_default_pii=False`) |

## Layout

| Path | Purpose |
|---|---|
| `src/ingest.py` | CertStream listener + demo replay |
| `src/score.py` | Explainable lookalike scoring (every point has a reason) + defensive-domain suggestions |
| `src/esq.py` | Index mappings, hybrid retriever and ES\|QL query builders |
| `src/store.py` | `ElasticStore` and an in-memory `MemoryStore` with the same interface |
| `src/investigate.py` | Investigator: evidence, signals, verdict, proposals (Agent Builder `converse`, OpenAI fallback) |
| `src/actions.py` | Policy gate, approval workflow, executors, audit trail |
| `src/triage.py` | SSRF-hardened page fetch and HTML fact extraction |
| `src/kibana.py`, `src/setup_elastic.py` | Agent Builder client and one-shot setup |
| `src/api.py`, `src/security.py`, `src/config.py` | API, security primitives, settings |
| `elastic/workflows/` | Elastic Workflow definitions |
| `web/` | Dashboard (no inline script/style, strict CSP) |

## Development

```powershell
pip install -r requirements-dev.txt
ruff check . ; pytest ; bandit -q -r src -ll
```

CI installs from the hash-pinned `requirements*.lock` files. To refresh them:
`pip install pip-tools; pip-compile --generate-hashes --strip-extras --allow-unsafe -o requirements.lock requirements.txt`
(and the same for `requirements-dev`).

## Status

Verified against a live Elasticsearch 9.5.1 node: mappings, ngram/fuzzy search, ES|QL, hybrid RRF + rerank
retrieval (through a local stand-in for Jina), and the full investigate → propose → approve loop. Not verified:
the Kibana Agent Builder registration and `converse` calls (no Kibana was available), the real Jina API, and the
OpenAI fallback against the live OpenAI API (tested against a mocked client). See
[SECURITY.md](SECURITY.md#known-limitations) for known limitations. The lure corpus is synthetic, and the public
CertStream server goes down sometimes, so use `DEMO=1` if it is.

## License

MIT
