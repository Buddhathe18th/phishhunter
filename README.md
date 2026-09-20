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

The LLM agent can only propose an action; a deterministic policy gate decides what actually runs, never the model.
If Agent Builder isn't available, the write-up falls back to a grounded Gemini call over evidence already gathered
- either way it's narrative only, and the dashboard credits whichever one answered.

The dashboard also clusters flagged domains into campaigns, and suggests lookalikes nobody's registered yet for any
recognised brand - the scorer run in reverse, so a defender has something to watch pre-emptively. It also looks up
each domain's actual registration date via RDAP, no API key needed, since a domain registered minutes before its
certificate was issued is a stronger signal than the certificate alone.

Everything above is behind the analyst dashboard's login. `/check` is a separate, public page that needs no
token at all: paste a domain or a link and get an instant answer from the same deterministic scorer, a pure,
stateless computation with no side effects, so it's safe to leave open to anyone, not just a security team.

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

## Named accounts

`API_TOKEN` is the admin credential - keep it out of individual analysts' hands. Instead, mint each person their
own login:

```
curl -X POST /api/users -H "Authorization: Bearer $API_TOKEN" \
     -d '{"username": "alex", "password": "..."}'
```

That returns a personal bearer token. Anyone can also trade a username/password for a fresh token later with
`POST /api/auth/login` (each login invalidates the previous token for that account). A personal token does
everything the admin token does except provision more accounts, and every approve/reject in the audit trail is
now attributed to the real username instead of a generic "dashboard" label. Passwords are hashed with scrypt,
tokens are stored only as a SHA-256 hash, and there's no token expiry or rotation yet - log in again to rotate.

## With Elasticsearch

1. Create an Elastic Cloud/serverless deployment + API key (least-privilege for the app; admin for setup).
2. Fill in `.env`: `ELASTIC_URL`, `ELASTIC_API_KEY`, optionally `KIBANA_URL` and `JINA_API_KEY`.
3. `python -m src.setup_elastic --seed` - idempotent, creates the Jina inference endpoints, indices, and Agent
   Builder tools/agent.
4. Optional: import `elastic/workflows/propose_action.yaml` in Kibana → Workflows, then
   `python -m src.setup_elastic --workflow-id <id>` to expose it to the agent.
5. Run with `DEMO=0` for the live stream, `DEMO=1` to replay.

No `JINA_API_KEY`? Everything still works with BM25-only retrieval.

## Autonomy and safety

| Setting | Default | Effect |
|---|---|---|
| `AUTO_INVESTIGATE` | on | Investigate hits scoring ≥ `INVESTIGATE_SCORE` |
| `TRIAGE_FETCH` | off | Plain, SSRF-hardened GET of flagged domains to detect password forms |
| `AUTO_ACTIONS` | off | Let policy run `block_domain` / `notify` unattended (needs score ≥ `AUTO_SCORE` and ≥ 2 corroborating signals) |

`file_report` (anything addressed to a third party) always waits for a person, and even then only writes a report
to `outbox/` for you to submit. Approve or reject pending actions in the dashboard. `GET /blocklist.txt` (token
required) serves the domains blocked by executed actions. Full threat model in [SECURITY.md](SECURITY.md).

## Measured accuracy, not just a demo

`python -m scripts.benchmark` scores a frozen snapshot of OpenPhish's live feed plus a known-legitimate spot-check;
`tests/test_benchmark.py` locks the results in as permanent regression bounds. Last run: **100% recall** on
in-scope phishing URLs, **2/21 false positives** on known-good domains - both from legitimate pages that merely
mention a brand by name, which is exactly why a human approves every action instead of the policy running blind.
Full writeup and the bug this found: [SECURITY.md](SECURITY.md#known-limitations).

## Optional integrations

Both are no-ops until you set the key; nothing else changes if you skip them.

| Variable | Enables |
|---|---|
| `GEMINI_API_KEY` (+ optional `GEMINI_MODEL`, default `gemini-flash-lite-latest`) | Analyst write-up fallback when Kibana Agent Builder isn't configured or fails |
| `SENTRY_DSN` | Exception capture and light performance tracing for the pipeline, investigator and API (`send_default_pii=False`) |

## Layout

| Path | Purpose |
|---|---|
| `src/ingest.py` | CertStream listener + demo replay |
| `src/score.py` | Explainable lookalike scoring (every point has a reason) + defensive-domain suggestions |
| `src/esq.py` | Index mappings, hybrid retriever and ES\|QL query builders |
| `src/store.py` | `ElasticStore` and an in-memory `MemoryStore` with the same interface |
| `src/investigate.py` | Investigator: evidence, signals, verdict, proposals (Agent Builder `converse`, Gemini fallback) |
| `src/actions.py` | Policy gate, approval workflow, executors, audit trail |
| `src/triage.py` | SSRF-hardened page fetch and HTML fact extraction |
| `src/rdap.py` | Domain-age lookup via IANA's RDAP bootstrap, no API key |
| `src/kibana.py`, `src/setup_elastic.py` | Agent Builder client and one-shot setup |
| `src/api.py`, `src/security.py`, `src/config.py` | API, security primitives, settings |
| `elastic/workflows/` | Elastic Workflow definitions |
| `web/index.html`, `web/app.js` | Analyst dashboard, token-gated (no inline script/style, strict CSP) |
| `web/check.html`, `web/check.js` | Public `/check` page, no token needed |
| `scripts/benchmark.py` | Accuracy check against a frozen real-world sample (see Measured accuracy above) |

## Development

```powershell
pip install -r requirements-dev.txt
ruff check . ; pytest ; bandit -q -r src -ll
```

CI installs from the hash-pinned `requirements*.lock` files. To refresh them:
`pip install pip-tools; pip-compile --generate-hashes --strip-extras --allow-unsafe -o requirements.lock requirements.txt`
(and the same for `requirements-dev`).

## Status

Everything in this project is verified against the real thing, not a stand-in: Elasticsearch 9.6.0, real Jina
hybrid retrieval (BM25 + vector + rerank), the real Kibana Agent Builder (`converse`, using its own registered
tools), the real Gemini API, and real Sentry event capture. Known limitations:
[SECURITY.md](SECURITY.md#known-limitations).

## License

MIT
