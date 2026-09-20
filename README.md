# Doppel

Watches the public Certificate Transparency stream for newly issued certificates and flags the ones that look
like they're impersonating a known brand. For anything flagged, it pulls up similar lures in any language, groups
related domains into a campaign, checks the live page, and writes up a verdict with a proposed action sitting
behind a policy gate. Built at Hack the North 2026.

It's defensive only. Everything it reads is public, and everything it produces is a report a person reviews. It
won't touch a third-party site unless you turn on the hardened page fetch, and it never files a takedown by itself.

## Why watch certificates

A fake login page needs a valid SSL certificate before a browser will show the padlock and let anyone trust it
enough to type a password in. Every certificate authority is required to publish every certificate it issues to a
small number of public, append-only logs, a system called Certificate Transparency. It was built so browsers and
researchers could catch fraudulent certificates, but the side effect is that anyone can watch those logs live and
see a phishing domain's certificate the moment it's issued, sometimes before the site is even fully built.

Most anti-phishing tools work the other way: they wait for a report, or for a blocklist to sync, which can take
hours or days, by which point the site has already had time to catch people. Doppel watches the certificate log
directly instead, so the gap between "domain exists" and "someone knows about it" can be minutes.

## How it works

A new certificate comes in off the CT stream (or, in demo mode, a replayed set of domains plus a live pull from
OpenPhish's public feed, so there's still real data to work with offline). It gets scored immediately by a plain,
deterministic function, no model involved, that checks the domain against a list of watched brands for typos,
lookalike characters, and off-brand TLDs like `.xyz`. This has to run on every certificate, so it stays cheap, and
every point the score gets comes with a reason attached rather than a bare number.

Anything that clears the threshold gets investigated properly, which is the expensive part and only runs on
domains that already look worth the effort. That means an RDAP lookup for how old the domain actually is (a
domain registered five minutes ago is a lot more suspicious than one that's ten years old), and a search over
stored evidence, real lure emails, scraped page text, forum posts, past reports, using both a keyword search
(BM25) and a semantic search over embeddings from Jina, merged together and reranked, so a lure worded completely
differently, or written in another language, still turns up. Optionally, off by default, it also does one tightly
restricted fetch of the live page to check for a password field, the one place Doppel touches the outside world
beyond reading public logs.

Whatever gets found is written up by an LLM, Elastic's Agent Builder when it's configured, Gemini as a fallback,
but the write-up only summarizes evidence that's already been retrieved, it never browses or invents anything and
never decides what to do next. That part's handled by a plain policy: based on the score and how many independent
signals actually agree with each other, it proposes blocking the domain, sending a notification, or drafting a
takedown report. Every one of those sits in a queue until a person clicks approve or reject. Nothing that could
touch a third party goes out automatically, a report is at most a draft written to a local folder.

```
CT stream ─► score ─► phish-hits ─┐
                                  ├─► Investigator ─► verdict ─► propose action ─► POLICY GATE ─► block / notify / report
lures, pages, reports ─► phish-evidence ─┘   ▲                                          │
                                  Agent Builder agent (LLM, read-only tools)       human approves the rest
```

The dashboard also clusters flagged domains into campaigns (the same brand, issuer, or TLD showing up repeatedly
in a short window usually means one attacker running several domains at once), and runs the scorer in reverse to
suggest lookalikes nobody's registered yet for a given brand, so there's a watchlist before an attacker shows up.

All of that lives behind the analyst dashboard's login. `/check` is a separate, public page that needs no account
at all: paste a domain and get an instant answer from the same scorer, no side effects, safe to leave open to
anyone.

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

The LLM agent can only propose an action; a deterministic policy gate decides what actually runs, never the model.
If Agent Builder isn't available, the write-up falls back to a grounded Gemini call over evidence already gathered
- either way it's narrative only, and the dashboard credits whichever one answered.

## Quick start (no cluster needed)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env            # then set API_TOKEN (see below) and DEMO=1
pytest                            # 100+ tests
uvicorn src.api:create_app --factory --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. The dashboard's login form takes a username and password directly (see Named accounts
below); "Use a token" is still there for the admin `API_TOKEN` itself. Generate one with
`python -c "import secrets; print(secrets.token_urlsafe(32))"`; if you leave it unset, one is generated and printed
when the server starts. Demo mode replays canned domains and uses an in-memory store with the bundled synthetic
lure corpus (`data/lures.jsonl`), so investigations work offline, lexical search only, no Elasticsearch or API
keys needed at all, this is the fastest way to see the whole thing running.

## Named accounts

`API_TOKEN` is the admin credential, basically a root password: one person sets it up, then uses it once to
create everyone else's account, never for day-to-day logins. Keep it out of individual analysts' hands. Instead,
mint each person their own login:

```
curl -X POST /api/users -H "Authorization: Bearer $API_TOKEN" \
     -d '{"username": "alex", "password": "..."}'
```

That returns a personal bearer token. Anyone can also trade a username/password for a fresh token later with
`POST /api/auth/login` (each login invalidates the previous token for that account), or just use the dashboard's
own login form, which does the same thing under the hood. A personal token does everything the admin token does
except provision more accounts, and every approve/reject in the audit trail is now attributed to the real
username instead of a generic "dashboard" label. Passwords are hashed with scrypt, tokens are stored only as a
SHA-256 hash, and there's no token expiry or rotation yet, log in again to rotate.

## With Elasticsearch

Everything above works with nothing but Python (see Quick start). This section's only needed if you want the real
Elasticsearch-backed search instead of the in-memory demo store.

1. Create an Elastic Cloud/serverless deployment + API key (least-privilege for the app; admin for setup).
2. Fill in `.env`: `ELASTIC_URL`, `ELASTIC_API_KEY`, optionally `KIBANA_URL` and `JINA_API_KEY`.
3. `python -m src.setup_elastic --seed` - idempotent, creates the Jina inference endpoints, indices, and Agent
   Builder tools/agent.
4. Optional: import `elastic/workflows/propose_action.yaml` in Kibana → Workflows, then
   `python -m src.setup_elastic --workflow-id <id>` to expose it to the agent.
5. Run with `DEMO=0` for the live stream, `DEMO=1` to replay.

No `JINA_API_KEY`? Everything still works with BM25-only (keyword) retrieval, just without the semantic half of
the hybrid search above.

## Autonomy and safety

By default Doppel investigates automatically but never acts automatically, a person always approves the action.
These settings control how much of that you turn on:

| Setting | Default | Effect |
|---|---|---|
| `AUTO_INVESTIGATE` | on | Investigate hits scoring ≥ `INVESTIGATE_SCORE` |
| `TRIAGE_FETCH` | off | Plain, SSRF-hardened GET of flagged domains to detect password forms |
| `AUTO_ACTIONS` | off | Let policy run `block_domain` / `notify` unattended (needs score ≥ `AUTO_SCORE` and ≥ 2 corroborating signals) |

`file_report` (anything addressed to a third party) always waits for a person, and even then only writes a report
to `outbox/` for you to submit, it never contacts anyone on Doppel's behalf. Approve or reject pending actions in
the dashboard. `GET /blocklist.txt` (token required) serves the domains blocked by executed actions as plain text
you could feed into a firewall or DNS sinkhole. Full threat model in [SECURITY.md](SECURITY.md).

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
| `web/index.html`, `web/app.js` | Analyst dashboard, login-gated (no inline script/style, strict CSP) |
| `web/check.html`, `web/check.js` | Public `/check` page, no login needed |
| `scripts/benchmark.py` | Accuracy check against a frozen real-world sample of confirmed phishing and known-legitimate domains |

New to the codebase? Start with `src/score.py` and `src/investigate.py`, the first is the whole scoring logic in
plain Python with no external dependencies, the second is where everything from the "How it works" section above
actually gets called in order.

## Development

```powershell
pip install -r requirements-dev.txt
ruff check . ; pytest ; bandit -q -r src -ll
```

CI installs from the hash-pinned `requirements*.lock` files. To refresh them:
`pip install pip-tools; pip-compile --generate-hashes --strip-extras --allow-unsafe -o requirements.lock requirements.txt`
(and the same for `requirements-dev`).

## License

MIT
