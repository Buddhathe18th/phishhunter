# Security policy

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (repository → Security → *Report a vulnerability*).
Do not open a public issue for security problems. You'll get an acknowledgement within a few days.

## Scope and threat model

Doppel processes **attacker-controlled input by design**: certificate domain names, phishing lure text and
the contents of phishing web pages. The design assumes all of it is hostile.

| Threat | Control |
|---|---|
| Malicious domain names (header/newline injection, odd characters) | `clean_domain` allow-list validation before anything is stored, queried, reported or written to disk |
| Query injection into Elasticsearch | Values travel only as ES\|QL `?params` or query-DSL values, never concatenated; strict index mappings (`dynamic: strict`) |
| SSRF via the page-triage fetch | Off by default; DNS resolved once, every address must be globally routable, connection pinned to the vetted IP, redirects re-validated, ports 80/443 only, size/time caps, no cookies |
| Prompt injection via lures/pages reaching the LLM agent (Agent Builder, or the OpenAI fallback when Kibana isn't configured) | Both are told content is untrusted data; Agent Builder has read-only tools, the OpenAI fallback gets a fixed evidence snapshot with no tool access at all; either way they can only *propose* actions, and a deterministic policy gate (not the model) decides what runs |
| Runaway or malicious autonomy | Unattended actions are off by default; even when on, require score ≥ threshold **and** ≥ 2 independent corroborating signals recomputed from data; third-party actions always need a human; a human rejection permanently blocks auto-action on that domain |
| XSS in the dashboard | No `innerHTML`; all server strings rendered with `textContent`; CSP forbids inline script/style and external sources |
| Unauthorised API/WebSocket use | Bearer token (constant-time compare) on every data route; WebSocket auth via first message (never a URL), origin check, client cap |
| DNS rebinding / host-header attacks against a local server | `TrustedHostMiddleware` allow-list; binds to loopback by default |
| Abuse / DoS | Per-client rate limits (stricter for POSTs), body-size caps, chunked uploads refused, bounded queues |
| Secret leakage | Secrets only from environment; excluded from `repr`; never logged; `.env` git-ignored; GitHub secret scanning + push protection enabled |
| Supply chain | Hash-pinned lockfiles installed with `--require-hashes`; `pip-audit`, Bandit and CodeQL in CI; GitHub Actions pinned to commit SHAs; Dependabot; dependency review on PRs |

## Defensive-use only

This tool consumes public data (Certificate Transparency) and, only if you opt in, performs a plain GET of pages
for domains it has already flagged. It never attacks, scans or probes third-party infrastructure beyond that, and it
never sends takedown requests on its own: reports are written to a local outbox for a person to review and submit.

## Operating it safely

- Set a strong `API_TOKEN`, and put TLS (a reverse proxy) in front of it before exposing it beyond localhost.
- Use a **least-privilege** Elasticsearch API key (read/write on `phish-*` only) for the running app; keep any
  admin-capable key for one-off setup.
- Leave `AUTO_ACTIONS=0` until you have watched the pending-approval queue and trust the signals for your data.
- Treat `/blocklist.txt` as advisory: lookalike scoring has false positives.

## Known limitations

- Scoring is heuristic; expect false positives and negatives.
- The in-memory demo store has lexical search only; cross-language matching needs the Elastic + Jina path.
- Verified against a live Elasticsearch 9.5.1 node: mappings, hybrid retrieval, ES|QL, actions. **Not** verified
  against a live Kibana: the Agent Builder tool/agent registration and `converse` call follow Elastic's documented
  API, and the workflow-tool registration (`--workflow-id`) follows an undocumented shape. Both fail closed (the
  app degrades to the deterministic playbook) and report the error clearly.
- Jina embeddings/reranker were exercised through a local stand-in, not the real Jina API.
- The OpenAI fallback analyst (`OPENAI_API_KEY`, used only when `KIBANA_URL` is unset or Agent Builder errors) is a
  single grounded completion over evidence already gathered, not a tool-calling loop, and was tested against a mocked
  client, not the live OpenAI API. Sends the flagged domain, brand, score and lure snippets already stored locally;
  no raw page content or full lure text beyond what `_lure` already caps at 220 characters.
- Sentry (`SENTRY_DSN`, off by default) receives exception type/stack traces and basic performance spans if
  configured; `send_default_pii=False` is set explicitly and no domain, lure or evidence text is added to events.
