# Phishhunter

Watches the public Certificate Transparency stream for newly issued certificates, flags domains that
impersonate well-known brands (typosquats, homoglyphs, credential-bait keywords), and generates a
takedown-ready abuse report. Built at Hack the North 2026.

Defensive only: it uses public data and never probes or attacks third parties.

## Run it

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest                                  # scoring tests
$env:DEMO = "1"                         # offline replay; omit for the live CT stream
uvicorn src.api:app --reload            # open http://127.0.0.1:8000
```

## Layout

| Path | Purpose |
|---|---|
| `src/ingest.py` | CertStream listener + demo replay |
| `src/score.py` | Explainable lookalike scoring (every point has a reason) |
| `src/triage.py` | Second-stage page analysis (TODO) |
| `src/report.py` | Abuse-report generator |
| `src/api.py` | FastAPI + WebSocket live feed |
| `web/index.html` | Dashboard |

## Next steps
- [ ] Verify the live CertStream connection (fall back to crt.sh polling if the public server is down)
- [ ] Index hits in Elasticsearch; add fuzzy lookalike search
- [ ] Sandboxed page fetch + login-form detection in `triage.py`
- [ ] Model-written explanations (OpenAI / Gemini / Baseten)
- [ ] Time-series storage of cert volume (Tiger Data)
- [ ] Sentry instrumentation of the pipeline
