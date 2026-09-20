"""FastAPI app: scores the domain stream, investigates hits, gates actions, and serves the dashboard.

Security posture: every data endpoint needs a bearer token; Host and WebSocket Origin are checked; responses carry
strict headers (CSP with no inline script); request bodies are size-capped and schema-validated; POSTs are
rate-limited; API docs are off unless ENABLE_DOCS=1.
"""
from __future__ import annotations

import asyncio
import random
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import sentry_sdk
from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from scripts.benchmark import run_benchmark

from .actions import ActionEngine
from .config import Settings, load
from .ingest import SIMULATED_ATTACKS, CertEvent, certstream_events, demo_events, fetch_live_attack_candidate
from .investigate import Investigation, Investigator
from .kibana import Kibana
from .score import BRANDS, score_domain
from .security import SECURITY_HEADERS, RateLimiter, clean_domain, clean_text, origin_allowed, token_matches
from .seed import seed
from .store import ElasticStore, MemoryStore, Store, clean_evidence, ensure_indices, hit_doc, make_client

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
MAX_BODY = 32 * 1024
MAX_WS_CLIENTS = 20
COOLDOWN_SECONDS = 600


@dataclass
class State:
    settings: Settings
    store: Store
    engine: ActionEngine
    investigator: Investigator
    stats: dict = field(default_factory=lambda: {"seen": 0, "flagged": 0})
    clients: set[WebSocket] = field(default_factory=set)
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=100))
    recent: dict[str, float] = field(default_factory=dict)


class InvestigateReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(max_length=253)


class EvidenceReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["lure_email", "lure_sms", "page_text", "forum_post", "feed_report"] = "feed_report"
    text: str = Field(min_length=10, max_length=4000)
    language: str | None = Field(default=None, max_length=8)
    source: str | None = Field(default=None, max_length=60)
    brand: str | None = Field(default=None, max_length=40)
    domains: list[str] = Field(default_factory=list, max_length=10)


def body_size_ok(request: Request) -> bool:
    """POST bodies must declare a Content-Length within MAX_BODY; chunked uploads are refused."""
    if "transfer-encoding" in request.headers:
        return False
    try:
        return 0 <= int(request.headers.get("content-length") or 0) <= MAX_BODY
    except ValueError:
        return False


def build_store(settings: Settings) -> Store:
    if settings.elastic_url:
        return ElasticStore(make_client(settings), settings)
    store = MemoryStore()
    seed(store)  # bundled lures, so the offline demo has something to retrieve
    return store


async def broadcast(state: State, message: dict) -> None:
    for ws in list(state.clients):
        try:
            await asyncio.wait_for(ws.send_json(message), timeout=2)
        except Exception:
            state.clients.discard(ws)


async def handle_event(state: State, raw_domain: str, issuer: str | None) -> bool:
    """Score one certificate event and, if it clears the threshold, record and broadcast it. Shared by the
    passive stream and the on-demand /api/simulate trigger so both go through the exact same logic.
    Returns True if the domain was flagged.
    """
    s = state.settings
    domain = clean_domain(raw_domain)
    if domain is None:
        return False
    state.stats["seen"] += 1
    result = score_domain(domain)
    if result.score < s.threshold:
        return False
    state.stats["flagged"] += 1
    doc = hit_doc(result, issuer)
    await asyncio.to_thread(state.store.upsert_hit, domain, doc)
    await broadcast(state, {"type": "hit", **doc, "stats": state.stats})
    if s.auto_investigate and result.score >= s.investigate_score and not state.queue.full():
        state.queue.put_nowait(domain)
    return True


async def pipeline(state: State) -> None:
    source = demo_events() if state.settings.demo else certstream_events()
    async for event in source:
        try:
            await handle_event(state, event.domain, event.issuer)
        except Exception as exc:  # one bad event (or a store hiccup) must not stop the stream
            print(f"[pipeline] error: {type(exc).__name__}", file=sys.stderr)
            sentry_sdk.capture_exception(exc)


async def investigation_worker(state: State) -> None:
    loop = asyncio.get_running_loop()
    while True:
        domain = await state.queue.get()
        now = loop.time()
        if now - state.recent.get(domain, -COOLDOWN_SECONDS) < COOLDOWN_SECONDS:
            continue
        state.recent[domain] = now
        if len(state.recent) > 5000:
            state.recent.clear()
        try:
            inv = await state.investigator.run(domain)
            await broadcast(state, {"type": "investigation", **inv.to_dict()})
        except Exception as exc:
            print(f"[investigate] error: {type(exc).__name__}", file=sys.stderr)
            sentry_sdk.capture_exception(exc)


async def action_sweeper(state: State) -> None:
    """Applies the policy to proposals written by the Elastic Workflow tool."""
    while True:
        await asyncio.sleep(30)
        try:
            if await asyncio.to_thread(state.engine.sweep):
                await broadcast(state, {"type": "actions"})
        except Exception as exc:
            print(f"[sweeper] error: {type(exc).__name__}", file=sys.stderr)
            sentry_sdk.capture_exception(exc)


def create_app(settings: Settings | None = None, store: Store | None = None, start_pipeline: bool = True) -> FastAPI:
    settings = settings or load()
    if settings.sentry_dsn and not sentry_sdk.is_initialized():
        sentry_sdk.init(dsn=settings.sentry_dsn, traces_sample_rate=0.2,
                         environment="demo" if settings.demo else "live", send_default_pii=False)
    store = store or build_store(settings)
    kibana = Kibana(settings) if settings.kibana_url and settings.elastic_url else None
    holder: dict[str, Investigator] = {}
    engine = ActionEngine(store, settings, signals_fn=lambda d: holder["inv"].signals_for(d),
                          report_fn=lambda d: holder["inv"].report_for(d))
    investigator = holder["inv"] = Investigator(store, engine, settings, kibana)
    state = State(settings, store, engine, investigator)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if isinstance(store, ElasticStore):
            await asyncio.to_thread(ensure_indices, store)
        tasks = []
        if start_pipeline:
            tasks = [asyncio.create_task(pipeline(state)), asyncio.create_task(investigation_worker(state)),
                     asyncio.create_task(action_sweeper(state))]
        if settings.token_generated:
            print(f"[doppel] no API_TOKEN set; this run's token is: {settings.api_token}", file=sys.stderr)
        yield
        for task in tasks:
            task.cancel()

    app = FastAPI(title="doppel", lifespan=lifespan, docs_url="/docs" if settings.enable_docs else None,
                  redoc_url=None, openapi_url="/openapi.json" if settings.enable_docs else None)
    app.state.ph = state
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=sorted(settings.allowed_hosts))

    general, heavy = RateLimiter(settings.rate_limit_per_min), RateLimiter(settings.heavy_rate_limit_per_min)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        client = request.client.host if request.client else "unknown"
        # /api/check needs no token, so it gets the tight limiter regardless of HTTP method
        limiter = heavy if request.method == "POST" or request.url.path == "/api/check" else general
        if not limiter.allow(client):
            response = JSONResponse({"detail": "rate limit exceeded"}, status_code=429, headers={"Retry-After": "60"})
        elif request.method == "POST" and not body_size_ok(request):
            response = JSONResponse({"detail": "request body too large or malformed"}, status_code=413)
        else:
            response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        if request.url.path.startswith("/api") or request.url.path == "/blocklist.txt":
            response.headers["Cache-Control"] = "no-store"
        return response

    def auth(authorization: str | None = Header(default=None)) -> None:
        supplied = authorization[7:] if authorization and authorization.startswith("Bearer ") else None
        if not token_matches(supplied, settings.api_token):
            raise HTTPException(401, "missing or invalid token", headers={"WWW-Authenticate": "Bearer"})

    def valid_domain(domain: str) -> str:
        cleaned = clean_domain(domain)
        if cleaned is None:
            raise HTTPException(422, "not a valid domain name")
        return cleaned

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.get("/api/check")
    def check(domain: str) -> dict:
        """Public, no token needed: the same deterministic scorer the internal pipeline uses, exposed so anyone
        can check a suspicious link themselves instead of only a security team being able to. Pure computation,
        no external calls, nothing stored - safe to leave open, and rate-limited tighter than the authenticated
        routes since it has no login barrier at all.
        """
        cleaned = valid_domain(domain)
        result = score_domain(cleaned)
        return {"domain": cleaned, "score": result.score, "brand": result.brand, "reasons": result.reasons,
                "verdict": "suspicious" if result.score >= settings.threshold else "looks fine"}

    @app.get("/api/hits", dependencies=[Depends(auth)])
    async def hits() -> dict:
        return {"stats": state.stats, "hits": await asyncio.to_thread(store.recent_hits, 100)}

    @app.get("/api/campaigns", dependencies=[Depends(auth)])
    async def campaigns() -> dict:
        return {"campaigns": await asyncio.to_thread(store.campaigns, 24, 2)}

    @app.get("/api/volume", dependencies=[Depends(auth)])
    async def volume() -> dict:
        return {"buckets": await asyncio.to_thread(store.volume, 24)}

    @app.get("/api/benchmark", dependencies=[Depends(auth)])
    async def benchmark() -> dict:
        return await asyncio.to_thread(run_benchmark)

    @app.post("/api/investigate", dependencies=[Depends(auth)])
    async def investigate(req: InvestigateReq) -> dict:
        inv: Investigation = await investigator.run(valid_domain(req.domain))
        payload = inv.to_dict()
        await broadcast(state, {"type": "investigation", **payload})
        return payload

    @app.post("/api/simulate", dependencies=[Depends(auth)])
    async def simulate(live: bool = False) -> dict:
        """Demo-mode only: inject one fresh attack right now, so the whole pipeline (score, flag, investigate,
        propose) reacts live instead of waiting on the passive replay's own timing. `live=true` pulls a real,
        currently-active phishing URL from OpenPhish's public feed instead of a canned demo string; if that
        fetch fails or finds nothing in scope, it falls back to the synthetic pool rather than erroring out.
        """
        if not settings.demo:
            raise HTTPException(400, "only available in DEMO=1 mode - it would be misleading against a live stream")
        source = "synthetic"
        event = None
        if live:
            event = await fetch_live_attack_candidate()
            source = "live" if event else "synthetic (live feed had no in-scope match)"
        if event is None:
            event = CertEvent(random.choice(SIMULATED_ATTACKS), random.choice(["Let's Encrypt", "ZeroSSL"]))  # noqa: S311
        flagged = await handle_event(state, event.domain, event.issuer)
        return {"domain": event.domain, "flagged": flagged, "source": source}

    @app.post("/api/evidence", dependencies=[Depends(auth)], status_code=201)
    async def add_evidence(req: EvidenceReq) -> dict:
        if req.brand and req.brand.lower() not in BRANDS:
            raise HTTPException(422, "unknown brand")
        doc = clean_evidence({**req.model_dump(), "brand": (req.brand or "").lower(), "source": req.source or "api"})
        if not doc["text"]:
            raise HTTPException(422, "empty text")
        return {"id": await asyncio.to_thread(store.add_evidence, doc)}

    @app.get("/api/report/{domain}", dependencies=[Depends(auth)], response_class=PlainTextResponse)
    async def report(domain: str) -> str:
        text = await asyncio.to_thread(investigator.report_for, valid_domain(domain))
        if text is None:
            raise HTTPException(404, "domain not found in recent hits")
        return text

    @app.get("/api/actions", dependencies=[Depends(auth)])
    async def actions(status: str | None = None) -> dict:
        if status is not None and status not in {"proposed", "pending_approval", "executed", "rejected", "failed"}:
            raise HTTPException(422, "unknown status")
        return {"actions": await asyncio.to_thread(store.list_actions, status, 100), "auto": settings.auto_actions}

    async def decide(action_id: str, verb: Literal["approve", "reject"]) -> dict:
        if len(action_id) != 32 or not all(c in "0123456789abcdef" for c in action_id):
            raise HTTPException(422, "bad action id")
        try:
            action = await asyncio.to_thread(getattr(engine, verb), action_id, "dashboard")
        except KeyError:
            raise HTTPException(404, "no such action") from None
        except ValueError as exc:
            raise HTTPException(409, clean_text(str(exc), 200)) from None
        await broadcast(state, {"type": "actions"})
        return action

    @app.post("/api/actions/{action_id}/approve", dependencies=[Depends(auth)])
    async def approve(action_id: str) -> dict:
        return await decide(action_id, "approve")

    @app.post("/api/actions/{action_id}/reject", dependencies=[Depends(auth)])
    async def reject(action_id: str) -> dict:
        return await decide(action_id, "reject")

    @app.get("/blocklist.txt", dependencies=[Depends(auth)], response_class=PlainTextResponse)
    async def blocklist() -> str:
        return "\n".join(await asyncio.to_thread(engine.blocklist)) + "\n"

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket) -> None:
        if not origin_allowed(ws.headers.get("origin"), ws.headers.get("host"), settings.allowed_origins) \
                or len(state.clients) >= MAX_WS_CLIENTS:
            await ws.close(code=1008)
            return
        await ws.accept()
        try:  # token goes in the first message, never the URL (URLs end up in logs)
            first = await asyncio.wait_for(ws.receive_text(), timeout=5)
            supplied = first[:512].removeprefix("Bearer ").strip()
            if not token_matches(supplied, settings.api_token):
                await ws.close(code=1008)
                return
            state.clients.add(ws)
            while True:
                if len(await ws.receive_text()) > 1024:
                    await ws.close(code=1009)
                    return
        except (TimeoutError, WebSocketDisconnect):
            pass
        finally:
            state.clients.discard(ws)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/check")
    def check_page() -> FileResponse:
        return FileResponse(WEB_DIR / "check.html")

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
    return app
