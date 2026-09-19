"""FastAPI app: consumes the domain stream, scores it, and pushes hits to the dashboard."""
from __future__ import annotations

import asyncio
import os
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .ingest import certstream_domains, demo_domains
from .report import abuse_report
from .score import Score, score_domain

THRESHOLD = int(os.getenv("THRESHOLD", "40"))
DEMO = os.getenv("DEMO", "0") == "1"
WEB_DIR = Path(__file__).resolve().parent.parent / "web"

hits: deque[Score] = deque(maxlen=500)
clients: set[WebSocket] = set()
stats = {"seen": 0, "flagged": 0}


async def pipeline() -> None:
    source = demo_domains() if DEMO else certstream_domains()
    async for domain in source:
        stats["seen"] += 1
        result = score_domain(domain)
        if result.score < THRESHOLD:
            continue
        stats["flagged"] += 1
        hits.appendleft(result)
        payload = {**asdict(result), "stats": stats}
        for ws in list(clients):
            try:
                await ws.send_json(payload)
            except Exception:
                clients.discard(ws)


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(pipeline())
    yield
    task.cancel()


app = FastAPI(title="phishhunter", lifespan=lifespan)


@app.get("/hits")
def recent_hits() -> dict:
    return {"stats": stats, "hits": [asdict(h) for h in hits]}


@app.get("/report/{domain}", response_class=PlainTextResponse)
def report(domain: str) -> str:
    for h in hits:
        if h.domain == domain:
            return abuse_report(h)
    return "domain not found in recent hits"


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        clients.discard(ws)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
