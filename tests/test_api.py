import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from src.api import create_app

from .conftest import TOKEN, add_hit

AUTH = {"Authorization": f"Bearer {TOKEN}"}
BAD = "paypa1-secure-login.xyz"


@pytest.fixture
def client(settings, store):
    add_hit(store, BAD)
    app = create_app(settings, store, start_pipeline=False)
    with TestClient(app, base_url="http://localhost") as c:
        yield c


PROTECTED_GET = ["/api/hits", "/api/campaigns", "/api/volume", "/api/actions", "/api/benchmark", "/blocklist.txt",
                 f"/api/report/{BAD}"]


@pytest.mark.parametrize("path", PROTECTED_GET)
def test_data_endpoints_require_token(client, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get(path, headers={"Authorization": TOKEN}).status_code == 401   # scheme required
    assert client.get(path, headers=AUTH).status_code == 200


def test_post_endpoints_require_token(client):
    assert client.post("/api/investigate", json={"domain": BAD}).status_code == 401
    assert client.post("/api/evidence", json={"text": "x" * 20}).status_code == 401
    assert client.post("/api/actions/" + "a" * 32 + "/approve").status_code == 401
    assert client.post("/api/simulate").status_code == 401


def test_static_page_and_health_are_public_and_carry_security_headers(client):
    for path in ("/", "/healthz", "/static/app.js"):
        r = client.get(path)
        assert r.status_code == 200
        assert "script-src 'self'" in r.headers["content-security-policy"]
        assert "'unsafe-inline'" not in r.headers["content-security-policy"]
        assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert client.get("/api/hits", headers=AUTH).headers["cache-control"] == "no-store"


def test_no_inline_script_or_style_in_dashboard(client):
    html = client.get("/").text
    assert "<script>" not in html and "style=" not in html and "onclick" not in html


def test_unknown_host_is_rejected(client):
    assert client.get("/healthz", headers={"Host": "evil.example"}).status_code == 400   # DNS-rebinding defence


def test_api_docs_are_off_by_default(client):
    assert client.get("/docs").status_code == 404 and client.get("/openapi.json").status_code == 404


def test_investigate_validates_and_works(client):
    assert client.post("/api/investigate", json={"domain": "not a domain"}, headers=AUTH).status_code == 422
    assert client.post("/api/investigate", json={"domain": BAD, "extra": 1}, headers=AUTH).status_code == 422
    r = client.post("/api/investigate", json={"domain": BAD}, headers=AUTH)
    assert r.status_code == 200 and r.json()["brand"] == "paypal" and r.json()["actions"]


def test_evidence_ingest_is_validated_and_cleaned(client):
    ok = client.post("/api/evidence", headers=AUTH, json={"text": "Your PayPal account\x00 is limited, verify now", "brand": "PayPal"})
    assert ok.status_code == 201
    assert client.post("/api/evidence", headers=AUTH, json={"text": "long enough text here", "brand": "nonexistent"}).status_code == 422
    assert client.post("/api/evidence", headers=AUTH, json={"text": "short"}).status_code == 422
    assert client.post("/api/evidence", headers=AUTH, json={"text": "y" * 5000}).status_code == 422
    huge = client.post("/api/evidence", headers=AUTH, content=b'{"text":"' + b"z" * 40_000 + b'"}')
    assert huge.status_code == 413


def test_chunked_bodies_are_refused(client):
    def gen():
        yield b'{"text": "aaaaaaaaaaaaaaaaaaaa"}'
    assert client.post("/api/evidence", headers={**AUTH, "Content-Type": "application/json"}, content=gen()).status_code == 413


def test_approval_flow_and_blocklist(client):
    inv = client.post("/api/investigate", json={"domain": BAD}, headers=AUTH).json()
    block = next(a for a in inv["actions"] if a["kind"] == "block_domain")
    assert client.get("/blocklist.txt", headers=AUTH).text.strip() == ""
    assert client.post(f"/api/actions/{block['id']}/approve", headers=AUTH).json()["status"] == "executed"
    assert BAD in client.get("/blocklist.txt", headers=AUTH).text
    assert client.post(f"/api/actions/{block['id']}/approve", headers=AUTH).status_code == 409
    assert client.post("/api/actions/nothex/approve", headers=AUTH).status_code == 422
    assert client.post("/api/actions/" + "0" * 32 + "/approve", headers=AUTH).status_code == 404


def test_report_endpoint_validates_domain(client):
    assert client.get("/api/report/evil..com", headers=AUTH).status_code == 422
    assert client.get("/api/report/unknown-domain.example", headers=AUTH).status_code == 404
    assert BAD in client.get(f"/api/report/{BAD}", headers=AUTH).text


def test_simulate_flags_a_fresh_attack_in_demo_mode(client):
    r = client.post("/api/simulate", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["flagged"] is True
    assert client.get("/api/hits", headers=AUTH).json()["stats"]["flagged"] >= 1


def test_simulate_live_uses_a_real_fetched_domain(client, monkeypatch):
    from src.ingest import CertEvent

    async def fake_fetch(client=None):
        return CertEvent("real-phish.example.com", "OpenPhish live feed")

    monkeypatch.setattr("src.api.fetch_live_attack_candidate", fake_fetch)
    r = client.post("/api/simulate?live=true", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["domain"] == "real-phish.example.com" and body["source"] == "live"


def test_simulate_live_falls_back_to_synthetic_when_feed_has_no_match(client, monkeypatch):
    async def fake_fetch(client=None):
        return None

    monkeypatch.setattr("src.api.fetch_live_attack_candidate", fake_fetch)
    r = client.post("/api/simulate?live=true", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["flagged"] is True
    assert "synthetic" in body["source"]


def test_simulate_refused_outside_demo_mode(settings, store):
    from dataclasses import replace
    app = create_app(replace(settings, demo=False), store, start_pipeline=False)
    with TestClient(app, base_url="http://localhost") as c:
        assert c.post("/api/simulate", headers=AUTH).status_code == 400


def test_post_rate_limit(settings, store):
    from dataclasses import replace
    app = create_app(replace(settings, heavy_rate_limit_per_min=2), store, start_pipeline=False)
    with TestClient(app, base_url="http://localhost") as c:
        codes = [c.post("/api/evidence", headers=AUTH, json={"text": "x" * 20}).status_code for _ in range(4)]
    assert codes[:2] == [201, 201] and codes[2:] == [429, 429]


def test_websocket_requires_first_message_token(client):
    with client.websocket_connect("/ws") as ws:
        ws.send_text("wrong")
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()
    with client.websocket_connect("/ws") as ws:
        ws.send_text(TOKEN)
        ws.send_text("ping")  # authenticated sockets stay open


def test_websocket_rejects_foreign_origin(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws", headers={"Origin": "https://evil.example"}):
            pass


def test_hit_serialisation_survives_hostile_strings(client, store):
    from src.score import Score
    from src.store import hit_doc
    hostile = hit_doc(Score(domain="evil.example", score=90, brand="paypal", reasons=["<img src=x onerror=alert(1)>"]))
    store.upsert_hit("evil.example", hostile)
    body = client.get("/api/hits", headers=AUTH).json()
    assert any("<img" in r for h in body["hits"] for r in h["reasons"])   # stored as data; the UI renders via textContent
