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
    for path in ("/", "/healthz", "/static/app.js", "/check", "/static/check.js"):
        r = client.get(path)
        assert r.status_code == 200
        assert "script-src 'self'" in r.headers["content-security-policy"]
        assert "'unsafe-inline'" not in r.headers["content-security-policy"]
        assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert client.get("/api/hits", headers=AUTH).headers["cache-control"] == "no-store"


def test_no_inline_script_or_style_in_dashboard(client):
    for path in ("/", "/check"):
        html = client.get(path).text
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
    approved = client.post(f"/api/actions/{block['id']}/approve", headers=AUTH).json()
    assert approved["status"] == "executed"
    assert approved["history"][-1]["by"] == "dashboard"  # master-token approvals are attributed exactly as before
    assert BAD in client.get("/blocklist.txt", headers=AUTH).text
    assert client.post(f"/api/actions/{block['id']}/approve", headers=AUTH).status_code == 409
    assert client.post("/api/actions/nothex/approve", headers=AUTH).status_code == 422
    assert client.post("/api/actions/" + "0" * 32 + "/approve", headers=AUTH).status_code == 404


# --- named accounts: master token stays the admin credential, everything below is additive -------------------

def create_user(client, username="alex", password="a-strong-password-123"):  # noqa: S107 - test fixture, not a real secret
    r = client.post("/api/users", headers=AUTH, json={"username": username, "password": password})
    assert r.status_code == 201, r.text
    return r.json()["token"]


def test_master_token_can_create_a_named_account(client):
    token = create_user(client)
    assert len(token) > 20
    # the new personal token works exactly like the master token for normal data access
    r = client.get("/api/hits", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_a_users_own_token_cannot_create_more_users(client):
    user_token = create_user(client)
    r = client.post("/api/users", headers={"Authorization": f"Bearer {user_token}"},
                    json={"username": "someone-else", "password": "another-strong-password"})
    assert r.status_code == 403


def test_creating_a_user_needs_a_token_at_all(client):
    r = client.post("/api/users", json={"username": "nobody", "password": "another-strong-password"})
    assert r.status_code == 401


def test_duplicate_username_is_rejected(client):
    create_user(client, username="alex")
    r = client.post("/api/users", headers=AUTH, json={"username": "alex", "password": "yet-another-password"})
    assert r.status_code == 409


def test_invalid_username_is_rejected(client):
    r = client.post("/api/users", headers=AUTH, json={"username": "a", "password": "a-strong-password-123"})
    assert r.status_code == 422
    r = client.post("/api/users", headers=AUTH, json={"username": "-bad-", "password": "a-strong-password-123"})
    assert r.status_code == 422


def test_short_password_is_rejected(client):
    r = client.post("/api/users", headers=AUTH, json={"username": "alex", "password": "short"})
    assert r.status_code == 422


def test_login_with_correct_password_issues_a_working_token(client):
    create_user(client, username="alex", password="a-strong-password-123")
    r = client.post("/api/auth/login", json={"username": "alex", "password": "a-strong-password-123"})
    assert r.status_code == 200
    token = r.json()["token"]
    assert client.get("/api/hits", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_login_with_wrong_password_is_rejected(client):
    create_user(client, username="alex", password="a-strong-password-123")
    r = client.post("/api/auth/login", json={"username": "alex", "password": "totally-wrong-password"})
    assert r.status_code == 401


def test_login_with_unknown_username_gives_the_same_error_as_wrong_password(client):
    """Don't leak whether a username exists via a different error message."""
    r1 = client.post("/api/auth/login", json={"username": "nobody-here", "password": "whatever-password"})
    create_user(client, username="alex", password="a-strong-password-123")
    r2 = client.post("/api/auth/login", json={"username": "alex", "password": "wrong-password-here"})
    assert r1.status_code == r2.status_code == 401
    assert r1.json()["detail"] == r2.json()["detail"]


def test_login_reissues_a_fresh_token_invalidating_the_old_one(client):
    old_token = create_user(client, username="alex", password="a-strong-password-123")
    new_token = client.post("/api/auth/login", json={"username": "alex", "password": "a-strong-password-123"}).json()["token"]
    assert old_token != new_token
    assert client.get("/api/hits", headers={"Authorization": f"Bearer {old_token}"}).status_code == 401
    assert client.get("/api/hits", headers={"Authorization": f"Bearer {new_token}"}).status_code == 200


def test_approval_by_a_named_account_is_attributed_in_the_audit_trail(client):
    user_token = create_user(client, username="alex")
    inv = client.post("/api/investigate", json={"domain": BAD}, headers=AUTH).json()
    block = next(a for a in inv["actions"] if a["kind"] == "block_domain")
    approved = client.post(f"/api/actions/{block['id']}/approve", headers={"Authorization": f"Bearer {user_token}"}).json()
    assert approved["history"][-1]["by"] == "alex"


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


def test_public_check_needs_no_token(client):
    r = client.get(f"/api/check?domain={BAD}")
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "suspicious" and body["brand"] == "paypal" and body["score"] >= 40


def test_public_check_on_a_benign_domain(client):
    r = client.get("/api/check?domain=github.com")
    assert r.status_code == 200
    assert r.json()["verdict"] == "looks fine"


def test_public_check_validates_domain(client):
    assert client.get("/api/check?domain=not a domain").status_code == 422


def test_public_check_never_writes_anything(client, store):
    before = store.recent_hits(100)
    client.get(f"/api/check?domain=some-random-domain-not-seen-before-{BAD}")
    assert store.recent_hits(100) == before


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
