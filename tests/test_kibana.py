from dataclasses import replace

import httpx
import pytest

from src.config import Settings
from src.kibana import Kibana, KibanaError

TOKEN = "t" * 32


def settings_with_kibana() -> Settings:
    return Settings(api_token=TOKEN, kibana_url="https://kibana.example", kibana_api_key="k")


def kibana_with(handler) -> Kibana:
    return Kibana(settings_with_kibana(), client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_upsert_creates_when_nothing_exists():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        return httpx.Response(200, json={"id": "x"})

    action = kibana_with(handler).upsert("tools", {"id": "x", "type": "esql"})
    assert action == "created"


def test_upsert_falls_back_to_put_on_409():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "POST":
            return httpx.Response(409, json={"message": "conflict"})
        return httpx.Response(200, json={"id": "x"})

    action = kibana_with(handler).upsert("agents", {"id": "x", "type": "agent"})
    assert action == "updated" and calls == ["POST", "PUT"]


def test_upsert_falls_back_to_put_on_400_already_exists():
    """Kibana isn't consistent: tools return a plain 400 with 'already exists' in the message, not a 409.
    Re-running setup_elastic must still be idempotent, which means checking the message, not just the status.
    """
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "POST":
            return httpx.Response(400, json={"statusCode": 400, "message": "Tool with id x already exists"})
        return httpx.Response(200, json={"id": "x"})

    action = kibana_with(handler).upsert("tools", {"id": "x", "type": "esql"})
    assert action == "updated" and calls == ["POST", "PUT"]


def test_upsert_raises_on_a_real_400_unrelated_to_conflict():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"statusCode": 400, "message": "invalid tool definition"})

    with pytest.raises(KibanaError):
        kibana_with(handler).upsert("tools", {"id": "x", "type": "esql"})


def test_converse_returns_the_response_message():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/agent_builder/converse"
        return httpx.Response(200, json={"response": {"message": "hello"}})

    assert kibana_with(handler).converse("agent-1", "hi") == "hello"


def test_converse_raises_on_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    with pytest.raises(KibanaError):
        kibana_with(handler).converse("agent-1", "hi")


def test_kibana_requires_url_and_key():
    with pytest.raises(KibanaError):
        Kibana(Settings(api_token=TOKEN))
    with pytest.raises(KibanaError):
        Kibana(replace(settings_with_kibana(), kibana_api_key=None))
