import asyncio

import httpx
import pytest

from src.ingest import fetch_live_attack_candidate


def run(coro):
    return asyncio.run(coro)


def client_with(text: str) -> httpx.AsyncClient:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=text)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_finds_an_in_scope_candidate():
    feed = "\n".join([
        "https://random-blog-post.example/page",          # no configured brand, out of scope
        "https://paypal-secure-login.netlify.app/verify",  # in scope
        "https://another-unrelated-site.example/x",
    ])
    result = run(fetch_live_attack_candidate(client_with(feed)))
    assert result is not None
    assert result.domain == "paypal-secure-login.netlify.app"
    assert result.issuer == "OpenPhish live feed"


def test_returns_none_when_nothing_in_scope():
    feed = "https://totally-unrelated-blog.example/post\nhttps://another-one.example/page"
    result = run(fetch_live_attack_candidate(client_with(feed)))
    assert result is None


def test_returns_none_on_fetch_failure_not_raises():
    async def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    result = run(fetch_live_attack_candidate(client))
    assert result is None


def test_returns_none_on_http_error_status():
    async def not_found(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    client = httpx.AsyncClient(transport=httpx.MockTransport(not_found))
    result = run(fetch_live_attack_candidate(client))
    assert result is None


@pytest.mark.parametrize("feed", ["", "not a url at all\n\n"])
def test_handles_empty_or_garbage_feed(feed):
    result = run(fetch_live_attack_candidate(client_with(feed)))
    assert result is None
