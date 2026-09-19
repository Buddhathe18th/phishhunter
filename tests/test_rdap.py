import httpx
import pytest

from src import rdap


class FakeTransport(httpx.BaseTransport):
    """Serves the IANA bootstrap file and canned per-domain RDAP responses, no network."""

    def __init__(self, domain_responses: dict[str, httpx.Response]):
        self.domain_responses = domain_responses

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == rdap.BOOTSTRAP_URL:
            return httpx.Response(200, json={"services": [[["com"], ["https://rdap.example/com"]],
                                                           [["xyz"], ["https://rdap.example/xyz"]]]})
        for domain, resp in self.domain_responses.items():
            if url.endswith(f"/domain/{domain}"):
                return resp
        return httpx.Response(404, json={})


@pytest.fixture(autouse=True)
def _reset_bootstrap_cache():
    rdap._bootstrap, rdap._bootstrap_at = {}, 0.0
    yield
    rdap._bootstrap, rdap._bootstrap_at = {}, 0.0


def client_for(domain_responses: dict[str, httpx.Response]) -> httpx.Client:
    return httpx.Client(transport=FakeTransport(domain_responses))


def test_returns_age_from_registration_event():
    resp = httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                                                 {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}]})
    result = rdap.lookup_domain_age("example.com", client=client_for({"example.com": resp}))
    assert result.error is None
    assert result.registered_at == "2020-01-01T00:00:00Z"
    assert result.age_days > 1000


def test_unsupported_tld_fails_closed():
    result = rdap.lookup_domain_age("example.unsupportedtld", client=client_for({}))
    assert result.age_days is None
    assert "no RDAP server" in result.error


def test_not_found_fails_closed():
    result = rdap.lookup_domain_age("example.xyz", client=client_for({"example.xyz": httpx.Response(404)}))
    assert result.age_days is None and result.error == "not found in registry"


def test_missing_registration_event_fails_closed():
    resp = httpx.Response(200, json={"events": [{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}]})
    result = rdap.lookup_domain_age("example.com", client=client_for({"example.com": resp}))
    assert result.age_days is None and "no registration event" in result.error


def test_transport_error_fails_closed_not_raises():
    class Boom(httpx.BaseTransport):
        def handle_request(self, request):
            raise httpx.ConnectError("no route")

    result = rdap.lookup_domain_age("example.com", client=httpx.Client(transport=Boom()))
    assert result.age_days is None and result.error == "ConnectError"


def test_bootstrap_is_cached_across_calls():
    calls = []

    class CountingTransport(httpx.BaseTransport):
        def handle_request(self, request):
            calls.append(str(request.url))
            if str(request.url) == rdap.BOOTSTRAP_URL:
                return httpx.Response(200, json={"services": [[["com"], ["https://rdap.example/com"]]]})
            return httpx.Response(404)

    client = httpx.Client(transport=CountingTransport())
    rdap.lookup_domain_age("a.com", client=client)
    rdap.lookup_domain_age("b.com", client=client)
    assert calls.count(rdap.BOOTSTRAP_URL) == 1
