import asyncio

import httpx
import pytest

from src.triage import fetch_page, parse_page, resolve_public

LOGIN_HTML = """<html><head><title>PayPal - Log in</title><script>steal()</script></head>
<body><h1>Log in</h1><form action="https://collector.example.net/x"><input name=e><input type=PASSWORD name=p></form>
<style>.a{}</style></body></html>"""


def run(coro):
    return asyncio.run(coro)


def test_parse_page_finds_login_form_and_ignores_scripts():
    facts = parse_page(LOGIN_HTML, "https://paypa1.example/")
    assert facts.has_login_form and facts.title == "PayPal - Log in"
    assert facts.form_hosts == ["collector.example.net"]
    assert "steal" not in facts.text and "Log in" in facts.text
    assert facts.fingerprint


def test_parse_page_survives_garbage():
    facts = parse_page("<<<>>><form><input type=password" + "<div>" * 5000)
    assert isinstance(facts.has_login_form, bool)


def test_resolve_public_rejects_private_and_mixed():
    with pytest.raises(ValueError):
        resolve_public("x.example", lambda h: ["10.0.0.1"])
    with pytest.raises(ValueError):  # one bad address poisons the set (DNS rebinding tricks)
        resolve_public("x.example", lambda h: ["8.8.8.8", "169.254.169.254"])
    assert resolve_public("x.example", lambda h: ["8.8.8.8"]) == "8.8.8.8"


def explode(request):
    raise AssertionError("no request may be made")


def test_private_resolution_makes_no_request():
    facts = run(fetch_page("evil.example", resolver=lambda h: ["127.0.0.1"], transport=httpx.MockTransport(explode)))
    assert facts.error and "non-public" in facts.error


def test_invalid_domain_makes_no_request():
    facts = run(fetch_page("localhost", transport=httpx.MockTransport(explode)))
    assert facts.error == "invalid domain"


def test_connects_to_pinned_ip_with_host_header():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.headers["host"], request.headers.get("cookie"), request.headers["user-agent"]))
        return httpx.Response(200, headers={"content-type": "text/html"}, text=LOGIN_HTML)

    facts = run(fetch_page("paypa1.example", resolver=lambda h: ["93.184.216.34"], transport=httpx.MockTransport(handler)))
    assert facts.has_login_form and facts.ip == "93.184.216.34"
    assert seen[0][0] == "93.184.216.34" and seen[0][1] == "paypa1.example" and seen[0][2] is None
    assert seen[0][3].startswith("doppel-triage")


def test_redirect_to_internal_host_is_blocked():
    def resolver(host):
        return ["10.0.0.9"] if host == "internal.example" else ["93.184.216.34"]

    def handler(request):
        if request.headers["host"] == "internal.example":
            raise AssertionError("must not fetch internal host")
        return httpx.Response(302, headers={"location": "https://internal.example/admin"})

    facts = run(fetch_page("bait.example", resolver=resolver, transport=httpx.MockTransport(handler)))
    assert facts.error and "non-public" in facts.error


def test_redirect_to_odd_port_or_scheme_is_blocked():
    for target in ("https://bait.example:8443/", "file:///etc/passwd", "gopher://bait.example/"):
        handler = lambda r, t=target: httpx.Response(302, headers={"location": t})  # noqa: E731
        facts = run(fetch_page("bait.example", resolver=lambda h: ["93.184.216.34"], transport=httpx.MockTransport(handler)))
        assert facts.error == "blocked url", target


def test_redirect_loop_is_bounded():
    handler = lambda r: httpx.Response(302, headers={"location": "https://bait.example/"})  # noqa: E731
    facts = run(fetch_page("bait.example", resolver=lambda h: ["93.184.216.34"], transport=httpx.MockTransport(handler)))
    assert facts.error == "too many redirects"


def test_non_html_and_oversized_bodies():
    pdf = lambda r: httpx.Response(200, headers={"content-type": "application/pdf"}, content=b"%PDF")  # noqa: E731
    assert run(fetch_page("a.example", resolver=lambda h: ["8.8.8.8"], transport=httpx.MockTransport(pdf))).error == "not html"

    big = lambda r: httpx.Response(200, headers={"content-type": "text/html"}, content=b"<p>x</p>" * 400_000)  # noqa: E731
    facts = run(fetch_page("a.example", resolver=lambda h: ["8.8.8.8"], transport=httpx.MockTransport(big)))
    assert facts.error is None and len(facts.text) <= 2000
