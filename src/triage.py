"""Second-stage triage: fetch a suspect page in isolation and extract facts from it.

Hardening (the domain is attacker-controlled, so treat the fetch as hostile territory):
  * opt-in only (TRIAGE_FETCH=1) and only for domains that already scored above the threshold
  * DNS is resolved once, every address must be globally routable, and we connect to that exact IP
    (no DNS-rebinding, no reaching loopback / RFC1918 / cloud-metadata addresses)
  * http/https on the default ports only, max 3 redirects (each hop re-validated), 5s timeout, 512 KB cap
  * no cookies, no auth headers, no JavaScript execution; HTML is parsed to text, never rendered or stored raw
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

from .security import clean_domain, clean_text, is_public_ip

MAX_BYTES = 512 * 1024
MAX_REDIRECTS = 3
TIMEOUT = 5.0
USER_AGENT = "phishhunter-triage/1.0 (defensive research; +https://github.com/Buddhathe18th/phishhunter)"

Resolver = Callable[[str], list[str]]


@dataclass
class PageFacts:
    final_host: str = ""
    ip: str | None = None
    status: int | None = None
    title: str = ""
    text: str = ""
    has_login_form: bool = False
    form_hosts: list[str] = field(default_factory=list)
    fingerprint: str | None = None
    error: str | None = None


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title, self.chunks, self.forms = "", [], []
        self._skip = 0
        self._in_title = False
        self._form_action: str | None = None
        self._form_has_password = False
        self.password_seen = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = dict(attrs)
        if tag in {"script", "style", "noscript"}:
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "form":
            self._form_action, self._form_has_password = a.get("action") or "", False
        elif tag == "input" and (a.get("type") or "").lower() == "password":
            self.password_seen = self._form_has_password = True

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False
        elif tag == "form" and self._form_action is not None:
            self.forms.append((self._form_action, self._form_has_password))
            self._form_action = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        elif not self._skip and data.strip():
            self.chunks.append(data.strip())


def parse_page(html: str, base_url: str = "") -> PageFacts:
    """Pure HTML -> facts. Safe to call on any string."""
    ex = _Extractor()
    with contextlib.suppress(Exception):  # malformed HTML is normal on phishing pages; keep whatever parsed
        ex.feed(html[:MAX_BYTES])
        ex.close()
    hosts = sorted({urlparse(urljoin(base_url, action)).hostname or "" for action, has_pw in ex.forms if has_pw} - {""})
    facts = PageFacts(
        title=clean_text(ex.title.strip(), 200),
        text=clean_text(" ".join(ex.chunks), 2000),
        has_login_form=ex.password_seen,
        form_hosts=hosts[:5],
    )
    shape = f"{facts.title}|{sorted(hosts)}|{len(ex.forms)}|{ex.password_seen}"
    facts.fingerprint = hashlib.sha256(shape.encode()).hexdigest()[:16]
    return facts


def _default_resolver(host: str) -> list[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})


def resolve_public(host: str, resolver: Resolver = _default_resolver) -> str:
    """Resolve `host` and return one public IP, or raise ValueError if any address is non-public."""
    addresses = resolver(host)
    if not addresses:
        raise ValueError("no addresses")
    if not all(is_public_ip(a) for a in addresses):
        raise ValueError("resolves to a non-public address")
    return addresses[0]


async def fetch_page(domain: str, *, resolver: Resolver = _default_resolver,
                     transport: httpx.AsyncBaseTransport | None = None) -> PageFacts:
    """Fetch https://domain/ (falling back to http) under the restrictions above. Never raises."""
    host = clean_domain(domain)
    if host is None:
        return PageFacts(error="invalid domain")
    for scheme in ("https", "http"):
        facts = await _fetch(f"{scheme}://{host}/", resolver, transport)
        if facts.error is None or scheme == "http":
            return facts
    return facts  # pragma: no cover


async def _fetch(url: str, resolver: Resolver, transport: httpx.AsyncBaseTransport | None) -> PageFacts:
    ip: str | None = None
    try:
        async with httpx.AsyncClient(transport=transport, timeout=TIMEOUT, follow_redirects=False, trust_env=False,
                                     headers={"User-Agent": USER_AGENT}) as client:
            for _ in range(MAX_REDIRECTS + 1):
                parsed = urlparse(url)
                host = clean_domain(parsed.hostname or "")
                if parsed.scheme not in {"http", "https"} or host is None or parsed.port not in (None, 80, 443):
                    return PageFacts(error="blocked url")
                ip = await asyncio.to_thread(resolve_public, host, resolver)
                pinned = f"{parsed.scheme}://{f'[{ip}]' if ':' in ip else ip}{parsed.path or '/'}"
                if parsed.query:
                    pinned += f"?{parsed.query}"
                async with client.stream("GET", pinned, headers={"Host": host},
                                         extensions={"sni_hostname": host}) as resp:
                    if resp.is_redirect and (loc := resp.headers.get("location")):
                        url = urljoin(url, loc)
                        continue
                    ctype = resp.headers.get("content-type", "")
                    if "html" not in ctype.lower():
                        return PageFacts(final_host=host, ip=ip, status=resp.status_code, error="not html")
                    body = b""
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) >= MAX_BYTES:
                            break
                    facts = parse_page(body.decode(resp.encoding or "utf-8", errors="replace"), url)
                    facts.final_host, facts.ip, facts.status = host, ip, resp.status_code
                    return facts
            return PageFacts(ip=ip, error="too many redirects")
    except ValueError as exc:
        return PageFacts(ip=ip, error=f"blocked: {exc}")
    except Exception as exc:  # unreachable hosts are the common case for takedown-bound domains
        return PageFacts(ip=ip, error=type(exc).__name__)
