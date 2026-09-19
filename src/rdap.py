"""Domain-age lookup via RDAP. No API key: the server to query comes from IANA's own public bootstrap
registry, keyed only by TLD, so unlike the page-triage fetch this never touches attacker-chosen infrastructure.

A domain registered minutes before its certificate was issued is a much stronger signal than the certificate
alone - most legitimate sites are not brand new. A lookup failure (unsupported TLD, registry down, rate limited)
just means no signal either way; it is never treated as suspicious by itself.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL = 24 * 3600
TIMEOUT = 5.0

_bootstrap: dict[str, str] = {}
_bootstrap_at = 0.0


@dataclass
class RdapResult:
    registered_at: str | None = None
    age_days: float | None = None
    error: str | None = None


def _load_bootstrap(client: httpx.Client) -> dict[str, str]:
    global _bootstrap, _bootstrap_at
    if _bootstrap and time.monotonic() - _bootstrap_at < BOOTSTRAP_TTL:
        return _bootstrap
    resp = client.get(BOOTSTRAP_URL, timeout=TIMEOUT)
    resp.raise_for_status()
    table = {tld.lower(): urls[0].rstrip("/") for tlds, urls in resp.json()["services"] for tld in tlds}
    _bootstrap, _bootstrap_at = table, time.monotonic()
    return table


def lookup_domain_age(domain: str, client: httpx.Client | None = None) -> RdapResult:
    """`domain` must already be validated by `clean_domain` - this trusts it enough to put in a URL path."""
    tld = domain.rsplit(".", 1)[-1]
    owns_client = client is None
    client = client or httpx.Client(follow_redirects=True, trust_env=False)
    try:
        base = _load_bootstrap(client).get(tld)
        if base is None:
            return RdapResult(error=f"no RDAP server for .{tld}")
        resp = client.get(f"{base}/domain/{domain}", timeout=TIMEOUT)
        if resp.status_code == 404:
            return RdapResult(error="not found in registry")
        resp.raise_for_status()
        events = resp.json().get("events", [])
        registered = next((e["eventDate"] for e in events if e.get("eventAction") == "registration"), None)
        if registered is None:
            return RdapResult(error="no registration event in response")
        reg_dt = datetime.fromisoformat(registered.replace("Z", "+00:00"))
        age_days = (datetime.now(UTC) - reg_dt).total_seconds() / 86400
        return RdapResult(registered_at=registered, age_days=round(age_days, 2))
    except Exception as exc:
        return RdapResult(error=type(exc).__name__)
    finally:
        if owns_client:
            client.close()
