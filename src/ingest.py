"""Domain sources: the live Certificate Transparency stream, or a demo replay."""
from __future__ import annotations

import asyncio
import json
import random
from collections.abc import AsyncIterator
from dataclasses import dataclass

import websockets

from .security import clean_text

CERTSTREAM_URL = "wss://certstream.calidog.io"

DEMO_DOMAINS = [
    "paypa1-secure-login.xyz", "rnicrosoft-support.top", "login.paypal.com.account-verify.click",
    "rbc-royalbank-signin.online", "shopify-billing-update.shop", "metamask-wallet-recovery.site",
    "coinbase.com.verify-account.icu", "netfIix-billing.com", "phantom-airdrop-claim.xyz",
    "paypa1-account-verify.top", "paypal-secure-login-update.xyz", "rbc-signin-secure.online",
    "uwaterloo.ca", "github.com", "blog.example.org", "paypal.com", "my-bakery-shop.ca",
]
DEMO_ISSUERS = ["Let's Encrypt", "Google Trust Services", "ZeroSSL"]

# A separate pool for on-demand simulation (POST /api/simulate), so triggering it live doesn't just
# repeat whatever the passive replay already happened to show.
SIMULATED_ATTACKS = [
    "binance-security-alert.xyz", "cibc-online-verify.top", "scotiabank-account-locked.click",
    "amaz0n-order-issue.shop", "bmo-signin-secure.online", "google-account-recovery-team.icu",
    "apple-id-locked-verify.xyz", "netflix-payment-declined.top",
]


@dataclass(frozen=True, slots=True)
class CertEvent:
    domain: str
    issuer: str | None = None


async def certstream_events() -> AsyncIterator[CertEvent]:
    """Yield every domain from newly issued certificates. Reconnects forever."""
    while True:
        try:
            async with websockets.connect(CERTSTREAM_URL, ping_interval=20, max_size=1_000_000) as ws:
                async for raw in ws:
                    msg = json.loads(raw)
                    if msg.get("message_type") != "certificate_update":
                        continue
                    leaf = msg["data"]["leaf_cert"]
                    issuer = clean_text((leaf.get("issuer") or {}).get("O"), 80) or None
                    for domain in leaf["all_domains"]:
                        yield CertEvent(domain, issuer)
        except Exception as exc:  # network blips are normal for a public stream
            print(f"[ingest] certstream dropped ({type(exc).__name__}); retrying in 5s")
            await asyncio.sleep(5)


async def demo_events() -> AsyncIterator[CertEvent]:
    """Replay a canned mix of scam and benign domains so the demo works offline."""
    while True:
        yield CertEvent(random.choice(DEMO_DOMAINS), random.choice(DEMO_ISSUERS))  # noqa: S311 - demo replay only
        await asyncio.sleep(random.uniform(0.4, 1.5))  # noqa: S311


if __name__ == "__main__":
    async def main() -> None:
        async for ev in certstream_events():
            print(ev.domain)

    asyncio.run(main())
