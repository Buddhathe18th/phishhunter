"""Domain sources: the live Certificate Transparency stream, or a demo replay."""
from __future__ import annotations

import asyncio
import json
import random
from typing import AsyncIterator

import websockets

CERTSTREAM_URL = "wss://certstream.calidog.io"

DEMO_DOMAINS = [
    "paypa1-secure-login.xyz", "rnicrosoft-support.top", "login.paypal.com.account-verify.click",
    "rbc-royalbank-signin.online", "shopify-billing-update.shop", "metamask-wallet-recovery.site",
    "coinbase.com.verify-account.icu", "netfIix-billing.com", "phantom-airdrop-claim.xyz",
    "uwaterloo.ca", "github.com", "blog.example.org", "paypal.com", "my-bakery-shop.ca",
]


async def certstream_domains() -> AsyncIterator[str]:
    """Yield every domain from newly issued certificates. Reconnects forever."""
    while True:
        try:
            async with websockets.connect(CERTSTREAM_URL, ping_interval=20) as ws:
                async for raw in ws:
                    msg = json.loads(raw)
                    if msg.get("message_type") != "certificate_update":
                        continue
                    for domain in msg["data"]["leaf_cert"]["all_domains"]:
                        yield domain
        except Exception as exc:  # network blips are normal for a public stream
            print(f"[ingest] certstream dropped ({exc!r}); retrying in 5s")
            await asyncio.sleep(5)


async def demo_domains() -> AsyncIterator[str]:
    """Replay a canned mix of scam and benign domains so the demo works offline."""
    while True:
        yield random.choice(DEMO_DOMAINS)
        await asyncio.sleep(random.uniform(0.4, 1.5))


if __name__ == "__main__":
    async def main() -> None:
        async for d in certstream_domains():
            print(d)

    asyncio.run(main())
