"""Measures the scorer against real data instead of just the hand-picked test cases.

    python -m scripts.benchmark

Two checks:
1. Recall: of live phishing URLs (from OpenPhish's public community feed, a frozen snapshot in
   data/openphish_sample_2026-09-19.txt) that target one of our configured brands, how many do we flag?
   Most of the feed targets brands we haven't configured - that's expected, this is a brand-protection
   tool that only watches for the brands it's told to, not a general-purpose phishing detector. Recall is
   only meaningful on the subset that's actually in scope for us.
2. False positives: of a spot-check list of known-legitimate domains, including a few adversarial-looking
   ones that share surface features with phishing (hyphens, a brand name in an unofficial context) without
   actually impersonating anyone, how many get flagged?

This is a snapshot, not a live-updating benchmark: OpenPhish's feed changes constantly, so the numbers here
describe one point in time, not a permanent guarantee. Re-run against a fresh feed with
`curl -sL https://openphish.com/feed.txt -o data/openphish_sample_<date>.txt` to check drift.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from src.score import BRANDS, score_domain

DATA = Path(__file__).resolve().parent.parent / "data" / "openphish_sample_2026-09-19.txt"

# Known-legitimate domains, including a few that share surface features with phishing (hyphens, a brand
# name used in an unofficial-but-legitimate way) without actually impersonating a login flow.
KNOWN_GOOD = [
    "google.com", "wikipedia.org", "github.com", "stackoverflow.com", "reddit.com",
    "amazon.ca", "cloudflare.com", "mozilla.org", "python.org", "npmjs.com",
    "uwaterloo.ca", "waterloo.ca", "yorku.ca", "utoronto.ca",
    "my-bakery-shop.ca", "buy-local-produce.shop", "best-coffee-online.xyz",
    "microsoft-teams-help.uwaterloo.ca",
    "secure-checkout.shopify.com", "account-settings.google.com",
    "netflix-inc-investor-relations.com",
]


def hostnames_from(urls: list[str]) -> list[str]:
    hosts, seen = [], set()
    for u in urls:
        host = urlparse(u).hostname
        if host and host.lower() not in seen:
            seen.add(host.lower())
            hosts.append(host.lower())
    return hosts


def main() -> None:
    urls = DATA.read_text().splitlines()
    hosts = hostnames_from(urls)
    scored = [(h, score_domain(h)) for h in hosts]
    in_scope = [(h, s) for h, s in scored if s.brand]
    flagged = [(h, s) for h, s in in_scope if s.score >= 40]

    recall_pct = 100 * len(flagged) / len(in_scope) if in_scope else 0
    print(f"OpenPhish snapshot: {len(urls)} URLs, {len(hosts)} unique hostnames")
    print(f"  targeting one of our {len(BRANDS)} configured brands: {len(in_scope)}")
    print(f"  of those, flagged (score>=40): {len(flagged)}  ({recall_pct:.0f}% recall in scope)")
    for h, s in in_scope:
        mark = "caught" if s.score >= 40 else "MISSED"
        print(f"    [{mark}] {h}  score={s.score}  brand={s.brand}")

    fp = [(d, score_domain(d)) for d in KNOWN_GOOD if score_domain(d).score >= 40]
    print(f"\nKnown-legitimate spot-check: {len(KNOWN_GOOD)} domains, false positives: {len(fp)}")
    for d, s in fp:
        print(f"    FALSE POSITIVE: {d}  score={s.score}  reasons={s.reasons}")


if __name__ == "__main__":
    main()
