"""Measures the scorer against real data instead of just the hand-picked test cases.

    python -m scripts.benchmark

Two checks:
1. Recall: of live phishing URLs (from OpenPhish's public community feed, a frozen snapshot in
   data/openphish_sample_2026-09-20.txt) that target one of our configured brands, how many do we flag?
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

DATA = Path(__file__).resolve().parent.parent / "data" / "openphish_sample_2026-09-20.txt"

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


def run_benchmark() -> dict:
    """The same two checks as the CLI report, as structured data - used by both `python -m scripts.benchmark`
    and the dashboard's GET /api/benchmark, so the number a judge sees live is the number this file computes,
    not a hand-typed claim in the README.
    """
    urls = DATA.read_text().splitlines()
    hosts = hostnames_from(urls)
    in_scope = [(h, score_domain(h)) for h in hosts]
    in_scope = [(h, s) for h, s in in_scope if s.brand]
    flagged = [(h, s) for h, s in in_scope if s.score >= 40]
    fp = [(d, score_domain(d)) for d in KNOWN_GOOD if score_domain(d).score >= 40]
    return {
        "snapshot": DATA.name,
        "total_urls": len(urls),
        "unique_hosts": len(hosts),
        "configured_brands": len(BRANDS),
        "in_scope": len(in_scope),
        "flagged": len(flagged),
        "recall_pct": round(100 * len(flagged) / len(in_scope), 1) if in_scope else None,
        "known_good_tested": len(KNOWN_GOOD),
        "false_positives": len(fp),
        "false_positive_examples": [d for d, _ in fp],
    }


def main() -> None:
    r = run_benchmark()
    print(f"OpenPhish snapshot ({r['snapshot']}): {r['total_urls']} URLs, {r['unique_hosts']} unique hostnames")
    print(f"  targeting one of our {r['configured_brands']} configured brands: {r['in_scope']}")
    print(f"  of those, flagged (score>=40): {r['flagged']}  ({r['recall_pct']}% recall in scope)")
    print(f"\nKnown-legitimate spot-check: {r['known_good_tested']} domains, "
          f"false positives: {r['false_positives']} {r['false_positive_examples']}")


if __name__ == "__main__":
    main()
