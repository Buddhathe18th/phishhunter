"""Cheap, explainable lookalike-domain scoring. No ML: every point of score has a reason."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from rapidfuzz import fuzz

# brand -> domains that legitimately belong to it
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "goog.le"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.ca", "aws.amazon.com", "amazonaws.com"},
    "netflix": {"netflix.com"},
    "shopify": {"shopify.com", "myshopify.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "phantom": {"phantom.app"},
    "royalbank": {"rbc.com", "rbcroyalbank.com", "royalbank.com"},
    "rbc": {"rbc.com", "rbcroyalbank.com", "royalbank.com"},
    "scotiabank": {"scotiabank.com"},
    "cibc": {"cibc.com"},
    "bmo": {"bmo.com"},
}

KEYWORDS = {"login", "signin", "secure", "verify", "account", "update", "support",
            "wallet", "auth", "billing", "recovery", "confirm", "airdrop"}
RISKY_TLDS = {"xyz", "top", "click", "zip", "mov", "icu", "buzz", "cfd", "sbs", "shop",
              "live", "site", "online", "support", "work", "tk", "ml", "ga"}
MULTIPART_SUFFIXES = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "org.uk"}

# Sequences attackers use to look like real letters. Order matters: longest first.
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"),
              ("3", "e"), ("5", "s"), ("@", "a"), ("$", "s")]

DEFENSIVE_PREFIXES = ("secure", "login", "verify", "account", "support")
DEFENSIVE_TLDS = ("xyz", "top", "click", "shop", "online")


@dataclass
class Score:
    domain: str
    score: int = 0
    brand: str | None = None
    reasons: list[str] = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        self.score += points
        self.reasons.append(reason)


def split_domain(domain: str) -> tuple[str, str, str]:
    """Return (subdomain, registered_domain, tld). Naive on purpose: no network lookups."""
    domain = domain.lower().strip().lstrip("*.").rstrip(".")
    labels = domain.split(".")
    if len(labels) < 2:
        return "", domain, ""
    take = 3 if ".".join(labels[-2:]) in MULTIPART_SUFFIXES and len(labels) >= 3 else 2
    registered = ".".join(labels[-take:])
    sub = ".".join(labels[:-take])
    return sub, registered, labels[-1]


def demangle(text: str) -> str:
    for fake, real in HOMOGLYPHS:
        text = text.replace(fake, real)
    return text


def score_domain(domain: str) -> Score:
    result = Score(domain=domain.lower().lstrip("*."))
    sub, registered, tld = split_domain(domain)

    if any(registered in legit for legit in BRANDS.values()):
        return result  # a real brand domain: score 0

    label = registered.rsplit(".", 1)[0] if "." in registered else registered
    haystack = f"{sub}.{label}" if sub else label
    tokens = [t for t in re.split(r"[.\-_]", haystack) if t]
    plain = haystack.replace(".", "").replace("-", "")
    demangled = demangle(plain)

    for brand in BRANDS:
        if brand in tokens:
            where = "in subdomain" if sub and brand in sub.split(".") else "as a word"
            result.add(50, f"contains brand '{brand}' {where} but is not their domain")
        elif len(brand) >= 4 and brand in plain:
            result.add(45, f"embeds brand '{brand}' inside another string")
        elif len(brand) >= 4 and brand in demangled and brand not in plain:
            result.add(60, f"homoglyph trick: reads as '{brand}' after swapping look-alike characters")
        elif len(brand) >= 5:
            for token in tokens:
                if token != brand and fuzz.ratio(token, brand) >= 85:
                    result.add(45, f"'{token}' is a near-miss of '{brand}' (typosquat)")
                    break
        if result.brand is None and result.score > 0:
            result.brand = brand
        if result.score >= 45:
            break

    hits = sorted(k for k in KEYWORDS if k in plain)
    if hits and result.score > 0:
        result.add(min(20, 10 * len(hits)), f"credential-bait keywords: {', '.join(hits)}")
    if result.score > 0:
        if tld in RISKY_TLDS:
            result.add(10, f"low-reputation TLD .{tld}")
        if "xn--" in domain:
            result.add(15, "punycode (internationalized) domain")
        if haystack.count("-") >= 2:
            result.add(5, "multiple hyphens")

    result.score = min(result.score, 100)
    return result


def suggest_defensive_domains(brand: str, limit: int = 8) -> list[str]:
    """Domains nobody has registered yet that fit the same patterns attackers use against this brand.

    Purely generative from the brand name: no lookup, no registration check, no claim that any of these exist
    or are malicious. It is the scorer run in reverse, so a brand owner (or this tool's own operator) can pre-stage
    monitoring or defensive registration instead of only ever reacting after a certificate is already issued.
    """
    if brand not in BRANDS or len(brand) < 3:
        return []
    variants: set[str] = set()
    for pre in DEFENSIVE_PREFIXES:
        variants.add(f"{pre}-{brand}")
        variants.add(f"{brand}-{pre}")
    for fake, real in HOMOGLYPHS:
        if real in brand and fake.isalnum():  # skip '@'/'$': valid as a display trick, not as a DNS label
            variants.add(brand.replace(real, fake, 1))
    variants.add(brand[:-2] + brand[-1] + brand[-2])  # last two letters swapped
    variants.add(brand[0] * 2 + brand[1:])            # doubled first letter

    out: list[str] = []
    for v in sorted(variants):
        for tld in DEFENSIVE_TLDS:
            out.append(f"{v}.{tld}")
            if len(out) >= limit:
                return out
    return out
