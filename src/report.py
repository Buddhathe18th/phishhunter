"""Turn a scored hit (plus its investigation) into a takedown-ready abuse report. Deterministic; no model needed.

Only validated fields go in (domains pass clean_domain, other strings are length-capped) so an attacker-chosen
certificate can't inject headers or extra lines into the report.
"""
from __future__ import annotations

from datetime import UTC, datetime

from .security import clean_text


def abuse_report(hit: dict, investigation: dict | None = None) -> str:
    when = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    domain = clean_text(hit["domain"], 253)
    brand = clean_text(hit.get("brand") or "a known brand", 40)
    reasons = "\n".join(f"  - {clean_text(r, 200)}" for r in hit.get("reasons", []))
    extra = ""
    if investigation:
        signals = investigation.get("corroboration", [])
        if signals:
            extra = "\nCorroborating evidence:\n" + "\n".join(f"  - {clean_text(s, 200)}" for s in signals) + "\n"
    return (
        f"Subject: Suspected phishing domain impersonating {brand}: {domain}\n\n"
        f"Hello,\n\n"
        f"We believe the domain {domain} is being used to impersonate {brand}. "
        f"It appeared in Certificate Transparency logs and was flagged on {when}.\n\n"
        f"Confidence score: {hit.get('score', 0)}/100. Indicators:\n{reasons}\n{extra}\n"
        f"We request that you review this domain and suspend it if it violates your abuse policy.\n"
    )
