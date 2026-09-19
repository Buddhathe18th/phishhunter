"""Turn a scored hit into a takedown-ready abuse report (deterministic; no model needed)."""
from __future__ import annotations

from datetime import datetime, timezone

from .score import Score


def abuse_report(hit: Score) -> str:
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    reasons = "\n".join(f"  - {r}" for r in hit.reasons)
    return (
        f"Subject: Suspected phishing domain impersonating {hit.brand or 'a known brand'}: {hit.domain}\n\n"
        f"Hello,\n\n"
        f"We believe the domain {hit.domain} is being used to impersonate "
        f"{hit.brand or 'a known brand'}. It appeared in Certificate Transparency logs on {when}.\n\n"
        f"Confidence score: {hit.score}/100. Indicators:\n{reasons}\n\n"
        f"We request that you review this domain and suspend it if it violates your abuse policy.\n"
    )
