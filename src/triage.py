"""Second-stage triage: fetch the suspect page in isolation and explain it.

TODO (milestone 2):
  1. Fetch the page with httpx (short timeout, no cookies, no JS, size cap) - never from your own
     credentials/session, and only for domains that already scored above the threshold.
  2. Detect a login form / brand logo clone with plain HTML parsing.
  3. Optionally ask a model (OpenAI / Gemini / Baseten) to write a 2-sentence explanation.
"""
from __future__ import annotations

from .score import Score


async def triage(hit: Score) -> Score:
    return hit  # placeholder: returns the hit unchanged
