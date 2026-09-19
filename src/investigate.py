"""The investigator: gathers evidence for a flagged domain, reaches a verdict, and proposes actions.

With Elastic Agent Builder configured, the LLM agent reasons over the same tools via `converse` and its write-up is
attached to the result. The deterministic playbook below always runs too: it is the fallback when no cluster/LLM is
available and the source of the signals that the action policy trusts (it never trusts model output for that).
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field

from .actions import ActionEngine, Signals
from .config import Settings
from .kibana import Kibana
from .report import abuse_report
from .score import KEYWORDS, score_domain, split_domain
from .security import clean_domain, clean_text
from .store import Store, clean_evidence, hit_doc
from .triage import PageFacts, fetch_page

PLAN = {"suspicious": ["notify"], "likely": ["notify", "block_domain"],
        "confirmed": ["notify", "block_domain", "file_report"]}


@dataclass
class Investigation:
    domain: str
    verdict: str = "benign"
    score: int = 0
    brand: str | None = None
    summary: str = ""
    corroboration: list[str] = field(default_factory=list)
    lures: list[dict] = field(default_factory=list)
    campaign: list[dict] = field(default_factory=list)
    lookalikes: list[dict] = field(default_factory=list)
    page: dict | None = None
    agent_summary: str | None = None
    actions: list[dict] = field(default_factory=list)
    trace: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def verdict_for(score: int, corroborations: int, threshold: int = 40) -> str:
    if score >= 70 and corroborations >= 2:
        return "confirmed"
    if (score >= 60 and corroborations >= 1) or score >= 85:
        return "likely"
    return "suspicious" if score >= threshold else "benign"


def lure_query(hit: dict) -> str:
    plain = hit["domain"].replace(".", " ").replace("-", " ")
    words = sorted(k for k in KEYWORDS if k in plain)
    return f"phishing message impersonating {hit.get('brand')}: " + " ".join(words or ["verify", "account", "login"])


class Investigator:
    def __init__(self, store: Store, engine: ActionEngine, settings: Settings, kibana: Kibana | None = None,
                 fetch: Callable[[str], Awaitable[PageFacts]] = fetch_page) -> None:
        self.store, self.engine, self.settings, self.kibana, self.fetch = store, engine, settings, kibana, fetch

    # --- signals the policy trusts (recomputed from data, never from model output) ---------------------
    def signals_for(self, domain: str) -> Signals | None:
        hit = self.store.get_hit(domain)
        if hit is None:
            return None
        brand = hit.get("brand")
        return Signals(
            score=hit["score"],
            reported=bool(self.store.reported(domain, hit.get("registered_domain", domain))),
            lure_similar=bool(brand and self.store.search_evidence(lure_query(hit), brand, size=1)),
            campaign_size=sum(r.get("domains", 0) for r in self.store.brand_window(brand, 24)) if brand else 0,
            login_form=hit.get("has_login_form"),
        )

    def report_for(self, domain: str) -> str | None:
        hit = self.store.get_hit(domain)
        if hit is None:
            return None
        signals = self.signals_for(domain)
        return abuse_report(hit, {"corroboration": signals.corroboration() if signals else []})

    # --- the investigation ----------------------------------------------------------------------------
    async def run(self, raw_domain: str) -> Investigation:
        domain = clean_domain(raw_domain)
        if domain is None:
            raise ValueError("invalid domain")
        inv = Investigation(domain=domain)
        tool = self._tracer(inv)

        hit = await asyncio.to_thread(self.store.get_hit, domain)
        if hit is None:
            scored = score_domain(domain)
            if scored.score > 0:
                hit = hit_doc(scored)
                await asyncio.to_thread(self.store.upsert_hit, domain, hit)
        tool("lookup_domain", f"score {hit['score'] if hit else 0}" + (f", brand {hit.get('brand')}" if hit else ""))
        if not hit:
            inv.summary = f"{domain} shows no lookalike indicators."
            return inv
        inv.score, inv.brand = hit["score"], hit.get("brand")
        registered = hit.get("registered_domain") or split_domain(domain)[1]

        if inv.brand:
            found = await asyncio.to_thread(self.store.search_evidence, lure_query(hit), inv.brand, 3)
            inv.lures = [self._lure(d) for d in found]
            tool("search_similar_lures", f"{len(inv.lures)} matching lures (hybrid BM25 + vector + rerank)"
                 if self.store.semantic else f"{len(inv.lures)} matching lures (BM25)")
            campaign = await asyncio.to_thread(self.store.campaigns, 24, 2)
            inv.campaign = [c for c in campaign if c.get("brand") == inv.brand]
            total = sum(c["domains"] for c in inv.campaign)
            tool("campaign_clusters", f"{total} domains in {len(inv.campaign)} cluster(s), last 24h")
        inv.lookalikes = await asyncio.to_thread(self.store.lookalikes, hit.get("label") or registered, domain, 5)
        tool("find_lookalikes", f"{len(inv.lookalikes)} similar flagged domains")

        if self.settings.triage_fetch:
            await self._triage(domain, inv, tool)

        signals = await asyncio.to_thread(self.signals_for, domain)
        inv.corroboration = signals.corroboration() if signals else []
        inv.verdict = verdict_for(inv.score, len(inv.corroboration), self.settings.threshold)
        inv.summary = (f"{domain} scored {inv.score}/100 for impersonating {inv.brand or 'a brand'}; "
                       f"{len(inv.corroboration)} corroborating signal(s). Verdict: {inv.verdict}.")

        if self.kibana:
            inv.agent_summary = await self._ask_agent(domain, tool)

        for kind in PLAN.get(inv.verdict, []):
            action = await asyncio.to_thread(self.engine.propose, domain, kind, inv.summary, "playbook")
            inv.actions.append({"id": action["id"], "kind": kind, "status": action["status"]})
        tool("propose_actions", ", ".join(f"{a['kind']}={a['status']}" for a in inv.actions) or "none")
        return inv

    # --- helpers --------------------------------------------------------------------------------------
    @staticmethod
    def _tracer(inv: Investigation) -> Callable[[str, str], None]:
        def tool(name: str, result: str) -> None:
            inv.trace.append({"step": len(inv.trace) + 1, "tool": name, "result": result})
        return tool

    @staticmethod
    def _lure(doc: dict) -> dict:
        return {"language": doc.get("language"), "type": doc.get("type"), "source": doc.get("source"),
                "snippet": clean_text(doc.get("text"), 220), "score": doc.get("_score")}

    async def _triage(self, domain: str, inv: Investigation, tool: Callable[[str, str], None]) -> None:
        facts = await self.fetch(domain)
        if facts.error:
            tool("fetch_page", f"skipped ({facts.error})")
            return
        inv.page = {"title": facts.title, "has_login_form": facts.has_login_form, "form_hosts": facts.form_hosts,
                    "ip": facts.ip, "status": facts.status}
        update = {"has_login_form": facts.has_login_form, "page_title": facts.title, "page_fingerprint": facts.fingerprint}
        if facts.ip:
            update["ip"] = facts.ip
        await asyncio.to_thread(self.store.upsert_hit, domain, update)
        if facts.text:
            await asyncio.to_thread(self.store.add_evidence, clean_evidence(
                {"type": "page_text", "text": facts.text, "source": "triage", "brand": inv.brand, "domains": [domain]}))
        tool("fetch_page", f"login form: {facts.has_login_form}; title: {facts.title[:60]!r}")

    async def _ask_agent(self, domain: str, tool: Callable[[str, str], None]) -> str | None:
        prompt = (f"Investigate the domain {domain}. Use your tools to check the certificate hit, similar lures, "
                  "lookalike domains and recent campaign clusters, then give a verdict with the key evidence.")
        try:
            text = await asyncio.to_thread(self.kibana.converse, self.settings.agent_id, prompt)  # type: ignore[union-attr]
        except Exception as exc:
            tool("agent_builder", f"unavailable ({type(exc).__name__})")
            return None
        tool("agent_builder", "agent reasoning attached")
        return clean_text(text, 3000) or None
