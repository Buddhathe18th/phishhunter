"""Closing the loop: proposed actions, a deterministic policy gate, and executors.

The reasoning agent (an LLM reading untrusted lures and web pages) can only *propose* an action. Whether it runs
unattended is decided here by fixed rules over signals we recompute from the data, never by anything the model
says. That keeps prompt injection from turning into a takedown.

Status flow: proposed -> executed | pending_approval -> executed | rejected | failed
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx

from .config import Settings
from .security import clean_domain
from .store import Store, now_iso

AUTO_KINDS = {"block_domain", "notify"}        # low blast radius: internal blocklist + a chat message
HUMAN_KINDS = {"file_report"}                  # anything addressed to a third party needs a person
KINDS = AUTO_KINDS | HUMAN_KINDS
OPEN_STATUSES = {"proposed", "pending_approval", "executed"}


YOUNG_DOMAIN_DAYS = 7  # a domain registered this recently is itself a signal, independent of the scorer


@dataclass
class Signals:
    score: int
    reported: bool = False          # this exact domain is already named in collected evidence
    lure_similar: bool = False      # evidence for the same brand matched by hybrid search
    campaign_size: int = 0          # other flagged domains for the same brand in the last 24h
    login_form: bool | None = None  # None = page not fetched
    domain_age_days: float | None = None  # None = RDAP lookup unavailable/failed, not "old"

    def corroboration(self) -> list[str]:
        found = []
        if self.reported:
            found.append("domain named in collected reports")
        if self.lure_similar:
            found.append("matches known lure text for the brand")
        if self.campaign_size >= 3:
            found.append(f"part of a burst of {self.campaign_size} lookalike domains")
        if self.login_form:
            found.append("live page has a password form")
        if self.domain_age_days is not None and self.domain_age_days < YOUNG_DOMAIN_DAYS:
            found.append(f"domain registered only {self.domain_age_days:.1f} days ago")
        return found


SignalsFn = Callable[[str], Signals | None]
ReportFn = Callable[[str], str | None]


def decide_auto(settings: Settings, kind: str, signals: Signals | None, previously_rejected: bool) -> tuple[bool, list[str]]:
    """The whole autonomy policy. Returns (may_run_unattended, reasons)."""
    if kind not in AUTO_KINDS:
        return False, [f"'{kind}' is addressed to a third party and always needs a human"]
    if not settings.auto_actions:
        return False, ["unattended actions are disabled (AUTO_ACTIONS=0)"]
    if signals is None:
        return False, ["no evidence available for this domain"]
    if previously_rejected:
        return False, ["a human previously rejected an action on this domain"]
    if signals.score < settings.auto_score:
        return False, [f"score {signals.score} is below the unattended threshold {settings.auto_score}"]
    corroboration = signals.corroboration()
    if len(corroboration) < 2:
        return False, [f"needs 2+ independent corroborating signals, found {len(corroboration)}"]
    return True, [f"score {signals.score} >= {settings.auto_score}", *corroboration]


class ActionEngine:
    def __init__(self, store: Store, settings: Settings, signals_fn: SignalsFn, report_fn: ReportFn,
                 http: httpx.Client | None = None) -> None:
        self.store, self.settings = store, settings
        self.signals_fn, self.report_fn = signals_fn, report_fn
        self.http = http

    # --- lifecycle ------------------------------------------------------------------------------------
    def propose(self, domain: str, kind: str, rationale: str, source: str = "agent") -> dict:
        domain_ok = clean_domain(domain)
        if domain_ok is None or kind not in KINDS:
            raise ValueError("invalid domain or action kind")
        for existing in self.store.list_actions(limit=500):
            if existing["domain"] == domain_ok and existing["kind"] == kind and existing["status"] in OPEN_STATUSES:
                return existing
        action = {"id": self.store.new_action_id(), "domain": domain_ok, "kind": kind, "status": "proposed",
                  "source": source, "rationale": rationale[:500], "created": now_iso(), "updated": now_iso(),
                  "policy": {}, "history": [{"at": now_iso(), "by": source, "to": "proposed", "note": rationale[:200]}]}
        self.store.save_action(action)
        return self.evaluate(action)

    def evaluate(self, action: dict) -> dict:
        action.setdefault("history", [])  # proposals written by the Elastic Workflow arrive without one
        action.setdefault("created", now_iso())
        if clean_domain(action.get("domain")) != action.get("domain") or action.get("kind") not in KINDS:
            return self._move(action, "rejected", "policy", "invalid domain or action kind in proposal")
        rejected = any(a["domain"] == action["domain"] and a["status"] == "rejected" for a in self.store.list_actions(limit=500))
        auto, reasons = decide_auto(self.settings, action["kind"], self.signals_fn(action["domain"]), rejected)
        action["policy"] = {"auto": auto, "reasons": reasons}
        if auto:
            return self._execute(action, by="policy")
        return self._move(action, "pending_approval", "policy", "; ".join(reasons))

    def approve(self, action_id: str, by: str = "human") -> dict:
        action = self._require(action_id, {"pending_approval"})
        return self._execute(action, by=by)

    def reject(self, action_id: str, by: str = "human") -> dict:
        action = self._require(action_id, {"pending_approval", "proposed"})
        return self._move(action, "rejected", by, "rejected by reviewer")

    def sweep(self) -> int:
        """Evaluate proposals written by the Elastic Workflow (which can't run our policy itself)."""
        pending = self.store.list_actions("proposed")
        for action in pending:
            self.evaluate(action)
        return len(pending)

    def blocklist(self) -> list[str]:
        rows = self.store.list_actions("executed", limit=1000)
        return sorted({a["domain"] for a in rows if a["kind"] == "block_domain"})

    # --- internals ------------------------------------------------------------------------------------
    def _require(self, action_id: str, allowed: set[str]) -> dict:
        action = self.store.get_action(action_id)
        if action is None:
            raise KeyError(action_id)
        if action["status"] not in allowed:
            raise ValueError(f"action is {action['status']}, not one of {sorted(allowed)}")
        return action

    def _move(self, action: dict, status: str, by: str, note: str) -> dict:
        action["status"], action["updated"] = status, now_iso()
        action["history"].append({"at": now_iso(), "by": by, "to": status, "note": note[:300]})
        self.store.save_action(action)
        return action

    def _execute(self, action: dict, by: str) -> dict:
        try:
            note = {"block_domain": self._block, "notify": self._notify, "file_report": self._file_report}[action["kind"]](action)
        except Exception as exc:
            return self._move(action, "failed", by, f"{type(exc).__name__}: {str(exc)[:120]}")
        return self._move(action, "executed", by, note)

    def _block(self, action: dict) -> str:
        return "added to the blocklist feed (/blocklist.txt)"

    def _notify(self, action: dict) -> str:
        if not self.settings.webhook_url:
            return "no ACTION_WEBHOOK_URL configured; recorded only"
        text = f"doppel: {action['kind']} for {action['domain']} - {action['rationale'][:200]}"
        client = self.http or httpx.Client(timeout=5.0, follow_redirects=False, trust_env=False)
        resp = client.post(self.settings.webhook_url, json={"text": text})
        resp.raise_for_status()
        return "webhook notified"

    def _file_report(self, action: dict) -> str:
        report = self.report_fn(action["domain"])
        if not report:
            raise ValueError("no report available")
        base = Path(self.settings.outbox_dir).resolve()
        base.mkdir(parents=True, exist_ok=True)
        target = (base / f"{re.sub(r'[^a-z0-9.-]', '_', action['domain'])}.txt").resolve()
        if base not in target.parents:
            raise ValueError("bad path")
        target.write_text(report, encoding="utf-8")
        return f"report written to outbox/{target.name} (not sent; a person submits it)"
