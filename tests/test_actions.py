from pathlib import Path

import pytest

from src.actions import Signals, decide_auto
from src.config import Settings

from .conftest import add_hit, make_engine

BAD = "paypa1-secure-login.xyz"


def prime(store):
    """A high-scoring domain with three independent corroborating signals."""
    add_hit(store, BAD, has_login_form=True)
    add_hit(store, "paypa1-account-verify.top")
    add_hit(store, "paypal-secure-login-update.xyz")


def test_nothing_runs_unattended_by_default(store, settings):
    prime(store)
    engine, _ = make_engine(store, settings)  # auto_actions off
    action = engine.propose(BAD, "block_domain", "test")
    assert action["status"] == "pending_approval"
    assert engine.blocklist() == []


def test_auto_runs_only_with_score_and_two_signals(store, settings):
    prime(store)
    engine, _ = make_engine(store, settings, auto_actions=True, auto_score=50)
    action = engine.propose(BAD, "block_domain", "test")
    assert action["status"] == "executed" and action["policy"]["auto"]
    assert engine.blocklist() == [BAD]
    assert [h["to"] for h in action["history"]] == ["proposed", "executed"]


def test_weak_evidence_waits_for_a_human(store, settings):
    add_hit(store, "rbc-signin-secure.online")   # no login form, no report, small campaign
    engine, _ = make_engine(store, settings, auto_actions=True, auto_score=1)
    action = engine.propose("rbc-signin-secure.online", "block_domain", "test")
    assert action["status"] == "pending_approval"
    assert "corroborating" in action["policy"]["reasons"][0]


def test_third_party_actions_always_need_a_human(store, settings):
    prime(store)
    engine, _ = make_engine(store, settings, auto_actions=True, auto_score=1)
    action = engine.propose(BAD, "file_report", "test")
    assert action["status"] == "pending_approval"
    assert not list(Path(settings.outbox_dir).glob("*"))       # nothing written until approved
    done = engine.approve(action["id"], by="alex")
    assert done["status"] == "executed"
    written = Path(settings.outbox_dir) / f"{BAD}.txt"
    assert written.exists() and BAD in written.read_text(encoding="utf-8")


def test_reject_and_rejection_blocks_future_auto(store, settings):
    prime(store)
    engine, _ = make_engine(store, settings, auto_actions=True, auto_score=50)
    pending = engine.propose(BAD, "file_report", "test")
    assert engine.reject(pending["id"])["status"] == "rejected"
    later = engine.propose(BAD, "block_domain", "test")
    assert later["status"] == "pending_approval" and "rejected" in later["policy"]["reasons"][0]


def test_invalid_transitions_and_ids(store, settings):
    prime(store)
    engine, _ = make_engine(store, settings)
    action = engine.propose(BAD, "notify", "test")
    engine.approve(action["id"])
    with pytest.raises(ValueError):
        engine.approve(action["id"])           # already executed
    with pytest.raises(KeyError):
        engine.approve("0" * 32)


def test_proposals_are_deduplicated(store, settings):
    prime(store)
    engine, _ = make_engine(store, settings)
    a = engine.propose(BAD, "notify", "one")
    b = engine.propose(BAD, "notify", "two")
    assert a["id"] == b["id"]


def test_rejects_invalid_proposals(store, settings):
    engine, _ = make_engine(store, settings)
    with pytest.raises(ValueError):
        engine.propose("evil.com\nBcc: x", "notify", "x")
    with pytest.raises(ValueError):
        engine.propose(BAD, "delete_everything", "x")


def test_sweeper_polices_workflow_written_proposals(store, settings):
    """The Elastic Workflow writes raw docs; the sweeper must validate them and apply the policy."""
    prime(store)
    engine, _ = make_engine(store, settings)
    store.save_action({"id": "a" * 32, "domain": BAD, "kind": "block_domain", "status": "proposed", "source": "agent-builder"})
    store.save_action({"id": "b" * 32, "domain": "x.example", "kind": "rm -rf", "status": "proposed", "source": "agent-builder"})
    assert engine.sweep() == 2
    assert store.get_action("a" * 32)["status"] == "pending_approval"
    assert store.get_action("b" * 32)["status"] == "rejected"


def test_policy_table():
    s = Settings(auto_actions=True, auto_score=85)
    strong = Signals(score=90, reported=True, lure_similar=True)
    assert decide_auto(s, "block_domain", strong, False)[0]
    assert not decide_auto(s, "block_domain", Signals(score=90, reported=True), False)[0]
    assert not decide_auto(s, "block_domain", Signals(score=80, reported=True, lure_similar=True), False)[0]
    assert not decide_auto(s, "block_domain", None, False)[0]
    assert not decide_auto(s, "file_report", strong, False)[0]
    assert not decide_auto(Settings(auto_actions=False), "block_domain", strong, False)[0]
