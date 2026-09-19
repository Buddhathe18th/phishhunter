"""Regression test against a frozen real-world sample, not just hand-picked cases (see scripts/benchmark.py
for the full report and methodology). The snapshot is fixed, so these bounds should hold indefinitely -
if a scoring change breaks one, that's a real regression, not benchmark drift.
"""
from scripts.benchmark import DATA, KNOWN_GOOD, hostnames_from, run_benchmark
from src.score import score_domain


def test_perfect_recall_on_in_scope_openphish_hits():
    urls = DATA.read_text().splitlines()
    in_scope = [(h, score_domain(h)) for h in hostnames_from(urls)]
    in_scope = [(h, s) for h, s in in_scope if s.brand]
    assert in_scope, "snapshot should contain at least a few hits on our configured brands"
    missed = [h for h, s in in_scope if s.score < 40]
    assert missed == [], f"missed known phishing domains that target a configured brand: {missed}"


def test_false_positive_rate_bounded_on_known_good():
    fp = [d for d in KNOWN_GOOD if score_domain(d).score >= 40]
    rate = len(fp) / len(KNOWN_GOOD)
    assert rate <= 0.15, f"false positive rate {rate:.0%} on known-good domains: {fp}"


def test_run_benchmark_returns_consistent_structured_data():
    r = run_benchmark()
    assert r["flagged"] == r["in_scope"] and r["recall_pct"] == 100.0
    assert r["false_positives"] == len(r["false_positive_examples"])
