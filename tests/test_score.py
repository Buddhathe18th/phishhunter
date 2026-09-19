import pytest

from src.score import score_domain, split_domain

BAD = [
    "paypa1-secure-login.xyz",
    "rnicrosoft-support.top",
    "login.paypal.com.account-verify.click",
    "rbc-royalbank-signin.online",
    "coinbase.com.verify-account.icu",
    "metamask-wallet-recovery.site",
]

GOOD = [
    "paypal.com",
    "www.paypal.com",
    "github.com",
    "uwaterloo.ca",
    "my-bakery-shop.ca",
    "blog.example.org",
]


@pytest.mark.parametrize("domain", BAD)
def test_flags_known_bad(domain):
    assert score_domain(domain).score >= 40, score_domain(domain)


@pytest.mark.parametrize("domain", GOOD)
def test_ignores_benign(domain):
    assert score_domain(domain).score < 40, score_domain(domain)


def test_real_brand_domain_scores_zero():
    assert score_domain("paypal.com").score == 0


def test_wildcard_is_stripped():
    assert score_domain("*.paypa1-login.xyz").domain == "paypa1-login.xyz"


def test_split_domain_handles_multipart_tld():
    assert split_domain("a.b.example.co.uk") == ("a.b", "example.co.uk", "uk")


def test_reasons_explain_score():
    result = score_domain("paypa1-secure-login.xyz")
    assert result.reasons and result.brand == "paypal"
