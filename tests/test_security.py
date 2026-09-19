import pytest

from src.config import load
from src.security import RateLimiter, clean_domain, clean_text, is_public_ip, origin_allowed, token_matches


@pytest.mark.parametrize("raw,expected", [
    ("Paypa1-Login.XYZ", "paypa1-login.xyz"),
    ("*.evil.example.com", "evil.example.com"),
    ("example.com.", "example.com"),
    ("xn--pypal-4ve.com", "xn--pypal-4ve.com"),
])
def test_clean_domain_accepts(raw, expected):
    assert clean_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "evil.com\nBcc: victim@example.com",   # header injection
    "a b.com", "evil.com/path", "evil.com:8080", "user@evil.com", "-bad.com", "bad-.com",
    "localhost", "", "127.0.0.1", "a" * 64 + ".com", "x." * 130 + "com", "exa_mple.com", "évil.com", None, 42,
])
def test_clean_domain_rejects(raw):
    assert clean_domain(raw) is None


def test_clean_text_strips_controls_and_caps():
    assert clean_text("a\x00b\x1bc\u0085d", 10) == "abcd"
    assert clean_text("x" * 50, 5) == "xxxxx"
    assert clean_text(None, 5) == ""


@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), ("2606:4700:4700::1111", True),
    ("127.0.0.1", False), ("10.0.0.5", False), ("192.168.1.1", False), ("172.16.0.1", False),
    ("169.254.169.254", False), ("100.64.0.1", False), ("0.0.0.0", False), ("::1", False),
    ("fe80::1", False), ("::ffff:127.0.0.1", False), ("224.0.0.1", False), ("not-an-ip", False),
])
def test_is_public_ip(ip, public):
    assert is_public_ip(ip) is public


def test_origin_check():
    assert origin_allowed(None, "localhost:8000", frozenset())
    assert origin_allowed("http://localhost:8000", "localhost:8000", frozenset())
    assert not origin_allowed("https://evil.example", "localhost:8000", frozenset())
    assert origin_allowed("https://ok.example", "localhost:8000", frozenset({"https://ok.example"}))


def test_token_matches_is_strict():
    assert token_matches("secret", "secret")
    assert not token_matches("secreT", "secret")
    assert not token_matches(None, "secret")
    assert not token_matches("", "secret")
    assert not token_matches("sécret", "secret")  # non-ASCII must not raise


def test_rate_limiter_window():
    rl = RateLimiter(limit=3, window=60)
    assert [rl.allow("a") for _ in range(4)] == [True, True, True, False]
    assert rl.allow("b")  # separate key


def test_config_rejects_weak_token_and_plain_http(monkeypatch):
    monkeypatch.setenv("API_TOKEN", "short")
    with pytest.raises(ValueError, match="24 characters"):
        load()
    monkeypatch.setenv("API_TOKEN", "x" * 32)
    monkeypatch.setenv("ELASTIC_URL", "http://es.example.com:9200")
    with pytest.raises(ValueError, match="https"):
        load()
    monkeypatch.setenv("ELASTIC_URL", "https://user:pw@es.example.com")
    with pytest.raises(ValueError, match="credentials"):
        load()
    monkeypatch.setenv("ELASTIC_URL", "http://localhost:9200")
    assert load().elastic_url == "http://localhost:9200"


def test_secrets_never_appear_in_repr(monkeypatch):
    monkeypatch.setenv("API_TOKEN", "s3cret-token-" + "x" * 20)
    monkeypatch.setenv("JINA_API_KEY", "jina_supersecret")
    monkeypatch.setenv("ELASTIC_API_KEY", "es-supersecret")
    text = repr(load())
    assert "supersecret" not in text and "s3cret-token" not in text


def test_generated_token_when_unset(monkeypatch):
    monkeypatch.delenv("API_TOKEN", raising=False)
    s = load()
    assert s.token_generated and len(s.api_token) >= 32


def test_optional_integrations_default_off(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    s = load()
    assert s.gemini_api_key is None and s.sentry_dsn is None and s.gemini_model == "gemini-flash-lite-latest"


def test_optional_integrations_read_from_env(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "gm-test")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.0-flash")
    monkeypatch.setenv("SENTRY_DSN", "https://public@o0.ingest.sentry.io/1")
    s = load()
    assert s.gemini_api_key == "gm-test" and s.gemini_model == "gemini-2.0-flash" and s.sentry_dsn is not None
    assert "gm-test" not in repr(s)  # secrets stay out of repr, same guarantee as the other keys
