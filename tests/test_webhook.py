import json
import logging
from datetime import UTC, datetime, timedelta, timezone

import httpx
import pytest

from intel_feeds import webhook
from intel_feeds.config import CATEGORIES
from intel_feeds.webhook import WebhookError, build_embed, post_embed, send_test_posts

SECRET = "https://webhook.invalid/api/webhooks/0/sentinel-token"


class FakeDiscord:
    """Answers each request with the next scripted response and records it."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request):
        self.requests.append(request)
        reply = self.responses.pop(0) if self.responses else httpx.Response(200, json={})
        if isinstance(reply, Exception):
            raise reply
        return reply

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))

    def payload(self, i=0):
        return json.loads(self.requests[i].content)


@pytest.fixture
def sleeps(monkeypatch):
    calls = []
    monkeypatch.setattr(webhook, "_sleep", calls.append)
    return calls


def embed():
    return build_embed(title="t", category="news", source="s")


# --- build_embed ---------------------------------------------------------


def test_embed_has_title_link_source_time_excerpt_and_color():
    published = datetime(2026, 11, 18, 9, 30, tzinfo=timezone(timedelta(hours=-5)))
    e = build_embed(
        title="  CISA adds 2 KEVs  ",
        category="vulns",
        source="CISA KEV",
        url="https://example.com/a",
        published=published,
        excerpt="  Two flaws.  ",
    )
    assert e == {
        "title": "CISA adds 2 KEVs",
        "url": "https://example.com/a",
        "color": webhook.COLORS["vulns"],
        "author": {"name": "CISA KEV"},
        "description": "Two flaws.",
        "timestamp": "2026-11-18T14:30:00+00:00",
    }


def test_embed_treats_a_naive_time_as_utc_and_omits_empty_fields():
    e = build_embed(title="", category="news", source="s", published=datetime(2026, 1, 2, 3, 4))
    assert e["title"] == "(untitled)"
    assert e["timestamp"] == "2026-01-02T03:04:00+00:00"
    assert "url" not in e and "description" not in e


def test_embed_clips_long_text_to_discord_limits():
    e = build_embed(title="x" * 1000, category="news", source="y" * 1000, excerpt="z" * 5000)
    assert len(e["title"]) == webhook.TITLE_LIMIT and e["title"].endswith("…")
    assert len(e["description"]) == webhook.EXCERPT_LIMIT
    assert len(e["author"]["name"]) == webhook.AUTHOR_LIMIT


def test_embed_author_line_takes_the_source_link_and_icon():
    e = build_embed(
        title="t", category="news", source="  Krebs  ",
        source_url="https://krebsonsecurity.com/", source_icon="https://example.com/i.png",
    )
    assert e["author"] == {
        "name": "Krebs",
        "url": "https://krebsonsecurity.com/",
        "icon_url": "https://example.com/i.png",
    }
    assert "footer" not in e
    assert build_embed(title="t", category="news", source=" ")["author"] == {"name": "(unknown source)"}


def test_every_category_has_a_color():
    assert set(CATEGORIES) <= webhook.COLORS.keys()


# --- post_embed ----------------------------------------------------------


def test_posts_embed_with_wait_and_mentions_disabled(sleeps):
    discord = FakeDiscord(httpx.Response(200, json={"id": "1"}))
    post_embed(discord.client(), SECRET, embed(), label="WEBHOOK_NEWS")
    (request,) = discord.requests
    assert request.method == "POST"
    assert request.url.params["wait"] == "true"
    body = discord.payload()
    assert body["embeds"] == [embed()]
    assert body["allowed_mentions"] == {"parse": []}
    assert "content" not in body
    assert sleeps == []


def test_allowed_mentions_and_content_can_be_given():
    discord = FakeDiscord()
    mentions = {"parse": ["everyone"]}
    post_embed(
        discord.client(), SECRET, embed(), label="WEBHOOK_VULNS",
        allowed_mentions=mentions, content="@everyone",
    )
    body = discord.payload()
    assert body["allowed_mentions"] == mentions
    assert body["content"] == "@everyone"


def test_429_waits_for_retry_after_then_retries(sleeps):
    discord = FakeDiscord(
        httpx.Response(429, json={"retry_after": 1.5, "global": False}),
        httpx.Response(429, headers={"Retry-After": "2"}),
        httpx.Response(200, json={}),
    )
    post_embed(discord.client(), SECRET, embed(), label="WEBHOOK_NEWS")
    assert len(discord.requests) == 3
    assert sleeps == [1.5, 2.0]


def test_429_longer_than_the_limit_fails_without_waiting(sleeps):
    discord = FakeDiscord(httpx.Response(429, json={"retry_after": 600}))
    with pytest.raises(WebhookError, match="rate limited by Discord for 600s"):
        post_embed(discord.client(), SECRET, embed(), label="WEBHOOK_NEWS")
    assert sleeps == [] and len(discord.requests) == 1


def test_5xx_retries_with_exponential_backoff_then_succeeds(sleeps):
    discord = FakeDiscord(
        httpx.Response(502), httpx.Response(503), httpx.Response(500), httpx.Response(200)
    )
    post_embed(discord.client(), SECRET, embed(), label="WEBHOOK_NEWS")
    assert len(discord.requests) == 4
    assert sleeps == [1.0, 2.0, 4.0]


def test_5xx_gives_up_after_the_last_attempt(sleeps):
    discord = FakeDiscord(*[httpx.Response(503)] * 5)
    with pytest.raises(WebhookError, match="HTTP 503 after 4 attempts"):
        post_embed(discord.client(), SECRET, embed(), label="WEBHOOK_NEWS")
    assert len(discord.requests) == webhook.MAX_ATTEMPTS
    assert sleeps == [1.0, 2.0, 4.0]


def test_network_errors_are_retried(sleeps):
    discord = FakeDiscord(httpx.ConnectTimeout("timed out"), httpx.Response(200))
    post_embed(discord.client(), SECRET, embed(), label="WEBHOOK_NEWS")
    assert len(discord.requests) == 2 and sleeps == [1.0]


@pytest.mark.parametrize("status", [401, 403, 404])
def test_rejected_webhook_is_not_retried_and_names_the_variable(status, sleeps):
    discord = FakeDiscord(httpx.Response(status, json={"message": "Unknown Webhook", "code": 10015}))
    with pytest.raises(WebhookError) as exc:
        post_embed(discord.client(), SECRET, embed(), label="WEBHOOK_RESEARCH")
    assert f"HTTP {status}" in str(exc.value)
    assert "update WEBHOOK_RESEARCH" in str(exc.value)
    assert len(discord.requests) == 1 and sleeps == []


def test_bad_request_shows_discords_message():
    discord = FakeDiscord(httpx.Response(400, json={"message": "Invalid Form Body", "code": 50035}))
    with pytest.raises(WebhookError, match=r"HTTP 400\): Invalid Form Body \(code 50035\)"):
        post_embed(discord.client(), SECRET, embed(), label="WEBHOOK_NEWS")


def test_waits_when_the_rate_limit_bucket_is_empty(sleeps):
    discord = FakeDiscord(
        httpx.Response(
            200, json={}, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset-After": "0.8"}
        )
    )
    post_embed(discord.client(), SECRET, embed(), label="WEBHOOK_NEWS")
    assert sleeps == [0.8]


@pytest.mark.parametrize("bad", ["http://discord.com/api/webhooks/1/x", "discord.com/x", ""])
def test_non_https_url_fails_before_any_request(bad):
    discord = FakeDiscord()
    with pytest.raises(WebhookError, match="WEBHOOK_NEWS is not an https URL"):
        post_embed(discord.client(), bad, embed(), label="WEBHOOK_NEWS")
    assert discord.requests == []


def test_failures_never_reveal_the_url(caplog, sleeps):
    """Log at DEBUG everywhere (httpx included) and check every message."""
    caplog.set_level(logging.DEBUG)
    failures = [
        FakeDiscord(*[httpx.ConnectError(f"cannot connect to {SECRET}")] * 5),
        FakeDiscord(*[httpx.Response(503, text=SECRET)] * 5),
        FakeDiscord(httpx.Response(404, text=SECRET)),
        FakeDiscord(httpx.Response(429, json={"retry_after": 999})),
    ]
    messages = []
    for discord in failures:
        with pytest.raises(WebhookError) as exc:
            post_embed(discord.client(), SECRET, embed(), label="WEBHOOK_NEWS")
        messages.append(str(exc.value))
        assert exc.value.__suppress_context__ or exc.value.__context__ is None
    post_embed(FakeDiscord().client(), SECRET, embed(), label="WEBHOOK_NEWS")
    everything = caplog.text + "\n".join(messages)
    assert "WEBHOOK_NEWS" in everything
    assert "sentinel-token" not in everything
    assert "/api/webhooks/" not in everything


# --- send_test_posts -----------------------------------------------------


def test_test_posts_go_to_every_set_webhook_in_order():
    discord = FakeDiscord()
    env = {
        "WEBHOOK_NEWS": SECRET + "/news",
        "WEBHOOK_VULNS": SECRET + "/vulns",
        "WEBHOOK_OPS": SECRET + "/ops",
        "WEBHOOK_RESEARCH": "  ",
    }
    results = send_test_posts(discord.client(), env)
    assert results == [
        ("WEBHOOK_NEWS", "posted"),
        ("WEBHOOK_VULNS", "posted"),
        ("WEBHOOK_ADVISORIES", "skipped (not set)"),
        ("WEBHOOK_RESEARCH", "skipped (not set)"),
        ("WEBHOOK_RANSOM", "skipped (not set)"),
        ("WEBHOOK_OPS", "posted"),
    ]
    assert [r.url.path.rsplit("/", 1)[1] for r in discord.requests] == ["news", "vulns", "ops"]
    colors = [discord.payload(i)["embeds"][0]["color"] for i in range(3)]
    assert colors == [webhook.COLORS[c] for c in ("news", "vulns", "ops")]
    first = discord.payload(0)["embeds"][0]
    assert "test post" in first["title"]
    assert datetime.fromisoformat(first["timestamp"]).tzinfo == UTC


def test_one_failed_test_post_does_not_stop_the_others():
    discord = FakeDiscord(httpx.Response(404), httpx.Response(200))
    env = {"WEBHOOK_NEWS": SECRET + "/a", "WEBHOOK_VULNS": SECRET + "/b"}
    results = dict(send_test_posts(discord.client(), env))
    assert results["WEBHOOK_NEWS"].startswith("failed: WEBHOOK_NEWS: Discord rejected")
    assert results["WEBHOOK_VULNS"] == "posted"


def test_test_posts_use_a_category_sample_when_given():
    discord = FakeDiscord()
    env = {"WEBHOOK_NEWS": "https://webhook.invalid/news", "WEBHOOK_RANSOM": "https://webhook.invalid/ransom"}
    sample = {"title": "sample victim", "color": 1}
    results = send_test_posts(discord.client(), env, samples={"ransomware": sample})
    assert ("WEBHOOK_RANSOM", "posted") in results
    posted = {r.url.path: json.loads(r.content)["embeds"][0] for r in discord.requests}
    assert posted["/ransom"] == sample
    assert posted["/news"]["title"] == "intel-feeds test post: news"
