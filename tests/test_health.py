import json
import logging
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import fetch_client

from intel_feeds import __main__ as cli
from intel_feeds import fetch, health, webhook
from intel_feeds.__main__ import main
from intel_feeds.state import State, load_state, save_state

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
OPS = "https://discord.invalid/api/webhooks/9/ops-secret-token"
NEWS = "https://discord.invalid/api/webhooks/1/news-secret-token"


def state_with(*names):
    state = State()
    state.add_sources(list(names), NOW - timedelta(days=30))
    return state


class Ops:
    """A fake Discord that records ops posts; ``status`` is its answer."""

    def __init__(self, status=200):
        self.status = status
        self.posts = []

    def __call__(self, request):
        assert request.url.path.endswith("ops-secret-token")
        if self.status == 200:
            self.posts.append(json.loads(request.content)["embeds"][0])
        return httpx.Response(self.status, json={})

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))


# --- check ---------------------------------------------------------------


def test_a_working_source_changes_nothing():
    state = state_with("A")
    before = state.to_dict()
    assert health.check(state, {"A": None}, NOW) == []
    assert state.to_dict() == before


def test_the_first_failure_starts_the_count_and_later_ones_add_to_it(caplog):
    state = state_with("A")
    health.check(state, {"A": "HTTP 503"}, NOW)
    entry = state.sources["A"]
    assert (entry.failing_since, entry.failures, entry.alerted_at) == (
        "2026-11-18T12:00:00Z", 1, None,
    )
    health.check(state, {"A": "HTTP 503"}, NOW + timedelta(minutes=30))
    assert (entry.failing_since, entry.failures) == ("2026-11-18T12:00:00Z", 2)
    assert 'health "A": failing since 2026-11-18T12:00:00Z (2 runs in a row)' in caplog.text


def test_no_alert_before_24_hours_of_failures():
    state = state_with("A")
    health.check(state, {"A": "HTTP 503"}, NOW)
    almost = NOW + timedelta(hours=23, minutes=59)
    assert health.check(state, {"A": "HTTP 503"}, almost) == []


def test_a_down_alert_is_due_after_24_hours_with_the_latest_error():
    state = state_with("A", "B")
    health.check(state, {"A": "HTTP 503", "B": None}, NOW)
    alerts = health.check(state, {"A": "HTTP 404", "B": None}, NOW + timedelta(hours=24))
    assert alerts == [health.Alert("A", health.DOWN, "2026-11-18T12:00:00Z", 2, "HTTP 404")]


def test_once_alerted_a_source_gets_no_second_down_alert():
    state = state_with("A")
    health.check(state, {"A": "x"}, NOW)
    state.sources["A"].alerted_at = "2026-11-19T12:00:00Z"
    assert health.check(state, {"A": "x"}, NOW + timedelta(days=3)) == []
    assert state.sources["A"].failures == 2


def test_recovering_before_the_alert_clears_quietly(caplog):
    caplog.set_level(logging.INFO)
    state = state_with("A")
    health.check(state, {"A": "x"}, NOW)
    health.check(state, {"A": "x"}, NOW + timedelta(hours=1))
    assert health.check(state, {"A": None}, NOW + timedelta(hours=2)) == []
    entry = state.sources["A"]
    assert (entry.failing_since, entry.failures, entry.alerted_at) == (None, None, None)
    assert 'health "A": working again after 2 failed runs; no alert was sent' in caplog.text


def test_recovering_after_the_alert_makes_an_up_alert_and_keeps_state_until_sent():
    state = state_with("A")
    health.check(state, {"A": "x"}, NOW)
    state.sources["A"].alerted_at = "2026-11-19T12:00:00Z"
    alerts = health.check(state, {"A": None}, NOW + timedelta(days=2))
    assert alerts == [health.Alert("A", health.UP, "2026-11-18T12:00:00Z", 1)]
    assert state.sources["A"].alerted_at == "2026-11-19T12:00:00Z"


# --- send ----------------------------------------------------------------


def test_send_posts_a_down_alert_and_records_it():
    state = state_with("A")
    health.check(state, {"A": "HTTP 503 Service Unavailable"}, NOW)
    later = NOW + timedelta(hours=25)
    alerts = health.check(state, {"A": "HTTP 503 Service Unavailable"}, later)
    ops = Ops()
    report = health.send(ops.client(), alerts, state, later, {webhook.OPS_ENV: OPS})
    assert (report.posted, report.failed, report.unsent) == (1, 0, 0)
    assert state.sources["A"].alerted_at == "2026-11-19T13:00:00Z"
    [embed] = ops.posts
    assert embed["title"] == "Source down: A"
    assert embed["description"] == (
        "Failing since 2026-11-18 12:00 UTC (2 failed runs in a row). "
        "Last error: HTTP 503 Service Unavailable"
    )
    assert embed["color"] == webhook.COLORS["ops"]


def test_send_posts_a_recovery_and_clears_the_source():
    state = state_with("A")
    entry = state.sources["A"]
    entry.failing_since, entry.failures, entry.alerted_at = (
        "2026-11-17T12:00:00Z", 1, "2026-11-18T12:00:00Z",
    )
    alerts = health.check(state, {"A": None}, NOW)
    ops = Ops()
    health.send(ops.client(), alerts, state, NOW, {webhook.OPS_ENV: OPS})
    assert (entry.failing_since, entry.failures, entry.alerted_at) == (None, None, None)
    [embed] = ops.posts
    assert embed["title"] == "Source back: A"
    assert embed["description"] == (
        "Working again. It had been failing since 2026-11-17 12:00 UTC (1 failed run)."
    )


def test_without_an_ops_webhook_alerts_wait_and_are_named(caplog):
    state = state_with("A")
    alerts = [health.Alert("A", health.DOWN, "2026-11-17T12:00:00Z", 48, "x")]
    report = health.send(Ops().client(), alerts, state, NOW, {})
    assert report.unsent == 1
    assert state.sources["A"].alerted_at is None
    assert 'health: 1 alert not sent: WEBHOOK_OPS is not set ("A" down)' in caplog.text


def test_a_failed_alert_is_kept_for_the_next_run_and_never_logs_the_url(caplog):
    state = state_with("A")
    alerts = [health.Alert("A", health.DOWN, "2026-11-17T12:00:00Z", 48, "x")]
    report = health.send(Ops(status=404).client(), alerts, state, NOW, {webhook.OPS_ENV: OPS})
    assert (report.posted, report.failed) == (0, 1)
    assert state.sources["A"].alerted_at is None
    assert 'health "A": down alert not sent: WEBHOOK_OPS' in caplog.text
    assert "secret-token" not in caplog.text


def test_a_long_error_is_clipped_to_the_excerpt_limit():
    alert = health.Alert("A", health.DOWN, "2026-11-17T12:00:00Z", 48, "e" * 1000)
    assert len(health.embed(alert, NOW)["description"]) <= webhook.EXCERPT_LIMIT


# --- the run -------------------------------------------------------------

CONFIG = (
    "sources:\n"
    "  - name: Good\n    url: https://feeds.example.com/good.xml\n    type: rss\n    category: news\n"
    "  - name: Broken\n    url: https://feeds.example.com/broken.xml\n    type: rss\n"
    "    category: news\n"
)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    """Good answers 304; Broken answers ``answers['broken']`` (a status or bytes)."""
    answers = {"broken": 503}

    def handler(request):
        if request.url.path == "/good.xml":
            return httpx.Response(304)
        answer = answers["broken"]
        if isinstance(answer, bytes):
            return httpx.Response(200, content=answer)
        return httpx.Response(answer)

    monkeypatch.setattr(fetch, "make_client", lambda transport=None: fetch_client(handler))
    ops = Ops()
    monkeypatch.setattr(webhook, "make_client", lambda transport=None: ops.client())
    config = tmp_path / "sources.yaml"
    config.write_text(CONFIG)
    path = tmp_path / "state.json"
    state = State()
    state.add_sources(["Good", "Broken"], NOW - timedelta(days=30))
    for entry in state.sources.values():
        entry.backlog_at = "2026-10-01T00:00:00Z"
    save_state(path, state)
    os.environ[webhook.OPS_ENV] = OPS
    return config, path, answers, ops


def run(config, path):
    return main(["--config", str(config), "--state", str(path)])


def age(path, name, hours):
    """Move ``name``'s failing_since back by ``hours``."""
    state = load_state(path)
    since = health.parse_time(state.sources[name].failing_since)
    state.sources[name].failing_since = (since - timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    save_state(path, state)


def test_a_run_counts_a_failing_fetch_and_alerts_after_24_hours(setup):
    config, path, answers, ops = setup
    assert run(config, path) == 0
    broken = load_state(path).sources["Broken"]
    assert broken.failures == 1 and broken.alerted_at is None
    assert load_state(path).sources["Good"].failing_since is None
    assert ops.posts == []

    age(path, "Broken", 24)
    assert run(config, path) == 0
    [embed] = ops.posts
    assert embed["title"] == "Source down: Broken"
    assert "(2 failed runs in a row). Last error: HTTP 503" in embed["description"]
    assert "feeds.example.com" not in embed["description"]
    assert load_state(path).sources["Broken"].alerted_at is not None

    assert run(config, path) == 0  # still failing: no second alert
    assert len(ops.posts) == 1
    assert load_state(path).sources["Broken"].failures == 3

    answers["broken"] = 304
    assert run(config, path) == 0
    assert ops.posts[-1]["title"] == "Source back: Broken"
    broken = load_state(path).sources["Broken"]
    assert (broken.failing_since, broken.failures, broken.alerted_at) == (None, None, None)


def test_a_parse_failure_counts_as_a_failure(setup):
    config, path, answers, ops = setup
    answers["broken"] = b"<not a feed"
    assert run(config, path) == 0
    age(path, "Broken", 24)
    assert run(config, path) == 0
    [embed] = ops.posts
    assert "Last error: parse failed:" in embed["description"]


def test_a_failed_alert_post_fails_the_run_and_is_retried(setup):
    config, path, answers, ops = setup
    assert run(config, path) == 0
    age(path, "Broken", 24)
    ops.status = 500
    assert run(config, path) == cli.EXIT_POST_FAILED
    assert load_state(path).sources["Broken"].alerted_at is None
    ops.status = 200
    assert run(config, path) == 0
    assert [e["title"] for e in ops.posts] == ["Source down: Broken"]


def test_with_posting_off_alerts_are_only_logged(setup, monkeypatch, caplog):
    config, path, answers, ops = setup
    monkeypatch.setattr(cli, "POSTING_ENABLED", False)
    caplog.set_level(logging.INFO)
    assert run(config, path) == 0
    age(path, "Broken", 24)
    assert run(config, path) == 0
    assert ops.posts == []
    assert 'health "Broken": would post a down alert (posting is off)' in caplog.text
    assert load_state(path).sources["Broken"].alerted_at is None
