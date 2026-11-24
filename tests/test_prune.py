"""Pruning old items from state."""

import logging
import os
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest
from conftest import fetch_client

from intel_feeds import dedup, fetch
from intel_feeds import state as state_mod
from intel_feeds.__main__ import main
from intel_feeds.config import DEFAULTS, KEEP_TO_MAX_AGE, Source
from intel_feeds.items import Item
from intel_feeds.state import State, format_time, load_state, save_state

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
OLD = NOW - timedelta(days=100)


def seen(state, item_id, source="News", *, first_seen=OLD, url=None):
    state.mark_seen(item_id, source, first_seen, first_seen, url=url)


def prune(state, *, listed=(), parsed=("News",), active=("News",), **kw):
    return state.prune(NOW, listed=set(listed), parsed=set(parsed), active=set(active), **kw)


# --- State.prune -----------------------------------------------------------


def test_an_old_item_its_feed_no_longer_lists_is_dropped():
    state = State()
    seen(state, "https://example.com/gone")
    seen(state, "https://example.com/still-listed")
    assert prune(state, listed={"https://example.com/still-listed"}) == 1
    assert list(state.items) == ["https://example.com/still-listed"]


def test_an_item_still_listed_is_kept_at_any_age():
    # CISA KEV and MSRC list every entry they ever published.
    state = State()
    seen(state, "kev:CVE-2021-44228", "CISA KEV", first_seen=NOW - timedelta(days=2000))
    assert prune(state, listed={"kev:CVE-2021-44228"}, parsed={"CISA KEV"}, active={"CISA KEV"}) == 0
    assert "kev:CVE-2021-44228" in state.items


def test_an_item_whose_url_another_feed_still_lists_is_kept():
    state = State()
    seen(state, "News:guid-1", url="https://example.com/story")
    assert prune(state, listed={"https://example.com/story"}) == 0


def test_items_first_seen_within_keep_for_are_kept_even_if_unlisted():
    state = State()
    seen(state, "young", first_seen=NOW - timedelta(days=89))
    seen(state, "edge", first_seen=NOW - state_mod.KEEP_FOR)
    seen(state, "old", first_seen=NOW - state_mod.KEEP_FOR - timedelta(seconds=1))
    assert prune(state) == 1
    assert sorted(state.items) == ["edge", "young"]


def test_a_source_not_parsed_this_run_keeps_its_items():
    # A 304, a failed fetch or a failed parse says nothing about what it lists.
    state = State()
    seen(state, "quiet-old", "Quiet")
    assert prune(state, parsed={"News"}, active={"News", "Quiet"}) == 0


def test_items_of_a_disabled_or_removed_source_are_dropped_when_old():
    state = State()
    seen(state, "removed-old", "Removed")
    seen(state, "removed-young", "Removed", first_seen=NOW - timedelta(days=5))
    assert prune(state, parsed=(), active={"News"}) == 1
    assert list(state.items) == ["removed-young"]


def test_keep_for_can_be_passed():
    state = State()
    seen(state, "a", first_seen=NOW - timedelta(days=10))
    assert prune(state, keep_for=timedelta(days=30)) == 0
    assert prune(state, keep_for=timedelta(days=7)) == 1


def test_sources_are_never_pruned():
    state = State()
    state.add_sources(["Gone"], OLD)
    prune(state, active=())
    assert "Gone" in state.sources


def test_keep_for_is_well_above_the_flood_guards_max_age():
    # A pruned item that a feed lists again must be held back as stale;
    # config validation enforces the same for the settings (test_settings.py).
    assert DEFAULTS.keep_for >= KEEP_TO_MAX_AGE * DEFAULTS.max_age
    assert state_mod.KEEP_FOR == DEFAULTS.keep_for


# --- dedup.listed ----------------------------------------------------------


def source(**kw):
    fields = dict(name="News", url="https://feeds.example.com/news.xml", type="rss", category="news")
    return Source(**{**fields, **kw})


def item(guid, url, published=None):
    return Item(
        title=guid or url, url=url, source="News", category="news",
        published=published, guid=guid,
    )


def test_listed_has_every_id_and_url_key():
    keys = dedup.listed(
        source(),
        [
            item("tag:1", "https://example.com/one?utm_source=x"),
            item(None, "https://example.com/two/"),
            item(None, ""),  # no ID: skipped
        ],
    )
    assert keys == {"News:tag:1", "https://example.com/one", "https://example.com/two"}


def test_listed_uses_revision_ids():
    keys = dedup.listed(source(revisions=True), [item("CVE-2026-1", "https://example.com/a", OLD)])
    assert keys == {f"News:CVE-2026-1@{format_time(OLD)}"}


# --- the run ---------------------------------------------------------------

CONFIG = (
    "sources:\n"
    "  - name: News\n    url: https://feeds.example.com/news.xml\n    type: rss\n    category: news\n"
    "  - name: Quiet\n    url: https://feeds.example.com/quiet.xml\n    type: rss\n    category: news\n"
)
HOOKS = {"WEBHOOK_NEWS": "https://discord.invalid/api/webhooks/1/news-secret-token"}


def rss(*entries):
    """An RSS body listing ``(url, published)`` entries."""
    items = "".join(
        f"<item><title>{url}</title><link>{url}</link><guid>{url}</guid>"
        f"<pubDate>{format_datetime(published, usegmt=True)}</pubDate></item>"
        for url, published in entries
    )
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>{items}</channel></rss>'


@pytest.fixture
def feeds(tmp_path, monkeypatch):
    """News serves ``feeds.news``; Quiet always answers 304."""
    feeds.news = rss()

    def handler(request):
        if request.url.path == "/quiet.xml":
            return httpx.Response(304)
        return httpx.Response(200, text=feeds.news)

    monkeypatch.setattr(fetch, "make_client", lambda transport=None: fetch_client(handler))
    config = tmp_path / "sources.yaml"
    config.write_text(CONFIG)
    os.environ.update(HOOKS)  # a post would hit conftest's no-network webhook client and fail
    return feeds


def run(tmp_path, state_path):
    return main(["--config", str(tmp_path / "sources.yaml"), "--state", str(state_path)])


def taken_in(now):
    state = State()
    state.add_sources(["News", "Quiet"], now - timedelta(days=200))
    for entry in state.sources.values():
        entry.backlog_at = format_time(now - timedelta(days=200))
        entry.etag = '"v1"'
    return state


def test_a_run_prunes_what_no_feed_lists_and_keeps_the_rest(feeds, tmp_path, caplog):
    now = datetime.now(UTC)
    old = now - timedelta(days=100)
    feeds.news = rss(("https://example.com/listed", old))
    state = taken_in(now)
    seen(state, "https://example.com/listed", first_seen=old)
    seen(state, "https://example.com/gone", first_seen=old)
    seen(state, "https://example.com/gone-young", first_seen=now - timedelta(days=10))
    seen(state, "Quiet:old", "Quiet", first_seen=old)
    seen(state, "Removed:old", "Removed", first_seen=old)
    path = tmp_path / "state.json"
    save_state(path, state)

    caplog.set_level(logging.INFO)
    assert run(tmp_path, path) == 0
    assert sorted(load_state(path).items) == [
        "Quiet:old",
        "https://example.com/gone-young",
        "https://example.com/listed",
    ]
    assert "state: pruned 2 items first seen more than 90 days ago that no feed lists" in caplog.text
    assert "state: saved" in caplog.text

    caplog.clear()
    assert run(tmp_path, path) == 0
    assert "state: pruned 0 items" in caplog.text
    assert "state: unchanged, not written" in caplog.text


def test_a_pruned_item_listed_again_is_held_back_not_reposted(feeds, tmp_path, caplog):
    now = datetime.now(UTC)
    old = now - timedelta(days=100)
    state = taken_in(now)
    seen(state, "https://example.com/back", first_seen=old)
    path = tmp_path / "state.json"
    save_state(path, state)

    feeds.news = rss()  # the feed stops listing it: pruned
    assert run(tmp_path, path) == 0
    assert "https://example.com/back" not in load_state(path).items

    feeds.news = rss(("https://example.com/back", old))  # and lists it again
    caplog.set_level(logging.INFO)
    assert run(tmp_path, path) == 0
    back = load_state(path).items["https://example.com/back"]
    assert back.posted_at is None
    assert 'guard "News": held back 1 published more than 7 days ago' in caplog.text
