import logging
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import fetch_client
from test_route import BODIES, CONFIG, HOOKS, NO_AGE_LIMIT, FakeDiscord, run

from intel_feeds import __main__ as cli
from intel_feeds import fetch, guard, webhook
from intel_feeds.config import Source
from intel_feeds.dedup import Dedup, NewItem, Split
from intel_feeds.items import Item
from intel_feeds.state import State, load_state, save_state

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
TAKEN_IN = "2026-11-01T00:00:00Z"


def new(title, *, days_ago=None, source="Src"):
    """A new item published ``days_ago`` days before NOW (None: undated)."""
    published = None if days_ago is None else NOW - timedelta(days=days_ago)
    item = Item(
        title=title,
        url=f"https://example.com/{title}",
        source=source,
        category="news",
        published=published,
    )
    return NewItem(item, f"https://example.com/{title}", f"https://example.com/{title}")


def state_with(*names, taken_in=None):
    state = State()
    state.add_sources(list(names), NOW - timedelta(days=30))
    for name in names:
        state.sources[name].backlog_at = taken_in
    return state


def titles(split):
    return [n.item.title for n in split.new]


# --- new source ------------------------------------------------------------


def test_a_new_source_keeps_its_three_newest_and_records_the_rest_unposted():
    state = state_with("Src")
    # Feeds list newest first.
    news = [new(f"d{d}", days_ago=d) for d in (0.1, 0.5, 1, 2, 3, 4)]
    kept, report = guard.apply(state, {"Src": Split(new=news)}, NOW)

    assert titles(kept["Src"]) == ["d0.1", "d0.5", "d1"]
    assert report.held["Src"].backlog == 3
    assert report.new_sources == ["Src"]
    assert state.sources["Src"].backlog_at == "2026-11-18T12:00:00Z"
    held = {state.items[n.id].source for n in news[3:]}
    assert held == {"Src"}
    assert not any(state.items[n.id].posted_at for n in news[3:])
    for n in news[:3]:
        assert n.id not in state.items  # recorded only once posted


def test_the_newest_are_picked_by_date_not_feed_order():
    state = state_with("Src")
    news = [new("old", days_ago=5), new("newest", days_ago=0), new("mid", days_ago=2)]
    kept, _ = guard.apply(state, {"Src": Split(new=news)}, NOW, new_source_posts=2)
    assert titles(kept["Src"]) == ["newest", "mid"]


def test_ties_keep_the_feed_order():
    state = state_with("Src")
    news = [new(name, days_ago=1) for name in ("a", "b", "c", "d")]
    kept, _ = guard.apply(state, {"Src": Split(new=news)}, NOW)
    assert titles(kept["Src"]) == ["a", "b", "c"]


def test_with_posting_off_a_new_source_holds_its_whole_backlog():
    state = state_with("Src")
    news = [new(f"d{d}", days_ago=d) for d in (0, 1, 2)]
    kept, report = guard.apply(state, {"Src": Split(new=news)}, NOW, new_source_posts=0)
    assert kept["Src"].new == []
    assert report.backlog == 3
    assert all(n.id in state.items for n in news)
    assert state.sources["Src"].backlog_at  # taken in: a later run is not "new"


def test_a_new_source_posts_nothing_older_than_the_age_limit():
    state = state_with("Src")
    news = [new("week-old", days_ago=8), new("month-old", days_ago=30)]
    kept, report = guard.apply(state, {"Src": Split(new=news)}, NOW)
    assert kept["Src"].new == []
    assert report.held["Src"].backlog == 2


def test_a_new_source_holds_its_undated_items():
    state = state_with("Src")
    news = [new("undated"), new("dated", days_ago=1)]
    kept, _ = guard.apply(state, {"Src": Split(new=news)}, NOW)
    assert titles(kept["Src"]) == ["dated"]
    assert news[0].id in state.items


def test_a_new_source_with_nothing_new_is_still_taken_in():
    state = state_with("Src")
    kept, report = guard.apply(state, {"Src": Split(seen=4)}, NOW)
    assert kept["Src"].new == [] and kept["Src"].seen == 4
    assert report.new_sources == ["Src"]
    assert state.sources["Src"].backlog_at


def test_a_source_that_was_not_parsed_stays_new():
    state = state_with("Up", "Down")
    guard.apply(state, {"Up": Split(new=[new("a", days_ago=1)])}, NOW)
    assert state.sources["Up"].backlog_at
    assert state.sources["Down"].backlog_at is None


# --- known source ----------------------------------------------------------


def test_a_known_source_holds_items_older_than_seven_days():
    state = state_with("Src", taken_in=TAKEN_IN)
    news = [
        new("today", days_ago=0),
        new("six-days", days_ago=6),
        new("eight-days", days_ago=8),
        new("month-old", days_ago=35),  # Palo Alto's resurfaced advisory
    ]
    kept, report = guard.apply(state, {"Src": Split(new=news)}, NOW)
    assert titles(kept["Src"]) == ["today", "six-days"]
    assert report.held["Src"].stale == 2
    assert report.new_sources == []
    assert state.sources["Src"].backlog_at == TAKEN_IN  # unchanged
    for n in news[2:]:
        assert state.items[n.id].posted_at is None


def test_an_item_exactly_at_the_limit_is_kept():
    state = state_with("Src", taken_in=TAKEN_IN)
    news = [new("edge", days_ago=7), new("past", days_ago=7.001)]
    kept, _ = guard.apply(state, {"Src": Split(new=news)}, NOW)
    assert titles(kept["Src"]) == ["edge"]


def test_a_known_source_keeps_undated_items():
    state = state_with("Src", taken_in=TAKEN_IN)
    kept, report = guard.apply(state, {"Src": Split(new=[new("undated")])}, NOW)
    assert titles(kept["Src"]) == ["undated"]
    assert report.stale == 0


def test_a_known_source_posts_everything_recent_however_many():
    state = state_with("Src", taken_in=TAKEN_IN)
    news = [new(f"n{i}", days_ago=i / 10) for i in range(10)]
    kept, _ = guard.apply(state, {"Src": Split(new=news)}, NOW)
    assert len(kept["Src"].new) == 10


def test_the_seen_and_no_id_counts_are_kept():
    state = state_with("Src", taken_in=TAKEN_IN)
    kept, _ = guard.apply(
        state, {"Src": Split(new=[new("old", days_ago=9)], seen=3, no_id=1)}, NOW
    )
    assert (kept["Src"].seen, kept["Src"].no_id) == (3, 1)


def test_a_held_item_is_already_seen_on_the_next_run():
    source = Source(name="Src", url="https://example.com/feed", type="rss", category="news")
    state = state_with("Src", taken_in=TAKEN_IN)
    old = new("old", days_ago=20)
    guard.apply(state, {"Src": Split(new=[old])}, NOW)
    split = Dedup(state).split(source, [old.item])
    assert split.new == [] and split.seen == 1


# --- logging and state ------------------------------------------------------


def test_log_report_names_each_source_and_totals(caplog):
    caplog.set_level(logging.INFO)
    state = state_with("Fresh")
    state.add_sources(["Known", "Quiet"], NOW)
    state.sources["Known"].backlog_at = TAKEN_IN
    state.sources["Quiet"].backlog_at = TAKEN_IN
    _, report = guard.apply(
        state,
        {
            "Fresh": Split(new=[new(f"f{d}", days_ago=d) for d in range(5)]),
            "Known": Split(new=[new("k-old", days_ago=9), new("k-new", days_ago=1)]),
            "Quiet": Split(new=[new("q-new", days_ago=1)]),
        },
        NOW,
    )
    guard.log_report(report)
    assert 'guard "Fresh": new source, held back 2' in caplog.text
    assert 'guard "Known": held back 1 published more than 7 days ago' in caplog.text
    assert '"Quiet"' not in caplog.text
    assert "flood guard: held back 2 (new source), 1 (older than 7 days)" in caplog.text


def test_backlog_at_is_saved_and_loaded(tmp_path):
    state = state_with("Src", taken_in=TAKEN_IN)
    path = tmp_path / "state.json"
    save_state(path, state)
    assert load_state(path).sources["Src"].backlog_at == TAKEN_IN


def test_a_state_file_without_backlog_at_loads_as_new(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(
        '{"version": 1, "sources": {"Src": {"first_seen": "2026-11-18T07:50:40Z",'
        ' "etag": null, "last_modified": null, "cursor": null}}, "items": {}}'
    )
    assert load_state(path).sources["Src"].backlog_at is None


# --- a whole run -------------------------------------------------------------


@pytest.fixture
def feeds(tmp_path, monkeypatch):
    """The route tests' two fixture feeds, with ETags, and the default limits."""

    def handler(request):
        etag = f'"{request.url.path}-v1"'
        if request.headers.get("If-None-Match") == etag:
            return httpx.Response(304)
        return httpx.Response(200, content=BODIES[request.url.path], headers={"ETag": etag})

    monkeypatch.setattr(fetch, "make_client", lambda transport=None: fetch_client(handler))
    config = tmp_path / "sources.yaml"
    config.write_text(CONFIG.removeprefix(NO_AGE_LIMIT))
    return config


def test_with_posting_on_a_first_run_posts_at_most_three_per_source(
    feeds, tmp_path, monkeypatch, caplog
):
    monkeypatch.setattr(cli, "POSTING_ENABLED", True)
    feeds.write_text(CONFIG)  # no age limit: the fixture dates age as time goes on
    discord = FakeDiscord()
    monkeypatch.setattr(webhook, "make_client", lambda transport=None: discord.client())
    os.environ.update(HOOKS)
    caplog.set_level(logging.INFO)
    state_path = tmp_path / "state.json"
    assert run(feeds, state_path) == 0

    # The Record lists 5 items, so 2 are held; Cisco lists only 2.
    assert len(discord.titles("WEBHOOK_NEWS")) == 3
    assert len(discord.titles("WEBHOOK_ADVISORIES")) == 2
    assert "flood guard: held back 2 (new source)" in caplog.text
    saved = load_state(state_path)
    posted = [i for i in saved.items.values() if i.posted_at]
    assert len(posted) == 5
    assert len(saved.items) == 7  # the 2 held are recorded, not posted
    assert saved.sources["Record"].etag and saved.sources["Cisco"].etag

    # The next run gets 304s and posts nothing more.
    discord.posts.clear()
    assert run(feeds, state_path) == 0
    assert discord.posts == []
