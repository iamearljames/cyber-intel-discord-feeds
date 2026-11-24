import json
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from conftest import fetch_client

from intel_feeds import __main__ as cli
from intel_feeds import fetch, route, webhook
from intel_feeds.__main__ import main
from intel_feeds.config import DEFAULTS
from intel_feeds.dedup import NewItem, Split
from intel_feeds.embeds import item_embed
from intel_feeds.items import Item
from intel_feeds.state import State, load_state, save_state

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
T0 = datetime(2026, 11, 18, 0, 0, tzinfo=UTC)

# Fake webhook URLs; the token part must never show up in logs.
HOOKS = {
    "WEBHOOK_NEWS": "https://discord.invalid/api/webhooks/1/news-secret-token",
    "WEBHOOK_VULNS": "https://discord.invalid/api/webhooks/2/vulns-secret-token",
    "WEBHOOK_ADVISORIES": "https://discord.invalid/api/webhooks/3/advisories-secret-token",
    "WEBHOOK_RESEARCH": "https://discord.invalid/api/webhooks/4/research-secret-token",
}
VARIABLE_BY_PATH = {httpx.URL(url).path: var for var, url in HOOKS.items()}


def new(title, *, source="Src", category="news", hours=None, item_id=None):
    published = None if hours is None else T0 + timedelta(hours=hours)
    item = Item(
        title=title,
        url=f"https://example.com/{title}",
        source=source,
        category=category,
        published=published,
    )
    return NewItem(item, item_id or f"{source}:{title}", f"https://example.com/{title}")


def split(*items):
    return Split(new=list(items))


class FakeDiscord:
    """Answers webhook posts; ``fail`` maps a variable to a status code."""

    def __init__(self, fail=None):
        self.fail = fail or {}
        self.posts: list[tuple[str, dict]] = []

    def __call__(self, request):
        variable = VARIABLE_BY_PATH[request.url.path]
        status = self.fail.get(variable, 200)
        if status == 200:
            self.posts.append((variable, json.loads(request.content)))
        return httpx.Response(status, json={})

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))

    def titles(self, variable=None):
        return [p["embeds"][0]["title"] for v, p in self.posts if variable in (None, v)]


# --- plan ----------------------------------------------------------------


def test_plan_groups_by_category_oldest_first_across_sources():
    splits = {
        # Feeds list newest first.
        "A": split(new("a3", source="A", hours=3), new("a1", source="A", hours=1)),
        "B": split(new("b2", source="B", hours=2), new("v", source="B", category="vulns", hours=0)),
    }
    plan = route.plan(splits, HOOKS)
    assert [(r.category, r.variable) for r in plan.routes] == [
        ("news", "WEBHOOK_NEWS"),
        ("vulns", "WEBHOOK_VULNS"),
    ]
    assert [n.item.title for n in plan.routes[0].items] == ["a1", "b2", "a3"]
    assert plan.count() == 4 and plan.unrouted == []


def test_plan_keeps_feed_order_oldest_first_for_equal_times_and_puts_undated_last():
    splits = {
        "A": split(
            new("undated-newer", source="A"),
            new("same-newer", source="A", hours=1),
            new("same-older", source="A", hours=1),
            new("undated-older", source="A"),
        )
    }
    titles = [n.item.title for n in route.plan(splits, HOOKS).routes[0].items]
    assert titles == ["same-older", "same-newer", "undated-older", "undated-newer"]


@pytest.mark.parametrize("value", [None, "", "   "])
def test_a_category_without_a_webhook_is_unrouted(value):
    env = {k: v for k, v in HOOKS.items() if k != "WEBHOOK_NEWS"}
    if value is not None:
        env["WEBHOOK_NEWS"] = value
    plan = route.plan({"A": split(new("a", hours=1), new("v", category="vulns", hours=1))}, env)
    assert [r.variable for r in plan.routes] == ["WEBHOOK_VULNS"]
    assert [(r.variable, len(r.items)) for r in plan.unrouted] == [("WEBHOOK_NEWS", 1)]


def test_plan_with_nothing_new_is_empty():
    plan = route.plan({"A": split()}, HOOKS)
    assert plan.routes == [] and plan.unrouted == [] and plan.count() == 0


# --- post ----------------------------------------------------------------


def test_post_sends_each_item_as_its_embed_and_records_it_as_posted():
    a, b = new("a", hours=1), new("v", category="vulns", hours=2)
    discord, state = FakeDiscord(), State()
    report = route.post(discord.client(), route.plan({"S": split(b, a)}, HOOKS), state, NOW, HOOKS)
    assert discord.posts == [
        ("WEBHOOK_NEWS", {"embeds": [item_embed(a.item)], "allowed_mentions": {"parse": []}}),
        ("WEBHOOK_VULNS", {"embeds": [item_embed(b.item)], "allowed_mentions": {"parse": []}}),
    ]
    assert report.posted == 2 and report.failed == 0 and report.incomplete == set()
    for n in (a, b):
        assert state.items[n.id].posted_at == "2026-11-18T12:00:00Z"
        assert state.items[n.id].source == "Src"


def test_a_failed_post_stops_that_channel_and_leaves_the_rest_unrecorded(caplog):
    news = [new(f"n{i}", source=f"N{i}", hours=i) for i in range(3)]
    vulns = new("v", source="V", category="vulns", hours=0)
    discord = FakeDiscord()
    state = State()
    plan = route.plan({"N": split(*reversed(news)), "V": split(vulns)}, HOOKS)

    calls = {"n": 0}
    real = discord.__call__

    def handler(request):
        if VARIABLE_BY_PATH[request.url.path] == "WEBHOOK_NEWS":
            calls["n"] += 1
            if calls["n"] == 2:  # the second news post fails for good
                return httpx.Response(404, json={})
        return real(request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    caplog.set_level(logging.INFO)
    report = route.post(client, plan, state, NOW, HOOKS)

    assert discord.titles("WEBHOOK_NEWS") == ["n0"]
    assert discord.titles("WEBHOOK_VULNS") == ["v"]  # other channels carry on
    assert calls["n"] == 2  # no post after the failure
    assert set(state.items) == {news[0].id, vulns.id}
    assert report.posted == 2 and report.failed == 2
    assert report.incomplete == {"N1", "N2"}
    assert "post WEBHOOK_NEWS: 1 posted, then failed" in caplog.text
    assert "2 items left for the next run" in caplog.text
    assert "secret-token" not in caplog.text


def test_unrouted_items_are_kept_unrecorded_and_named_in_a_warning(caplog):
    env = {k: v for k, v in HOOKS.items() if k != "WEBHOOK_RESEARCH"}
    r = new("r", source="R", category="research", hours=1)
    n = new("n", source="N", hours=1)
    discord, state = FakeDiscord(), State()
    report = route.post(discord.client(), route.plan({"R": split(r), "N": split(n)}, env), state, NOW, env)
    assert discord.titles() == ["n"]
    assert set(state.items) == {n.id}
    assert report.unrouted == 1 and report.incomplete == {"R"}
    assert 'WEBHOOK_RESEARCH is not set; 1 "research" items kept for a later run' in caplog.text


def test_log_plan_says_what_would_post_without_posting(caplog):
    caplog.set_level(logging.INFO)
    env = {k: v for k, v in HOOKS.items() if k != "WEBHOOK_VULNS"}
    plan = route.plan({"S": split(new("a", hours=1), new("b", hours=2), new("v", category="vulns"))}, env)
    route.log_plan(plan)
    assert "route: would post 2 items to WEBHOOK_NEWS" in caplog.text
    assert "WEBHOOK_VULNS is not set; 1" in caplog.text


# --- per-channel cap ----------------------------------------------


def test_the_cap_is_ten_posts_per_channel():
    assert DEFAULTS.posts_per_channel == 10
    news = [new(f"n{i}", hours=i) for i in range(12)]
    [channel] = route.plan({"A": split(*news)}, HOOKS).routes
    assert (len(channel.items), len(channel.overflow)) == (10, 2)


def test_plan_keeps_the_oldest_up_to_the_cap_and_overflows_the_rest(monkeypatch):
    cap = 2
    news = [new(f"n{i}", source="A", hours=i) for i in range(5)]
    vulns = new("v", source="B", category="vulns", hours=0)
    plan = route.plan({"A": split(*reversed(news)), "B": split(vulns)}, HOOKS, cap=cap)
    by_var = {r.variable: r for r in plan.routes}
    assert [n.item.title for n in by_var["WEBHOOK_NEWS"].items] == ["n0", "n1"]
    assert [n.item.title for n in by_var["WEBHOOK_NEWS"].overflow] == ["n2", "n3", "n4"]
    assert [n.item.title for n in by_var["WEBHOOK_VULNS"].items] == ["v"]
    assert by_var["WEBHOOK_VULNS"].overflow == []
    assert plan.count() == 3 and plan.overflow() == 3


def test_the_cap_counts_a_channel_across_all_its_sources(monkeypatch):
    cap = 2
    splits = {
        "A": split(new("a3", source="A", hours=3), new("a1", source="A", hours=1)),
        "B": split(new("b2", source="B", hours=2)),
    }
    [news] = route.plan(splits, HOOKS, cap=cap).routes
    assert [n.item.title for n in news.items] == ["a1", "b2"]
    assert [n.item.title for n in news.overflow] == ["a3"]


def test_an_unrouted_channel_is_not_capped(monkeypatch):
    cap = 1
    env = {k: v for k, v in HOOKS.items() if k != "WEBHOOK_NEWS"}
    plan = route.plan({"A": split(new("a", hours=1), new("b", hours=2))}, env, cap=cap)
    assert [len(r.items) for r in plan.unrouted] == [2]
    assert plan.overflow() == 0


def test_post_leaves_the_overflow_unrecorded_and_its_sources_incomplete(monkeypatch, caplog):
    cap = 2
    caplog.set_level(logging.INFO)
    news = [new(f"n{i}", source=f"N{i}", hours=i) for i in range(4)]
    discord, state = FakeDiscord(), State()
    plan = route.plan({"N": split(*reversed(news))}, HOOKS, cap=cap)
    report = route.post(discord.client(), plan, state, NOW, HOOKS)
    assert discord.titles() == ["n0", "n1"]
    assert set(state.items) == {news[0].id, news[1].id}
    assert report.posted == 2 and report.failed == 0 and report.overflow == 2
    assert report.incomplete == {"N2", "N3"}
    assert "post WEBHOOK_NEWS: 2 posted, 2 over the cap of 2 left for the next run" in caplog.text


def test_a_failed_post_counts_the_overflow_apart_from_the_failed(monkeypatch):
    cap = 2
    news = [new(f"n{i}", source=f"N{i}", hours=i) for i in range(3)]
    discord, state = FakeDiscord(fail={"WEBHOOK_NEWS": 404}), State()
    report = route.post(discord.client(), route.plan({"N": split(*news)}, HOOKS, cap=cap), state, NOW, HOOKS)
    assert state.items == {}
    assert report.posted == 0 and report.failed == 2 and report.overflow == 1
    assert report.incomplete == {"N0", "N1", "N2"}


def test_log_plan_names_the_overflow(monkeypatch, caplog):
    cap = 1
    caplog.set_level(logging.INFO)
    route.log_plan(route.plan({"S": split(new("a", hours=1), new("b", hours=2))}, HOOKS, cap=cap))
    assert (
        "route: would post 1 items to WEBHOOK_NEWS, 1 over the cap of 1 left for the next run"
        in caplog.text
    )


# --- the run -------------------------------------------------------------

# No age limit: the fixture items' dates pass the default 7 days as time goes
# on, and the flood guard has its own tests (test_guard.py).
NO_AGE_LIMIT = "settings:\n  max_age_days: 36500\n  keep_days: 146000\n"
CONFIG = NO_AGE_LIMIT + (
    "sources:\n"
    "  - name: Record\n    url: https://feeds.example.com/record.xml\n    type: rss\n    category: news\n"
    "  - name: Cisco\n    url: https://feeds.example.com/cisco.xml\n    type: rss\n    category: advisories\n"
)
BODIES = {
    "/record.xml": (FIXTURES / "rss20_the_record.xml").read_bytes(),
    "/cisco.xml": (FIXTURES / "rss20_cisco_psirt.xml").read_bytes(),
}


@pytest.fixture
def feeds(tmp_path, monkeypatch):
    """Serve the two fixture feeds with ETags, answering 304 to a matching one."""
    seen = []

    def handler(request):
        seen.append(request.url.path)
        etag = f'"{request.url.path}-v1"'
        if request.headers.get("If-None-Match") == etag:
            return httpx.Response(304)
        return httpx.Response(200, content=BODIES[request.url.path], headers={"ETag": etag})

    monkeypatch.setattr(fetch, "make_client", lambda transport=None: fetch_client(handler))
    config = tmp_path / "sources.yaml"
    config.write_text(CONFIG)
    return config


@pytest.fixture
def discord(monkeypatch):
    fake = FakeDiscord()
    monkeypatch.setattr(webhook, "make_client", lambda transport=None: fake.client())
    return fake


def run(config, state_path):
    return main(["--config", str(config), "--state", str(state_path)])


@pytest.fixture
def taken_in(tmp_path, monkeypatch):
    """A state file whose sources' backlogs are taken in.

    With CONFIG's NO_AGE_LIMIT, routing tests then post every fixture item.
    """
    state = State()
    state.add_sources(["Record", "Cisco"], NOW)
    for source in state.sources.values():
        source.backlog_at = "2026-11-18T00:00:00Z"
    path = tmp_path / "state.json"
    save_state(path, state)
    return path


def test_posting_is_on():
    assert cli.POSTING_ENABLED is True


def test_with_posting_off_a_first_run_takes_in_the_backlog_and_posts_nothing(
    feeds, tmp_path, monkeypatch, caplog
):
    # conftest fails any webhook request, so a post here would fail the test.
    monkeypatch.setattr(cli, "POSTING_ENABLED", False)
    os.environ.update(HOOKS)
    caplog.set_level(logging.INFO)
    state_path = tmp_path / "state.json"
    assert run(feeds, state_path) == 0
    assert "posting is switched off" in caplog.text
    assert "would post" not in caplog.text
    saved = load_state(state_path)
    # Every item is recorded as not posted, even the newest few.
    assert len(saved.items) >= 5
    assert not any(i.posted_at for i in saved.items.values())
    assert f"flood guard: held back {len(saved.items)} (new source)" in caplog.text
    assert all(s.backlog_at for s in saved.sources.values())
    # Each source is finished, so its validators are saved.
    assert saved.sources["Record"].etag == '"/record.xml-v1"'
    assert saved.sources["Cisco"].etag == '"/cisco.xml-v1"'


def test_with_posting_off_a_later_run_logs_what_it_would_post_and_records_it_not(
    feeds, taken_in, monkeypatch, caplog
):
    monkeypatch.setattr(cli, "POSTING_ENABLED", False)
    os.environ.update(HOOKS)
    caplog.set_level(logging.INFO)
    assert run(feeds, taken_in) == 0
    assert "route: would post 5 items to WEBHOOK_NEWS" in caplog.text
    assert "items to WEBHOOK_ADVISORIES" in caplog.text
    saved = load_state(taken_in)
    assert saved.items == {}
    assert all(s.etag is None for s in saved.sources.values())


def test_with_posting_on_a_run_posts_records_and_saves_validators(
    feeds, discord, taken_in, monkeypatch, caplog
):
    monkeypatch.setattr(cli, "POSTING_ENABLED", True)
    os.environ.update(HOOKS)
    caplog.set_level(logging.INFO)
    state_path = taken_in
    assert run(feeds, state_path) == 0

    news = discord.titles("WEBHOOK_NEWS")
    advisories = discord.titles("WEBHOOK_ADVISORIES")
    assert len(news) == 5 and advisories
    saved = load_state(state_path)
    assert len(saved.items) == len(news) + len(advisories)
    assert all(i.posted_at for i in saved.items.values())
    assert saved.sources["Record"].etag == '"/record.xml-v1"'
    assert saved.sources["Cisco"].etag == '"/cisco.xml-v1"'
    assert f"post: {len(news) + len(advisories)} posted, 0 failed" in caplog.text
    assert "secret-token" not in caplog.text

    # Oldest first within the channel.
    times = [p["embeds"][0]["timestamp"] for v, p in discord.posts if v == "WEBHOOK_NEWS"]
    assert times == sorted(times)

    # The next run gets 304s and posts nothing more.
    discord.posts.clear()
    assert run(feeds, state_path) == 0
    assert discord.posts == []


def test_a_failed_post_saves_what_posted_keeps_validators_and_exits_one(
    feeds, discord, taken_in, monkeypatch, caplog
):
    monkeypatch.setattr(cli, "POSTING_ENABLED", True)
    os.environ.update(HOOKS)
    discord.fail = {"WEBHOOK_ADVISORIES": 404}
    state_path = taken_in
    assert run(feeds, state_path) == cli.EXIT_POST_FAILED

    saved = load_state(state_path)
    assert {i.source for i in saved.items.values()} == {"Record"}
    assert saved.sources["Record"].etag == '"/record.xml-v1"'
    assert saved.sources["Cisco"].etag is None  # fetched in full next run
    assert "WEBHOOK_ADVISORIES: Discord rejected the webhook" in caplog.text
    assert "secret-token" not in caplog.text

    # Fixed: the next run posts Cisco's items and nothing from The Record again.
    discord.fail = {}
    discord.posts.clear()
    assert run(feeds, state_path) == 0
    assert {v for v, _ in discord.posts} == {"WEBHOOK_ADVISORIES"}
    assert load_state(state_path).sources["Cisco"].etag == '"/cisco.xml-v1"'


def test_a_missing_webhook_keeps_its_items_and_validators_for_later(
    feeds, discord, taken_in, monkeypatch, caplog
):
    monkeypatch.setattr(cli, "POSTING_ENABLED", True)
    os.environ.update({k: v for k, v in HOOKS.items() if k != "WEBHOOK_NEWS"})
    state_path = taken_in
    assert run(feeds, state_path) == 0  # not a failure: nothing was refused

    saved = load_state(state_path)
    assert {i.source for i in saved.items.values()} == {"Cisco"}
    assert saved.sources["Record"].etag is None
    assert 'WEBHOOK_NEWS is not set; 5 "news" items kept for a later run' in caplog.text


def test_overflow_goes_out_on_the_next_runs_oldest_first(
    feeds, discord, taken_in, monkeypatch, caplog
):
    monkeypatch.setattr(cli, "POSTING_ENABLED", True)
    feeds.write_text(CONFIG.replace("settings:\n", "settings:\n  posts_per_channel: 2\n"))
    os.environ.update(HOOKS)
    caplog.set_level(logging.INFO)
    state_path = taken_in

    assert run(feeds, state_path) == 0
    first = discord.titles("WEBHOOK_NEWS")
    assert len(first) == 2
    assert "post WEBHOOK_NEWS: 2 posted, 3 over the cap of 2 left for the next run" in caplog.text
    assert "over the per-channel cap" in caplog.text
    saved = load_state(state_path)
    assert saved.sources["Record"].etag is None  # fetched in full next run

    # The next runs post the overflow, oldest first, with no repeats.
    for _ in range(3):
        assert run(feeds, state_path) == 0
    news = discord.titles("WEBHOOK_NEWS")
    assert len(news) == 5 and len(set(news)) == 5 and news[:2] == first
    times = [p["embeds"][0]["timestamp"] for v, p in discord.posts if v == "WEBHOOK_NEWS"]
    assert times == sorted(times)
    saved = load_state(state_path)
    assert saved.sources["Record"].etag == '"/record.xml-v1"'  # drained, so saved

    # Then nothing more.
    discord.posts.clear()
    assert run(feeds, state_path) == 0
    assert discord.posts == []


# --- the per-run summary -------------------------------------------


def summary_row(caplog, name):
    """A source's summary line, split into cells."""
    [line] = [r.getMessage() for r in caplog.records if r.getMessage().startswith(f"summary: {name} ")]
    return line.split()[1:]


def test_a_run_ends_with_a_summary_per_source(feeds, discord, taken_in, monkeypatch, caplog):
    monkeypatch.setattr(cli, "POSTING_ENABLED", True)
    os.environ.update(HOOKS)
    caplog.set_level(logging.INFO)
    discord.fail = {"WEBHOOK_ADVISORIES": 404}
    assert run(feeds, taken_in) == cli.EXIT_POST_FAILED

    news = len(discord.titles("WEBHOOK_NEWS"))
    record = summary_row(caplog, "Record")
    # source, fetch, items, new, filtered, posted, left, errors, seconds
    assert record[:2] == ["Record", "ok"]
    items, new_, filtered, posted, left, errors = map(int, record[2:8])
    assert new_ == items and filtered == 0 and posted == news == 5
    assert left == new_ - posted and errors == 0

    cisco = summary_row(caplog, "Cisco")
    assert cisco[1] == "ok"
    new_, posted, left, errors = int(cisco[3]), int(cisco[5]), int(cisco[6]), int(cisco[7])
    assert posted == 0 and left == new_ > 0 and errors == new_  # each unposted item failed

    assert "summary: total" in caplog.text
    assert "run: finished in " in caplog.text
    assert "secret-token" not in caplog.text

    # Next run: The Record answers 304; Cisco is fetched again and posts.
    discord.fail = {}
    caplog.clear()
    assert run(feeds, taken_in) == 0
    assert summary_row(caplog, "Record")[1:4] == ["not", "modified", "0"]
    assert int(summary_row(caplog, "Cisco")[5]) == new_


def test_the_summary_counts_fetch_failures_and_flood_guard_holds(
    discord, tmp_path, monkeypatch, caplog
):
    monkeypatch.setattr(cli, "POSTING_ENABLED", True)
    os.environ.update(HOOKS)
    caplog.set_level(logging.INFO)
    config = tmp_path / "sources.yaml"
    config.write_text(
        CONFIG + "  - name: Gone\n    url: https://feeds.example.com/gone.xml\n"
        "    type: rss\n    category: news\n"
    )

    def handler(request):
        if request.url.path == "/gone.xml":
            return httpx.Response(404)
        return httpx.Response(200, content=BODIES[request.url.path])

    monkeypatch.setattr(fetch, "make_client", lambda transport=None: fetch_client(handler))
    # First run: every source is new, so the guard holds all but the newest few.
    assert run(config, tmp_path / "state.json") == 0
    # fetch, items, new, filtered, posted, left, errors
    assert summary_row(caplog, "Gone")[1:8] == ["failed", "0", "0", "0", "0", "0", "1"]
    record = summary_row(caplog, "Record")
    new_, filtered, posted, left = (int(c) for c in record[3:7])
    assert filtered > 0 and posted <= DEFAULTS.new_source_posts
    assert left == 0 and new_ == filtered + posted
    assert "summary: total" in caplog.text


def test_a_slow_run_warns_about_the_minute_budget(feeds, discord, taken_in, monkeypatch, caplog):
    monkeypatch.setattr(cli, "POSTING_ENABLED", True)
    os.environ.update(HOOKS)
    ticks = iter([0.0])
    monkeypatch.setattr(cli, "_clock", lambda: next(ticks, 75.0))
    assert run(feeds, taken_in) == 0
    assert "run: took 75.0 s, over the 60 s budget" in caplog.text
