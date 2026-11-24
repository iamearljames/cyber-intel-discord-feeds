"""The KEV @everyone ping."""

import json
import logging
import os
from dataclasses import replace

from test_route import HOOKS, NOW, FakeDiscord, new, split

from intel_feeds import route
from intel_feeds.__main__ import main
from intel_feeds.state import State, save_state

ENV = HOOKS
EVERYONE = {"content": "@everyone", "allowed_mentions": {"parse": ["everyone"]}}


def kev(cve="CVE-2026-0001", hours=1):
    return new(cve, source="CISA KEV", category="vulns", hours=hours, item_id=f"kev:{cve}")


KEV_ENTRY = (
    "sources:\n  - name: CISA KEV\n    url: https://example.com/kev.json\n"
    "    type: kev\n    category: vulns\n"
)


# --- config --------------------------------------------------------------


def test_check_config_has_no_kev_warning(tmp_path, caplog):
    config = tmp_path / "sources.yaml"
    config.write_text(KEV_ENTRY)
    assert main(["--config", str(config), "--check-config"]) == 0
    assert "kev" not in caplog.text.lower()


# --- posting -------------------------------------------------------------


def post(splits, env):
    discord = FakeDiscord()
    report = route.post(discord.client(), route.plan(splits, env), State(), NOW, env)
    return discord, report


def test_a_kev_entry_mentions_everyone(caplog):
    caplog.set_level(logging.INFO)
    discord, report = post({"CISA KEV": split(kev())}, ENV)
    [(variable, payload)] = discord.posts
    assert variable == "WEBHOOK_VULNS"
    assert payload["content"] == "@everyone"
    assert payload["allowed_mentions"] == {"parse": ["everyone"]}
    assert report.pinged == 1 and report.posted == 1
    assert "post WEBHOOK_VULNS: 1 KEV entries pinged @everyone" in caplog.text


def test_each_new_kev_entry_pings():
    discord, report = post({"CISA KEV": split(kev("CVE-2026-0002", 2), kev("CVE-2026-0001", 1))}, ENV)
    assert [p["content"] for _, p in discord.posts] == ["@everyone"] * 2
    assert report.pinged == 2


def test_other_items_never_ping_even_with_a_kev_badge():
    # An MSRC entry whose CVE is in KEV carries the badge but is not a KEV entry.
    msrc = new("CVE-2026-0003", source="Microsoft MSRC", category="advisories", hours=1)
    msrc = replace(msrc, item=replace(msrc.item, kev=True))  # as the CVE filter sets it
    nvd = new("CVE-2026-0004", source="NVD", category="vulns", hours=1, item_id="nvd:CVE-2026-0004")
    news = new("story @everyone", hours=1)
    discord, report = post({"M": split(msrc), "N": split(nvd), "S": split(news)}, ENV)
    assert len(discord.posts) == 3
    for _, payload in discord.posts:
        assert "content" not in payload
        assert payload["allowed_mentions"] == {"parse": []}
    assert report.pinged == 0


def test_a_failed_kev_post_is_not_counted_as_pinged():
    discord = FakeDiscord(fail={"WEBHOOK_VULNS": 404})
    report = route.post(discord.client(), route.plan({"K": split(kev())}, ENV), State(), NOW, ENV)
    assert report.failed == 1 and report.pinged == 0


# --- the run -------------------------------------------------------------


def test_a_run_mentions_everyone_on_a_kev_post(tmp_path, monkeypatch):
    """End to end: a new KEV entry from the feed posts with @everyone."""
    import httpx
    from conftest import fetch_client

    from intel_feeds import __main__ as cli
    from intel_feeds import fetch, webhook

    monkeypatch.setattr(cli, "POSTING_ENABLED", True)
    os.environ.update(HOOKS)
    catalog = {"vulnerabilities": [{
        "cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Widget",
        "vulnerabilityName": "Acme Widget RCE", "dateAdded": NOW.strftime("%Y-%m-%d"),
        "shortDescription": "Remote code execution.",
    }]}
    monkeypatch.setattr(
        fetch, "make_client",
        lambda transport=None: fetch_client(lambda r: httpx.Response(200, json=catalog)),
    )
    discord = FakeDiscord()
    monkeypatch.setattr(webhook, "make_client", lambda transport=None: discord.client())
    state = State()
    state.add_sources(["CISA KEV"], NOW)
    state.sources["CISA KEV"].backlog_at = "2026-11-18T00:00:00Z"
    save_state(tmp_path / "state.json", state)
    config = tmp_path / "sources.yaml"
    config.write_text("settings:\n  max_age_days: 36500\n  keep_days: 146000\n" + KEV_ENTRY)
    assert main(["--config", str(config), "--state", str(tmp_path / "state.json")]) == 0
    [(variable, payload)] = discord.posts
    assert variable == "WEBHOOK_VULNS"
    assert {k: payload[k] for k in EVERYONE} == EVERYONE
    assert json.dumps(payload).count("@everyone") == 1  # the mention only, never feed text
