"""The optional settings: section of sources.yaml."""

import logging
import os
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from conftest import fetch_client

from intel_feeds import __main__ as cli
from intel_feeds import fetch, webhook
from intel_feeds.__main__ import main
from intel_feeds.config import (
    DEFAULTS,
    WEBHOOK_ENV,
    ConfigError,
    Settings,
    parse_config,
    webhook_warnings,
)
from intel_feeds.state import State, save_state

SOURCE = (
    "sources:\n  - name: Blog\n    url: https://example.com/feed\n"
    "    type: rss\n    category: news\n"
)


def settings(text: str) -> Settings:
    return parse_config("settings:\n" + text + SOURCE).settings


def problems(text: str) -> list[str]:
    with pytest.raises(ConfigError) as exc:
        parse_config("settings:\n" + text + SOURCE)
    return exc.value.errors


# --- defaults --------------------------------------------------------------


def test_without_a_settings_section_every_default_applies():
    assert parse_config(SOURCE).settings == DEFAULTS
    assert parse_config("settings:\n" + SOURCE).settings == DEFAULTS


def test_the_defaults_are_the_values_from_before_21():
    assert (
        DEFAULTS.cvss_min,
        DEFAULTS.cve_lookups_per_run,
        DEFAULTS.posts_per_channel,
        DEFAULTS.new_source_posts,
        DEFAULTS.max_age,
        DEFAULTS.keep_for,
        dict(DEFAULTS.webhooks),
    ) == (9.8, 20, 10, 3, timedelta(days=7), timedelta(days=90), WEBHOOK_ENV)


def test_the_real_sources_yaml_is_valid_and_keeps_the_defaults():
    config = cli.load_config(Path(__file__).resolve().parents[1] / "sources.yaml")
    # Only the watchlist differs from the defaults.
    assert config.settings == Settings(watchlist=config.settings.watchlist)


def test_settings_can_come_before_or_after_sources():
    after = parse_config(SOURCE + "settings:\n  cvss_min: 9\n")
    assert after.settings.cvss_min == 9.0


# --- each setting ----------------------------------------------------------


def test_every_setting_is_read():
    got = settings(
        "  cvss_min: 9\n  cve_lookups_per_run: 10\n  posts_per_channel: 5\n"
        "  new_source_posts: 0\n  max_age_days: 14\n  keep_days: 120\n"
        "  webhooks:\n    news: DISCORD_NEWS\n"
    )
    assert got.cvss_min == 9.0 and isinstance(got.cvss_min, float)
    assert (got.cve_lookups_per_run, got.posts_per_channel, got.new_source_posts) == (10, 5, 0)
    assert (got.max_age, got.keep_for) == (timedelta(days=14), timedelta(days=120))
    # Categories left out keep their default variable.
    assert got.webhooks == {**WEBHOOK_ENV, "news": "DISCORD_NEWS"}


@pytest.mark.parametrize(
    "line, message",
    [
        ("cvss_min: high", "'cvss_min' must be a number from 0 to 10, found \"high\""),
        ("cvss_min: 10.5", "'cvss_min' must be a number from 0 to 10, found 10.5 (a number)"),
        ("cvss_min: true", "'cvss_min' must be a number from 0 to 10, found True (true/false)"),
        ("cve_lookups_per_run: 41", "'cve_lookups_per_run' must be a whole number from 0 to 40"),
        ("cve_lookups_per_run: 2.5", "'cve_lookups_per_run' must be a whole number from 0 to 40"),
        ("posts_per_channel: 0", "'posts_per_channel' must be a whole number from 1 to 25, found 0"),
        ("posts_per_channel: 26", "'posts_per_channel' must be a whole number from 1 to 25"),
        ("new_source_posts: -1", "'new_source_posts' must be a whole number from 0 to 25"),
        ("max_age_days: 0", "'max_age_days' must be a whole number of 1 or more, found 0"),
        ("keep_days: '90'", "'keep_days' must be a whole number of 1 or more, found \"90\""),
    ],
)
def test_a_bad_value_names_the_setting_and_the_line(line, message):
    [problem] = problems(f"  {line}\n")
    assert problem.startswith("sources.yaml:2: settings: ")
    assert message in problem


def test_an_unknown_setting_suggests_the_closest():
    [problem] = problems("  cvss_minimum: 9\n")
    assert "unknown setting 'cvss_minimum'; did you mean 'cvss_min'?" in problem
    assert "(allowed: cvss_min, cve_lookups_per_run," in problem


def test_a_setting_given_twice_is_an_error():
    found = problems("  cvss_min: 9\n  cvss_min: 9.5\n")
    assert any("'cvss_min' appears more than once" in p for p in found)


def test_settings_must_be_a_set_of_fields():
    [problem] = problems("  - cvss_min: 9\n")
    assert "'settings' must be a set of fields like 'cvss_min: 9.8', found a list" in problem


def test_every_problem_is_listed_at_once_with_the_sources_problems():
    with pytest.raises(ConfigError) as exc:
        parse_config("settings:\n  cvss_min: x\n  posts_per_channel: 0\n" + SOURCE.replace("news", "new"))
    assert len(exc.value.errors) == 3


# --- keep_days against max_age_days -------------------------------------------


def test_keep_days_must_stay_four_times_max_age_days():
    [problem] = problems("  max_age_days: 30\n")  # keep_days stays 90
    assert "'keep_days' (90) must be at least 4 times 'max_age_days' (30), so at least 120" in problem
    assert settings("  max_age_days: 30\n  keep_days: 120\n").keep_days == 120
    [problem] = problems("  keep_days: 27\n")  # max_age_days stays 7
    assert "at least 28" in problem


# --- webhooks ------------------------------------------------------------------


def test_webhooks_must_name_known_categories_and_variable_names():
    found = problems("  webhooks:\n    vuln: WEBHOOK_VULNS\n    news: webhook_news\n")
    assert any("unknown category \"vuln\"; did you mean 'vulns'?" in p for p in found)
    assert any(
        "'news' must name an environment variable in capitals, like WEBHOOK_NEWS" in p
        for p in found
    )


def test_a_webhook_url_pasted_into_the_settings_is_never_echoed():
    url = "https://discord.com/api/webhooks/123/secret-token"
    [problem] = problems(f"  webhooks:\n    news: {url}\n")
    assert "looks like a URL; the URL goes in that variable, not here" in problem
    assert "secret-token" not in problem and "discord.com" not in problem


def test_webhooks_must_be_a_set_of_fields():
    [problem] = problems("  webhooks: WEBHOOK_NEWS\n")
    assert "'webhooks' must be a set of fields like 'news: WEBHOOK_NEWS', found text" in problem


def test_two_categories_may_share_a_webhook():
    got = settings("  webhooks:\n    research: WEBHOOK_NEWS\n")
    assert got.webhooks["research"] == got.webhooks["news"] == "WEBHOOK_NEWS"


def test_webhook_warnings_follow_the_mapping():
    sources = parse_config(SOURCE).sources
    custom = Settings(webhooks={**WEBHOOK_ENV, "news": "DISCORD_NEWS"})
    [warning] = webhook_warnings(sources, {"WEBHOOK_NEWS": "x"}, custom)
    assert "DISCORD_NEWS is not set" in warning
    assert webhook_warnings(sources, {"DISCORD_NEWS": "x"}, custom) == []


def test_test_posts_follow_the_mapping():
    seen = []
    client = httpx.Client(
        transport=httpx.MockTransport(lambda r: seen.append(r.url.path) or httpx.Response(204))
    )
    env = {"DISCORD_NEWS": "https://discord.invalid/api/webhooks/1/tok"}
    results = webhook.send_test_posts(client, env, {**WEBHOOK_ENV, "news": "DISCORD_NEWS"})
    assert results[0] == ("DISCORD_NEWS", "posted")
    assert seen == ["/api/webhooks/1/tok"]


# --- a run uses the settings -----------------------------------------------------


def test_a_run_uses_the_cap_the_webhook_mapping_and_max_age_from_the_settings(
    tmp_path, monkeypatch, caplog
):
    """No age limit (the fixture's dates age as time goes on); the cap holds 2 of 5."""
    from test_route import BODIES, FakeDiscord

    monkeypatch.setattr(cli, "POSTING_ENABLED", True)
    monkeypatch.setattr(
        fetch,
        "make_client",
        lambda transport=None: fetch_client(
            lambda r: httpx.Response(200, content=BODIES["/record.xml"])
        ),
    )
    discord = FakeDiscord()
    monkeypatch.setattr(webhook, "make_client", lambda transport=None: discord.client())
    # FakeDiscord tells channels apart by path; point DISCORD_NEWS at the news one.
    os.environ["DISCORD_NEWS"] = "https://discord.invalid/api/webhooks/1/news-secret-token"
    config = tmp_path / "sources.yaml"
    config.write_text(
        "settings:\n  posts_per_channel: 2\n  max_age_days: 36500\n  keep_days: 146000\n"
        "  webhooks:\n    news: DISCORD_NEWS\n"
        "sources:\n  - name: Record\n    url: https://feeds.example.com/record.xml\n"
        "    type: rss\n    category: news\n"
    )
    state = State()
    state.add_sources(["Record"], cli.datetime.now(cli.UTC))
    state.sources["Record"].backlog_at = "2026-11-18T00:00:00Z"
    save_state(tmp_path / "state.json", state)
    caplog.set_level(logging.INFO)

    assert main(["--config", str(config), "--state", str(tmp_path / "state.json")]) == 0
    assert len(discord.titles("WEBHOOK_NEWS")) == 2
    assert "post DISCORD_NEWS: 2 posted, 3 over the cap of 2 left for the next run" in caplog.text
    assert "secret-token" not in caplog.text


def test_a_run_passes_max_age_days_to_the_flood_guard(tmp_path, monkeypatch, caplog):
    # The run's clock is real, so only the limit in the log is checked here;
    # holding stale items is tested in test_guard.py.
    from test_route import BODIES, HOOKS, FakeDiscord

    monkeypatch.setattr(cli, "POSTING_ENABLED", True)
    monkeypatch.setattr(
        fetch,
        "make_client",
        lambda transport=None: fetch_client(
            lambda r: httpx.Response(200, content=BODIES["/record.xml"])
        ),
    )
    discord = FakeDiscord()
    monkeypatch.setattr(webhook, "make_client", lambda transport=None: discord.client())
    os.environ.update(HOOKS)
    config = tmp_path / "sources.yaml"
    config.write_text(
        "settings:\n  max_age_days: 3\n"
        "sources:\n  - name: Record\n    url: https://feeds.example.com/record.xml\n"
        "    type: rss\n    category: news\n"
    )
    state = State()
    state.add_sources(["Record"], cli.datetime.now(cli.UTC))
    state.sources["Record"].backlog_at = "2026-11-18T00:00:00Z"
    save_state(tmp_path / "state.json", state)
    caplog.set_level(logging.INFO)

    assert main(["--config", str(config), "--state", str(tmp_path / "state.json")]) == 0
    assert "flood guard: held back 0 (new source), " in caplog.text
    assert "(older than 3 days)" in caplog.text


def test_check_config_reports_settings_problems(tmp_path, capsys):
    config = tmp_path / "sources.yaml"
    config.write_text("settings:\n  posts_per_channel: 100\n" + SOURCE)
    assert main(["--config", str(config), "--check-config"]) == cli.EXIT_CONFIG_ERROR
    err = capsys.readouterr().err
    assert "sources.yaml:2: settings: 'posts_per_channel' must be a whole number from 1 to 25" in err
