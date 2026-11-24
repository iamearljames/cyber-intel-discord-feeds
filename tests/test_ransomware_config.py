"""Config for the ransomware.live channel."""

import logging

import pytest
from test_route import HOOKS, new, split

from intel_feeds import route
from intel_feeds.__main__ import main
from intel_feeds.config import (
    DEFAULTS,
    RANSOMWARE_KEY_ENV,
    WEBHOOK_ENV,
    ConfigError,
    Source,
    key_warnings,
    parse_config,
    webhook_warnings,
)

SECRET = "rl-key-that-must-never-show-0123456789"

RANSOM = (
    "  - name: ransomware.live\n    url: https://api-pro.ransomware.live/victims/recent\n"
    "    type: ransomware\n    category: ransomware\n"
)
BLOG = (
    "  - name: Blog\n    url: https://example.com/feed\n"
    "    type: rss\n    category: news\n"
)


def problems(text: str) -> list[str]:
    with pytest.raises(ConfigError) as exc:
        parse_config(text)
    return exc.value.errors


# --- variable names -----------------------------------------------------------


def test_the_variable_names():
    assert WEBHOOK_ENV["ransomware"] == "WEBHOOK_RANSOM"
    assert DEFAULTS.webhooks["ransomware"] == "WEBHOOK_RANSOM"
    assert RANSOMWARE_KEY_ENV == "RANSOMWARE_LIVE_API"


def test_the_other_channels_keep_their_names():
    assert {c: WEBHOOK_ENV[c] for c in ("news", "vulns", "advisories", "research")} == {
        "news": "WEBHOOK_NEWS",
        "vulns": "WEBHOOK_VULNS",
        "advisories": "WEBHOOK_ADVISORIES",
        "research": "WEBHOOK_RESEARCH",
    }


# --- source entries ----------------------------------------------------------


def test_a_ransomware_source_is_valid():
    [source] = parse_config("sources:\n" + RANSOM).sources
    assert (source.type, source.category) == ("ransomware", "ransomware")


def test_a_ransomware_source_must_post_to_the_ransomware_channel():
    [problem] = problems("sources:\n" + RANSOM.replace("category: ransomware", "category: news"))
    assert "type ransomware must use category 'ransomware'" in problem


def test_only_ransomware_sources_may_use_the_ransomware_channel():
    [problem] = problems("sources:\n" + BLOG.replace("category: news", "category: ransomware"))
    assert "category 'ransomware' is only for type ransomware" in problem


@pytest.mark.parametrize("field", ["revisions", "cve_filter"])
def test_rss_only_fields_are_rejected_on_a_ransomware_source(field):
    [problem] = problems("sources:\n" + RANSOM + f"    {field}: true\n")
    assert f"'{field}' applies only to type rss" in problem


# --- channel caps --------------------------------------------------------------


def test_the_ransomware_channel_posts_25_a_run_and_the_others_10():
    assert DEFAULTS.cap_for("ransomware") == 25
    for category in ("news", "vulns", "advisories", "research"):
        assert DEFAULTS.cap_for(category) == 10


def test_channel_caps_override_one_category_and_keep_the_default_for_ransomware():
    got = parse_config("settings:\n  channel_caps:\n    vulns: 5\nsources:\n" + BLOG).settings
    assert (got.cap_for("vulns"), got.cap_for("ransomware"), got.cap_for("news")) == (5, 25, 10)


def test_posts_per_channel_does_not_change_an_overridden_channel():
    got = parse_config("settings:\n  posts_per_channel: 3\nsources:\n" + BLOG).settings
    assert (got.cap_for("news"), got.cap_for("ransomware")) == (3, 25)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("channel_caps: 25", "'channel_caps' must be a set of fields like 'ransomware: 25', found"),
        ("channel_caps:\n    ransom: 25", "unknown category \"ransom\"; did you mean 'ransomware'?"),
        ("channel_caps:\n    ransomware: 0", "'ransomware' must be a whole number from 1 to 25, found 0"),
        ("channel_caps:\n    ransomware: 26", "'ransomware' must be a whole number from 1 to 25"),
        ("channel_caps:\n    ransomware: true", "'ransomware' must be a whole number from 1 to 25"),
    ],
)
def test_bad_channel_caps_are_reported(text, message):
    [problem] = problems("settings:\n  " + text + "\nsources:\n" + BLOG)
    assert message in problem


def test_plan_uses_each_channels_own_cap():
    hooks = {**HOOKS, "WEBHOOK_RANSOM": "https://webhook.invalid/r"}
    victims = [new(f"r{i}", source="R", category="ransomware", hours=i) for i in range(30)]
    news = [new(f"n{i}", source="A", hours=i) for i in range(12)]
    plan = route.plan(
        {"R": split(*reversed(victims)), "A": split(*reversed(news))},
        hooks,
        cap=10,
        caps={"ransomware": 25},
    )
    by_var = {r.variable: r for r in plan.routes}
    assert (len(by_var["WEBHOOK_RANSOM"].items), len(by_var["WEBHOOK_RANSOM"].overflow)) == (25, 5)
    assert (len(by_var["WEBHOOK_NEWS"].items), len(by_var["WEBHOOK_NEWS"].overflow)) == (10, 2)
    assert by_var["WEBHOOK_RANSOM"].cap == 25


# --- warnings never show values -------------------------------------------------


SOURCES = [Source("R", "https://api-pro.ransomware.live/victims/recent", "ransomware", "ransomware")]


def test_a_missing_key_is_a_warning_that_names_only_the_variable():
    assert key_warnings(SOURCES, {}) == [
        "no ransomware.live API key: RANSOMWARE_LIVE_API is not set, "
        "so 1 enabled ransomware source will fail to fetch"
    ]
    assert len(key_warnings(SOURCES, {RANSOMWARE_KEY_ENV: "  "})) == 1


def test_a_set_key_gives_no_warning_and_no_ransomware_source_needs_no_key():
    assert key_warnings(SOURCES, {RANSOMWARE_KEY_ENV: SECRET}) == []
    disabled = [Source("R", SOURCES[0].url, "ransomware", "ransomware", enabled=False)]
    assert key_warnings(disabled, {}) == []


def test_a_missing_ransomware_webhook_is_named_by_its_variable():
    [warning] = webhook_warnings(SOURCES, {})
    assert "WEBHOOK_RANSOM is not set" in warning


def test_check_config_never_prints_the_key(tmp_path, monkeypatch, capsys, caplog):
    config = tmp_path / "sources.yaml"
    config.write_text("sources:\n" + RANSOM)
    monkeypatch.setenv(RANSOMWARE_KEY_ENV, SECRET)
    monkeypatch.setenv("WEBHOOK_RANSOM", "https://webhook.invalid/api/webhooks/1/" + SECRET)
    with caplog.at_level(logging.DEBUG):
        assert main(["--config", str(config), "--check-config"]) == 0
    out = capsys.readouterr()
    assert SECRET not in out.out + out.err + caplog.text


def test_check_config_warns_when_the_key_is_missing(tmp_path, capsys, caplog):
    config = tmp_path / "sources.yaml"
    config.write_text("sources:\n" + RANSOM)
    with caplog.at_level(logging.WARNING):
        assert main(["--config", str(config), "--check-config"]) == 0
    assert "RANSOMWARE_LIVE_API is not set" in caplog.text
