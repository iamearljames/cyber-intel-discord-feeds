"""Config validation: each class of mistake gives a readable message."""

from __future__ import annotations

import textwrap

import pytest

from intel_feeds.config import (
    ConfigError,
    Source,
    load_sources,
    parse_sources,
    webhook_warnings,
)

GOOD_ENTRY = """\
  - name: SecurityWeek
    url: https://www.securityweek.com/feed/
    type: rss
    category: news
"""


def errors_for(text: str) -> list[str]:
    with pytest.raises(ConfigError) as exc:
        parse_sources(textwrap.dedent(text))
    return exc.value.errors


def one_error(text: str) -> str:
    errors = errors_for(text)
    assert len(errors) == 1, errors
    return errors[0]


def test_valid_entry_loads_with_defaults():
    [source] = parse_sources("sources:\n" + GOOD_ENTRY)
    assert source == Source(
        name="SecurityWeek",
        url="https://www.securityweek.com/feed/",
        type="rss",
        category="news",
        enabled=True,
        notes="",
    )


def test_message_matches_the_documented_format():
    error = one_error("sources:\n" + GOOD_ENTRY.replace("category: news", "category: new"))
    assert error == (
        'sources.yaml:2: source "SecurityWeek": unknown category "new"; '
        "did you mean 'news'? (allowed: news, vulns, advisories, research, ransomware)"
    )


def test_unknown_type():
    error = one_error("sources:\n" + GOOD_ENTRY.replace("type: rss", "type: atom"))
    assert 'unknown type "atom"' in error
    assert "(allowed: rss, kev, nvd, ransomware)" in error


@pytest.mark.parametrize("field", ["name", "url", "type", "category"])
def test_missing_required_field(field):
    fields = {
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed/",
        "type": "rss",
        "category": "news",
    }
    del fields[field]
    body = "\n    ".join(f"{key}: {value}" for key, value in fields.items())
    assert f"missing required field {field!r}" in one_error(f"sources:\n  - {body}\n")


def test_entry_without_name_is_identified_by_position_and_line():
    text = "sources:\n" + GOOD_ENTRY + "  - url: https://example.com/feed/\n    type: rss\n    category: news\n"
    error = one_error(text)
    assert error.startswith("sources.yaml:6: entry 2 (no name): ")


def test_field_left_blank_counts_as_missing():
    error = one_error("sources:\n" + GOOD_ENTRY.replace("type: rss", "type:"))
    assert "missing required field 'type'" in error


def test_misspelled_field_suggests_the_right_one():
    error = one_error("sources:\n" + GOOD_ENTRY + "    enable: false\n")
    assert "unknown field 'enable'; did you mean 'enabled'?" in error


def test_field_repeated_in_one_entry():
    error = one_error("sources:\n" + GOOD_ENTRY + "    category: research\n")
    assert "field 'category' appears more than once" in error


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("http://www.securityweek.com/feed/", "must start with https://"),
        ("www.securityweek.com/feed/", "must start with https://"),
        ("https:///feed/", "has no valid host name"),
        ("https://localhost/feed", "has no valid host name"),
        ("https://www.security week.com/feed/", "contains spaces"),
    ],
)
def test_bad_url_shape(url, message):
    error = one_error("sources:\n" + GOOD_ENTRY.replace("https://www.securityweek.com/feed/", url))
    assert message in error


def test_url_that_is_not_text():
    error = one_error("sources:\n" + GOOD_ENTRY.replace("https://www.securityweek.com/feed/", "42"))
    assert "'url' must be text, found a number" in error


def test_duplicate_name_ignores_case_and_points_at_first_use():
    second = GOOD_ENTRY.replace("SecurityWeek", "securityweek").replace("securityweek.com", "example.com")
    error = one_error("sources:\n" + GOOD_ENTRY + second)
    assert error.startswith('sources.yaml:6: source "securityweek": duplicate name (also used on line 2)')


@pytest.mark.parametrize("value", ['"yes please"', "1", '"true"'])
def test_enabled_must_be_true_or_false(value):
    error = one_error("sources:\n" + GOOD_ENTRY + f"    enabled: {value}\n")
    assert "'enabled' must be true or false" in error


def test_notes_must_be_text():
    error = one_error("sources:\n" + GOOD_ENTRY + "    notes: [a, b]\n")
    assert "'notes' must be text, found a list" in error


def test_entry_that_is_not_a_mapping():
    error = one_error("sources:\n  - just a string\n")
    assert error.startswith("sources.yaml:2: entry 1 (no name): expected fields like 'name:'")


def test_all_errors_reported_in_one_run():
    bad_one = GOOD_ENTRY.replace("category: news", "category: new")
    bad_two = (
        GOOD_ENTRY.replace("SecurityWeek", "Other")
        .replace("type: rss", "type: atom")
        .replace("https://www.securityweek.com/feed/", "http://example.com/feed")
    )
    errors = errors_for("sources:\n" + bad_one + bad_two)
    assert len(errors) == 3
    assert errors[0].startswith('sources.yaml:2: source "SecurityWeek"')
    assert all(e.startswith('sources.yaml:6: source "Other"') for e in errors[1:])


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "file is empty"),
        ("# only comments\n", "file is empty"),
        ("- name: x\n", "expected a top-level 'sources:' list, found a list"),
        ("feeds:\n" + GOOD_ENTRY, "missing the top-level 'sources:' list"),
        ("sources: hello\n", "'sources' must be a list"),
        ("sources: []\n", "'sources' is empty"),
    ],
)
def test_file_level_mistakes(text, message):
    assert any(message in e for e in errors_for(text))


def test_unknown_top_level_key_suggests_a_fix():
    errors = errors_for("source:\n" + GOOD_ENTRY)
    assert any("unknown top-level key 'source'; did you mean 'sources'?" in e for e in errors)


def test_yaml_syntax_error_names_the_line_and_hints():
    text = "sources:\n" + GOOD_ENTRY + "    notes: Rate limited: use a key\n"
    error = one_error(text)
    assert error.startswith("sources.yaml:6: YAML syntax error: mapping values are not allowed here")
    assert "needs quotes" in error


def test_tab_indentation_hint():
    error = one_error("sources:\n\t- name: x\n")
    assert "use spaces, not tabs" in error


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_sources(tmp_path / "nope.yaml")
    assert exc.value.errors == [f"{tmp_path / 'nope.yaml'}: file not found"]


def test_label_uses_the_file_name(tmp_path):
    path = tmp_path / "custom.yaml"
    path.write_text("sources:\n" + GOOD_ENTRY.replace("type: rss", "type: atom"))
    with pytest.raises(ConfigError) as exc:
        load_sources(path)
    assert exc.value.errors[0].startswith('custom.yaml:2: source "SecurityWeek"')


def test_disabled_entries_are_still_validated():
    error = one_error("sources:\n" + GOOD_ENTRY.replace("type: rss", "type: atom") + "    enabled: false\n")
    assert 'unknown type "atom"' in error


# Webhook warnings ------------------------------------------------------------

SOURCES = [
    Source("A", "https://a.example.com/feed", "rss", "news"),
    Source("B", "https://b.example.com/feed", "rss", "news"),
    Source("C", "https://c.example.com/feed", "rss", "research"),
    Source("D", "https://d.example.com/feed", "rss", "advisories", enabled=False),
]


def test_warns_for_each_category_with_enabled_sources_and_no_webhook():
    warnings = webhook_warnings(SOURCES, {"WEBHOOK_RESEARCH": "set"})
    assert warnings == [
        'no webhook for category "news": WEBHOOK_NEWS is not set, so 2 enabled sources will not post'
    ]


def test_blank_webhook_counts_as_unset():
    warnings = webhook_warnings(SOURCES, {"WEBHOOK_NEWS": "  ", "WEBHOOK_RESEARCH": "x"})
    assert len(warnings) == 1 and "WEBHOOK_NEWS" in warnings[0]


def test_no_warning_when_every_used_category_has_a_webhook():
    assert webhook_warnings(SOURCES, {"WEBHOOK_NEWS": "x", "WEBHOOK_RESEARCH": "y"}) == []
