import json
import os
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from conftest import fetch_client

from intel_feeds import fetch
from intel_feeds import state as state_mod
from intel_feeds.__main__ import main
from intel_feeds.state import State, StateError, format_time, load_state, save_state

REPO = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 18, 9, 30, 15, 123456, tzinfo=UTC)


def full_state() -> State:
    s = State()
    s.add_sources(["CISA KEV", "SecurityWeek"], NOW)
    s.set_fetch_info("SecurityWeek", '"abc123"', "Wed, 18 Nov 2026 09:00:00 GMT")
    s.mark_seen("https://example.com/a", "SecurityWeek", NOW, NOW - timedelta(minutes=18))
    s.mark_posted("https://example.com/a", NOW + timedelta(seconds=5))
    s.mark_seen("CVE-2026-0001", "CISA KEV", NOW)
    return s


# --- load ---------------------------------------------------------------


def test_missing_file_is_an_empty_state(tmp_path):
    s = load_state(tmp_path / "state.json")
    assert s.sources == {} and s.items == {}


def test_round_trip_keeps_every_field(tmp_path):
    path = tmp_path / "state.json"
    original = full_state()
    assert save_state(path, original) is True
    loaded = load_state(path)
    assert loaded == original
    item = loaded.items["https://example.com/a"]
    assert item.published_at == "2026-11-18T09:12:15Z"
    assert item.posted_at == "2026-11-18T09:30:20Z"
    assert loaded.sources["SecurityWeek"].etag == '"abc123"'
    assert loaded.items["CVE-2026-0001"].published_at is None


def test_file_layout_matches_the_documented_schema(tmp_path):
    path = tmp_path / "state.json"
    save_state(path, full_state())
    data = json.loads(path.read_text())
    assert data["version"] == 1
    assert data["sources"]["CISA KEV"] == {
        "first_seen": "2026-11-18T09:30:15Z",
        "etag": None,
        "last_modified": None,
        "cursor": None,
        "backlog_at": None,
        "failing_since": None,
        "failures": None,
        "alerted_at": None,
    }
    assert set(data["items"]["CVE-2026-0001"]) == {
        "source", "first_seen", "published_at", "posted_at", "url",
    }


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{not json", "state.json:1: not valid JSON"),
        ("[]", "expected a JSON object"),
        ('{"version": 2}', "unsupported version 2"),
        ('{"sources": {}}', "unsupported version None"),
        ('{"version": 1, "extra": 1}', "unknown top-level field 'extra'"),
        ('{"version": 1, "items": []}', '"items" must be an object'),
        ('{"version": 1, "sources": {"X": {}}}', "source \"X\": missing 'first_seen'"),
        (
            '{"version": 1, "sources": {"X": {"first_seen": "t", "etagg": null}}}',
            "source \"X\": unknown field 'etagg'",
        ),
        (
            '{"version": 1, "items": {"i": {"source": "X", "first_seen": 5}}}',
            "item \"i\": 'first_seen' must be text",
        ),
        (
            '{"version": 1, "items": {"i": {"source": null, "first_seen": "t"}}}',
            "item \"i\": 'source' must be text",
        ),
        (
            '{"version": 1, "sources": {"X": {"first_seen": "t", "failures": "2"}}}',
            "source \"X\": 'failures' must be a whole number or null",
        ),
        (
            '{"version": 1, "sources": {"X": {"first_seen": "t", "failures": -1}}}',
            "source \"X\": 'failures' must be a whole number or null",
        ),
        (
            '{"version": 1, "sources": {"X": {"first_seen": "t", "failures": true}}}',
            "source \"X\": 'failures' must be a whole number or null",
        ),
        (
            '{"version": 1, "sources": {"X": {"first_seen": "t", "alerted_at": 5}}}',
            "source \"X\": 'alerted_at' must be text",
        ),
    ],
)
def test_bad_files_raise_instead_of_starting_empty(tmp_path, content, message):
    path = tmp_path / "state.json"
    path.write_text(content)
    with pytest.raises(StateError) as exc:
        load_state(path)
    assert message in str(exc.value)


def test_a_file_written_before_cursor_existed_still_loads(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(
        '{"version": 1, "sources": {"NVD": {"first_seen": "2026-11-18T09:30:00Z",'
        ' "etag": null, "last_modified": null}}, "items": {}}'
    )
    assert load_state(path).sources["NVD"].cursor is None


def test_set_fetch_info_keeps_the_cursor_round_trip(tmp_path):
    state = State()
    state.add_sources(["NVD"], datetime(2026, 11, 18, tzinfo=UTC))
    state.set_fetch_info("NVD", None, None, cursor="2026-11-18T10:00:00Z")
    path = tmp_path / "state.json"
    save_state(path, state)
    assert load_state(path).sources["NVD"].cursor == "2026-11-18T10:00:00Z"


def test_top_level_sections_may_be_absent(tmp_path):
    path = tmp_path / "state.json"
    path.write_text('{"version": 1}')
    assert load_state(path) == State()


# --- save ---------------------------------------------------------------


def test_saving_identical_state_does_not_rewrite_the_file(tmp_path):
    path = tmp_path / "state.json"
    save_state(path, full_state())
    before = path.stat().st_mtime_ns
    os.utime(path, ns=(before - 10**9, before - 10**9))
    assert save_state(path, load_state(path)) is False
    assert path.stat().st_mtime_ns == before - 10**9


def test_output_is_stable_regardless_of_insert_order(tmp_path):
    a, b = State(), State()
    a.add_sources(["B", "A"], NOW)
    b.add_sources(["A", "B"], NOW)
    assert state_mod.dumps(a) == state_mod.dumps(b)
    assert state_mod.dumps(a).endswith("}\n")


def test_save_creates_the_parent_folder(tmp_path):
    path = tmp_path / ".state" / "state.json"
    assert save_state(path, State()) is True
    assert load_state(path) == State()


def test_failed_write_keeps_the_old_file_and_leaves_no_temp(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    save_state(path, State())
    old = path.read_text()

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(state_mod.os, "replace", boom)
    with pytest.raises(OSError):
        save_state(path, full_state())
    assert path.read_text() == old
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


# --- State methods ------------------------------------------------------


def test_add_sources_returns_only_new_names_and_keeps_first_seen():
    s = State()
    assert s.add_sources(["A", "B"], NOW) == ["A", "B"]
    assert s.add_sources(["B", "C"], NOW + timedelta(hours=1)) == ["C"]
    assert s.sources["B"].first_seen == "2026-11-18T09:30:15Z"


def test_mark_seen_twice_keeps_the_first_record():
    s = State()
    s.mark_seen("id", "A", NOW)
    s.mark_seen("id", "B", NOW + timedelta(hours=1))
    assert s.seen("id") and not s.seen("other")
    assert s.items["id"].source == "A"


def test_format_time_converts_to_utc_and_treats_naive_as_utc():
    plus2 = datetime(2026, 11, 18, 11, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    assert format_time(plus2) == "2026-11-18T09:00:00Z"
    assert format_time(datetime(2026, 11, 18, 9, 0, 0)) == "2026-11-18T09:00:00Z"


# --- CLI ----------------------------------------------------------------


def run(*extra):
    return main(["--config", str(REPO / "sources.yaml"), *extra])


def test_first_run_creates_state_and_a_second_failing_run_only_counts_failures(
    tmp_path, caplog
):
    # Offline, every source fails (conftest), so source health counts it.
    path = tmp_path / ".state" / "state.json"
    caplog.set_level("INFO")
    assert run("--state", str(path)) == 0
    first = json.loads(path.read_text())
    assert len(first["sources"]) == 20  # the enabled sources; ransomware.live ships off
    assert {s["failures"] for s in first["sources"].values()} == {1}
    assert "state: saved" in caplog.text

    caplog.clear()
    assert run("--state", str(path)) == 0
    second = json.loads(path.read_text())
    assert "state: 20 sources, 0 items" in caplog.text
    for name, entry in first["sources"].items():
        assert second["sources"][name] == {**entry, "failures": 2}


def test_a_run_that_learns_nothing_leaves_state_alone(tmp_path, monkeypatch, caplog):
    config = tmp_path / "sources.yaml"
    config.write_text(
        "sources:\n"
        "  - name: A\n    url: https://example.com/a.xml\n    type: rss\n    category: news\n"
        "  - name: B\n    url: https://example.com/b.xml\n    type: rss\n    category: news\n"
    )
    monkeypatch.setattr(
        fetch, "make_client", lambda transport=None: fetch_client(lambda r: httpx.Response(304))
    )
    path = tmp_path / "state.json"
    caplog.set_level("INFO")
    assert main(["--config", str(config), "--state", str(path)]) == 0
    first = path.read_text()
    caplog.clear()
    assert main(["--config", str(config), "--state", str(path)]) == 0
    assert path.read_text() == first
    assert "state: unchanged, not written" in caplog.text


def test_disabled_sources_are_not_recorded(tmp_path):
    config = tmp_path / "sources.yaml"
    config.write_text(
        "sources:\n"
        "  - name: Kept\n    url: https://example.com/a.xml\n    type: rss\n    category: news\n"
        "  - name: Skipped\n    url: https://example.com/b.xml\n    type: rss\n    category: news\n"
        "    enabled: false\n"
    )
    assert main(["--config", str(config)]) == 0
    assert list(json.loads((tmp_path / "state.json").read_text())["sources"]) == ["Kept"]


def test_corrupt_state_exits_3_and_is_not_overwritten(tmp_path, capsys):
    path = tmp_path / "state.json"
    path.write_text("{broken")
    assert run("--state", str(path)) == 3
    assert "State file problem" in capsys.readouterr().err
    assert path.read_text() == "{broken"


def test_check_config_and_test_post_do_not_touch_state(tmp_path):
    assert run("--check-config") == 0
    assert run("--test-post") == 1  # no webhooks set in tests
    assert not (tmp_path / "state.json").exists()
