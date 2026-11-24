"""ransomware.live: fetch with the API key, parse victims, dedup by ID."""

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from conftest import fetch_client
from test_check_feeds import check_feeds, serve, write_config  # noqa: F401 (serve is a fixture)

from intel_feeds import dedup, fetch
from intel_feeds.config import Source, load_sources
from intel_feeds.items import ParseError, Victim, parse
from intel_feeds.state import State

REPO = Path(__file__).resolve().parents[1]
FIXTURE = (REPO / "tests" / "fixtures" / "ransomware_live.json").read_bytes()
NOW = datetime(2026, 11, 20, 3, 0, 0, tzinfo=UTC)
KEY = "test-key-0123456789abcdef"
RL = Source(
    "ransomware.live",
    "https://api-pro.example/victims/recent",
    "ransomware",
    "ransomware",
)


def victims(*entries) -> bytes:
    return json.dumps({"client": "example", "count": len(entries), "victims": list(entries)}).encode()


def victim(**fields) -> dict:
    base = {
        "id": "QWNtZUBncm91cA==",
        "victim": "Acme Corp",
        "group": "SoulGroup",
        "discovered": "2026-11-20T01:22:03.955012+00:00",
        "country": "US",
        "activity": "Manufacturing",
        "website": "acme.example",
        "description": "Acme makes things.",
        "permalink": "https://www.ransomware.live/id/QWNtZUBncm91cA==",
        "post_url": "http://leaksiteexample.onion#Acme",
    }
    base.update(fields)
    return base


# --- fetch ----------------------------------------------------------------


def fetch_one(handler, env):
    with fetch_client(handler) as client:
        return fetch.fetch_source(client, RL, None, NOW, env)


def test_fetch_sends_the_key_header_and_no_validators():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=FIXTURE, headers={"ETag": '"x"'})

    result = fetch_one(handler, {"RANSOMWARE_LIVE_API": KEY})
    assert result.status == fetch.OK and result.body == FIXTURE
    assert seen[0].headers["x-api-key"] == KEY
    assert "if-none-match" not in seen[0].headers
    assert result.etag is None  # nothing to send next time: always a full fetch


def test_fetch_without_a_key_fails_naming_only_the_variable():
    def handler(request):  # pragma: no cover - must not be called
        raise AssertionError("no request without a key")

    result = fetch_one(handler, {"RANSOMWARE_LIVE_API": "  "})
    assert result.status == fetch.FAILED
    assert result.error == "no API key: RANSOMWARE_LIVE_API is not set"


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_fetch_errors_never_include_the_key(status, caplog):
    def handler(request):
        return httpx.Response(status, headers={"message": f"bad key {KEY}"})

    with caplog.at_level(logging.INFO):
        result = fetch_one(handler, {"RANSOMWARE_LIVE_API": KEY})
    assert result.status == fetch.FAILED
    assert result.error.startswith(f"HTTP {status}")
    assert KEY not in result.error and KEY not in caplog.text


# --- parse ----------------------------------------------------------------


def test_fixture_parses_into_one_item_per_victim():
    parsed = parse(RL, FIXTURE)
    data = json.loads(FIXTURE)
    assert parsed.skipped == 0
    assert len(parsed.items) == len(data["victims"]) == 5
    for item, raw in zip(parsed.items, data["victims"]):
        assert item.title == raw["victim"]
        assert item.category == "ransomware" and item.source == "ransomware.live"
        assert item.guid == f"ransomware:{raw['id']}"
        assert item.url == raw["permalink"]
        assert ".onion" not in item.url and ".onion" not in item.excerpt
        assert item.published == datetime.fromisoformat(raw["discovered"])
        assert item.published.tzinfo is UTC
        assert len(item.excerpt) <= 300
        assert "\n" not in item.excerpt
        assert item.victim.group == raw["group"]


def test_fixture_unknowns_become_empty_text():
    items = {i.title: i for i in parse(RL, FIXTURE).items}
    jw = items["J... W..."].victim
    assert jw.country == "" and jw.sector == "" and jw.website == ""
    cm = items["Contoso Motors Sdn. Bhd."].victim
    assert (cm.country, cm.sector, cm.website) == ("MY", "Transportation", "contoso-motors.example")


def test_fixture_long_and_multi_line_descriptions_are_cut_to_one_line():
    items = {i.title: i for i in parse(RL, FIXTURE).items}
    assert 250 < len(items["Northwind Freight Ltd"].excerpt) <= 300  # cut at a word
    assert items["Northwind Freight Ltd"].excerpt.endswith("…")
    assert items["Fabrikam Football Association"].excerpt.startswith("Status: PENDING Deadline:")


def test_group_page_url_is_built_from_the_group_name():
    items = {i.title: i for i in parse(RL, FIXTURE).items}
    assert items["Tailspin Toys Inc"].victim.group_url == (
        "https://www.ransomware.live/group/Handsome%20Boy%20Hacking%20Club"
    )
    assert items["J... W..."].victim.group_url == (
        "https://www.ransomware.live/group/SilentRansomGroup"
    )


def test_one_victim_in_full():
    [item] = parse(RL, victims(victim(country="gb", activity="Not Found", website=""))).items
    assert item.victim == Victim(
        group="SoulGroup",
        group_url="https://www.ransomware.live/group/SoulGroup",
        country="GB",
        sector="",
        website="",
    )
    assert item.excerpt == "Acme makes things."
    assert item.tags == ("SoulGroup",)


def test_missing_permalink_is_rebuilt_from_the_id():
    [item] = parse(RL, victims(victim(permalink=None, id="a/b+c=="))).items
    assert item.url == "https://www.ransomware.live/id/a%2Fb%2Bc%3D%3D"


def test_bad_values_are_dropped_not_fatal():
    [item] = parse(
        RL,
        victims(victim(country="USA", discovered="yesterday", description=None, activity=7)),
    ).items
    assert item.victim.country == "" and item.victim.sector == ""
    assert item.published is None and item.excerpt == ""


@pytest.mark.parametrize("missing", ["victim", "group", "id"])
def test_victims_without_a_name_group_or_id_are_skipped(missing):
    parsed = parse(RL, victims(victim(**{missing: ""}), victim(id="b"), "not a dict"))
    assert len(parsed.items) == 1 and parsed.skipped == 2


@pytest.mark.parametrize(
    "body, problem",
    [(b"<html>", "not JSON"), (b'{"victims": {}}', 'no "victims" list'), (b"[]", 'no "victims" list')],
)
def test_unreadable_responses_raise(body, problem):
    with pytest.raises(ParseError, match=problem):
        parse(RL, body)


# --- dedup ----------------------------------------------------------------


def test_dedup_uses_the_victim_id_and_skips_the_url_check():
    state = State()
    first = parse(RL, FIXTURE).items
    split = dedup.Dedup(state).split(RL, first)
    assert len(split.new) == 5
    assert all(n.id.startswith("ransomware:") and n.url is None for n in split.new)
    for new in split.new:
        dedup.record(state, new, NOW, posted=True)
    again = dedup.Dedup(state).split(RL, parse(RL, FIXTURE).items)
    assert again.new == [] and again.seen == 5


def test_same_victim_name_from_two_groups_is_two_items():
    body = victims(victim(id="QUBh", group="A"), victim(id="QUBi", group="B"))
    split = dedup.Dedup(State()).split(RL, parse(RL, body).items)
    assert len(split.new) == 2


# --- sources.yaml and the feed checker --------------------------------------


def test_committed_entry_ships_off():
    [source] = [s for s in load_sources(REPO / "sources.yaml") if s.type == "ransomware"]
    assert source.url == "https://api-pro.ransomware.live/victims/recent"
    assert source.category == "ransomware"
    assert source.enabled is False  # needs a paid API key: users turn it on


def test_checker_sends_the_key_and_reports_victims(tmp_path, serve, monkeypatch, capsys):
    monkeypatch.setenv("RANSOMWARE_LIVE_API", KEY)
    serve("rl.example", FIXTURE)
    config = write_config(tmp_path, ("RL", "https://rl.example/victims/recent", "ransomware", "ransomware"))
    assert check_feeds.main(["--config", str(config)]) == 0
    assert serve.requests[0].headers["x-api-key"] == KEY
    out = capsys.readouterr().out
    line = next(line for line in out.splitlines() if line.startswith("RL"))
    assert "json (ransomware)" in line and "  5  " in line
    assert KEY not in out


def test_checker_without_a_key_fails_without_a_request(tmp_path, serve, monkeypatch, capsys):
    monkeypatch.delenv("RANSOMWARE_LIVE_API", raising=False)
    config = write_config(tmp_path, ("RL", "https://rl.example/victims/recent", "ransomware", "ransomware"))
    assert check_feeds.main(["--config", str(config)]) == 1
    assert serve.requests == []
    assert "no API key: RANSOMWARE_LIVE_API is not set" in capsys.readouterr().out


def test_checker_saves_a_trimmed_sample_without_the_client(tmp_path, serve, monkeypatch):
    monkeypatch.setenv("RANSOMWARE_LIVE_API", KEY)
    data = json.loads(FIXTURE)
    data["client"] = "account-or-address"
    data["victims"] = data["victims"] + [dict(v, id=v["id"] + "x", discovered="2026-11-01T00:00:00+00:00") for v in data["victims"][:2]]
    serve("rl.example", json.dumps(data).encode())
    config = write_config(tmp_path, ("RL", "https://rl.example/victims/recent", "ransomware", "ransomware"))
    out_dir = tmp_path / "fixtures"
    assert check_feeds.main(["--config", str(config), "--save-fixtures", str(out_dir)]) == 0
    saved = json.loads((out_dir / "ransomware_live.json").read_text())
    assert saved["client"] == "example"
    assert saved["count"] == len(saved["victims"]) == 5
    newest = sorted((v["discovered"] for v in data["victims"]), reverse=True)[:5]
    assert [v["discovered"] for v in saved["victims"]] == newest
