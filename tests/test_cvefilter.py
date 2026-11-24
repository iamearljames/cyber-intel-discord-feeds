import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from conftest import fetch_client
from test_route import HOOKS, FakeDiscord

from intel_feeds import cvefilter, fetch, webhook
from intel_feeds.__main__ import main
from intel_feeds.config import ConfigError, Source, parse_sources
from intel_feeds.dedup import NewItem, Split
from intel_feeds.embeds import item_embed
from intel_feeds.fetch import CveInfo, FetchError
from intel_feeds.items import Item
from intel_feeds.state import State, load_state, save_state

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)

KEV = Source("CISA KEV", "https://kev.example/kev.json", "kev", "vulns")
NVD = Source("NVD CVE API", "https://nvd.example/cves", "nvd", "vulns")
MSRC = Source(
    "Microsoft MSRC", "https://msrc.example/rss", "rss", "advisories",
    revisions=True, cve_filter=True,
)
NEWS = Source("The Record", "https://record.example/feed", "rss", "news")
SOURCES = {s.name: s for s in (KEV, NVD, MSRC, NEWS)}


def new(source, cve=None, *, cvss=None, hours=0, title=None, item_id=None):
    item = Item(
        title=title or (f"{cve} title" if cve else "no CVE here"),
        url=f"https://example.com/{cve or title}",
        source=source.name,
        category=source.category,
        published=NOW - timedelta(hours=hours),
        cve_ids=(cve,) if cve else (),
        cvss=cvss,
        cvss_version="3.1" if cvss is not None else None,
        kev=source.type == "kev",
    )
    return NewItem(item, item_id or f"{source.name}:{cve or title}@{hours}", None)


class FakeNvd:
    """Answers lookups from a dict: CVE -> CveInfo, or an exception to raise."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.asked: list[str] = []

    def __call__(self, cve):
        self.asked.append(cve)
        answer = self.answers.get(cve, CveInfo(found=False))
        if isinstance(answer, Exception):
            raise answer
        return answer


def apply(splits, nvd=None, *, state=None, has_key=True):
    state = state or State()
    nvd = nvd or FakeNvd()
    kept, report = cvefilter.apply(state, splits, SOURCES, NOW, nvd, has_key=has_key)
    return kept, report, state


def ids(split):
    return [n.id for n in split.new]


# --- NVD ---------------------------------------------------------------------


def test_nvd_keeps_cvss_nine_point_eight_and_up_and_drops_the_rest_unrecorded():
    news = [
        new(NVD, "CVE-2026-1", cvss=10.0),
        new(NVD, "CVE-2026-2", cvss=9.8),
        new(NVD, "CVE-2026-3", cvss=9.7),
        new(NVD, "CVE-2026-4"),  # unscored at publish
    ]
    kept, report, state = apply({NVD.name: Split(new=news, seen=2)})
    assert ids(kept[NVD.name]) == [news[0].id, news[1].id]
    assert kept[NVD.name].seen == 2
    counts = report.counts[NVD.name]
    assert (counts.kept, counts.below, counts.in_kev) == (2, 2, 0)
    assert state.items == {}  # dropped CVEs are not recorded
    assert report.deferred_sources == set()


def test_a_cve_in_kev_is_not_posted_again_from_nvd():
    state = State()
    state.mark_seen("kev:CVE-2026-10", KEV.name, NOW)  # an old catalog entry
    splits = {
        KEV.name: Split(new=[new(KEV, "CVE-2026-11", item_id="kev:CVE-2026-11")]),
        NVD.name: Split(
            new=[
                new(NVD, "CVE-2026-10", cvss=9.8),  # in KEV from an earlier run
                new(NVD, "CVE-2026-11", cvss=10.0),  # added to KEV this run
                new(NVD, "CVE-2026-12", cvss=9.9),
            ]
        ),
    }
    kept, report, _ = apply(splits, state=state)
    assert [n.item.cve_ids[0] for n in kept[NVD.name].new] == ["CVE-2026-12"]
    assert report.counts[NVD.name].in_kev == 2
    assert ids(kept[KEV.name]) == ["kev:CVE-2026-11"]  # KEV always posts


def test_an_nvd_cve_that_mentions_a_kev_cve_still_posts():
    state = State()
    state.mark_seen("kev:CVE-2026-10", KEV.name, NOW)
    item = new(NVD, "CVE-2026-20", cvss=9.8)
    item = NewItem(
        Item(**{**vars(item.item), "cve_ids": ("CVE-2026-20", "CVE-2026-10")}), item.id, None
    )
    kept, _, _ = apply({NVD.name: Split(new=[item])}, state=state)
    assert ids(kept[NVD.name]) == [item.id]


def test_kev_and_unfiltered_sources_pass_untouched():
    kev = Split(new=[new(KEV, "CVE-2026-1", item_id="kev:CVE-2026-1")])
    news = Split(new=[new(NEWS, title="story")], seen=1)
    kept, report, _ = apply({KEV.name: kev, NEWS.name: news})
    assert kept[KEV.name] is kev and kept[NEWS.name] is news
    assert report.counts == {}


# --- cve_filter sources (MSRC) ---------------------------------------------------


def test_an_entry_in_kev_posts_with_the_kev_badge_and_no_lookup():
    state = State()
    state.mark_seen("kev:CVE-2026-5", KEV.name, NOW)
    nvd = FakeNvd()
    kept, _, _ = apply({MSRC.name: Split(new=[new(MSRC, "CVE-2026-5")])}, nvd, state=state)
    assert kept[MSRC.name].new[0].item.kev is True
    assert nvd.asked == []


def test_an_entry_scoring_nine_point_eight_or_more_posts_with_its_score():
    nvd = FakeNvd({"CVE-2026-6": CveInfo(True, 9.8, "3.1")})
    kept, report, state = apply({MSRC.name: Split(new=[new(MSRC, "CVE-2026-6")])}, nvd)
    item = kept[MSRC.name].new[0].item
    assert (item.cvss, item.cvss_version) == (9.8, "3.1")
    assert state.items == {}  # recorded only once posted
    fields = {f["name"]: f["value"] for f in item_embed(item)["fields"]}
    assert fields["CVSS"] == "9.8 Critical (v3.1)"
    assert report.lookups == 1


def test_an_entry_nvd_lists_as_kev_posts_whatever_its_score():
    nvd = FakeNvd({"CVE-2026-7": CveInfo(True, 7.8, "3.1", kev=True)})
    kept, _, _ = apply({MSRC.name: Split(new=[new(MSRC, "CVE-2026-7")])}, nvd)
    item = kept[MSRC.name].new[0].item
    assert item.kev is True and item.cvss == 7.8


def test_an_entry_below_the_bar_is_recorded_as_not_posted():
    nvd = FakeNvd({"CVE-2026-8": CveInfo(True, 9.6, "3.1")})  # critical, but under the bar
    entry = new(MSRC, "CVE-2026-8")
    kept, report, state = apply({MSRC.name: Split(new=[entry])}, nvd)
    assert kept[MSRC.name].new == []
    assert state.items[entry.id].posted_at is None
    assert report.counts[MSRC.name].held == 1
    assert report.deferred_sources == set()


def test_an_entry_without_a_cve_is_recorded_as_not_posted():
    entry = new(MSRC, title="ADV-2026-0001 servicing stack update")
    kept, report, state = apply({MSRC.name: Split(new=[entry])})
    assert kept[MSRC.name].new == [] and entry.id in state.items
    assert report.lookups == 0


@pytest.mark.parametrize(
    "answer",
    [
        CveInfo(found=False),  # NVD does not have it yet
        CveInfo(True, None, None),  # NVD has not scored it yet
        FetchError("HTTP 503 Service Unavailable"),
    ],
)
def test_an_entry_nvd_cannot_answer_for_is_deferred_unrecorded(answer):
    entry = new(MSRC, "CVE-2026-9")
    kept, report, state = apply(
        {MSRC.name: Split(new=[entry])}, FakeNvd({"CVE-2026-9": answer})
    )
    assert kept[MSRC.name].new == []
    assert entry.id not in state.items
    assert report.counts[MSRC.name].deferred == 1
    assert report.deferred_sources == {MSRC.name}


def test_a_failed_lookup_is_logged_without_a_url(caplog):
    caplog.set_level(logging.INFO)
    nvd = FakeNvd({"CVE-2026-9": FetchError("network error: ConnectError")})
    _, report, _ = apply({MSRC.name: Split(new=[new(MSRC, "CVE-2026-9")])}, nvd)
    cvefilter.log_report(report)
    assert "NVD lookup of CVE-2026-9 failed: network error: ConnectError" in caplog.text
    assert "cve filter: 1 NVD lookups failed; deferred" in caplog.text
    assert "https://" not in caplog.text


@pytest.mark.parametrize("has_key, limit", [(True, 20), (False, 4)])
def test_lookups_are_capped_per_run_oldest_first(has_key, limit):
    # Feed order is newest first: hours=0 is the newest.
    news = [new(MSRC, f"CVE-2026-{100 + h}", hours=h) for h in range(25)]
    nvd = FakeNvd({n.item.cve_ids[0]: CveInfo(True, 9.9, "3.1") for n in news})
    kept, report, _ = apply({MSRC.name: Split(new=news)}, nvd, has_key=has_key)
    assert report.lookups == limit
    assert nvd.asked == [f"CVE-2026-{100 + h}" for h in range(24, 24 - limit, -1)]
    assert report.counts[MSRC.name].deferred == 25 - limit
    # What posts keeps the feed's order.
    assert ids(kept[MSRC.name]) == [n.id for n in news[25 - limit:]]


def test_lookups_are_paced_for_the_rate_limit(monkeypatch):
    sleeps = []
    monkeypatch.setattr(cvefilter, "_sleep", sleeps.append)
    news = [new(MSRC, f"CVE-2026-{i}", hours=i) for i in range(3)]
    apply({MSRC.name: Split(new=news)}, FakeNvd(), has_key=False)
    assert sleeps == [6.5, 6.5]  # 5 requests per 30 s without a key


def test_revisions_of_one_cve_are_looked_up_once():
    nvd = FakeNvd({"CVE-2026-30": CveInfo(True, 9.8, "3.1")})
    news = [new(MSRC, "CVE-2026-30", hours=h) for h in (1, 2, 3)]
    kept, report, _ = apply({MSRC.name: Split(new=news)}, nvd)
    assert nvd.asked == ["CVE-2026-30"] and report.lookups == 1
    assert len(kept[MSRC.name].new) == 3


def test_log_report_lines(caplog):
    caplog.set_level(logging.INFO)
    nvd = FakeNvd({"CVE-2026-41": CveInfo(True, 5.0, "3.1")})
    _, report, _ = apply(
        {
            NVD.name: Split(new=[new(NVD, "CVE-2026-40", cvss=9.9), new(NVD, "CVE-2026-1", cvss=4.0)]),
            MSRC.name: Split(new=[new(MSRC, "CVE-2026-41"), new(MSRC, "CVE-2026-42", hours=1)]),
        },
        nvd,
    )
    cvefilter.log_report(report)
    assert 'cve filter "NVD CVE API": 1 kept, 1 below CVSS 9.8 or unscored' in caplog.text
    assert (
        'cve filter "Microsoft MSRC": 0 kept, 1 held back, 1 deferred to the next run'
        in caplog.text
    )
    assert "cve filter: 1 kept, 1 dropped, 1 held back, 1 deferred, 2 NVD lookups" in caplog.text


# --- fetch.lookup_cve ------------------------------------------------------------


def nvd_answer(cve_id, *, score=None, kev=None):
    cve = {"id": cve_id, "metrics": {}}
    if score is not None:
        cve["metrics"]["cvssMetricV31"] = [
            {"type": "Secondary", "cvssData": {"baseScore": score}}
        ]
    if kev:
        cve["cisaExploitAdd"] = kev
    return {"totalResults": 1, "vulnerabilities": [{"cve": cve}]}


def test_lookup_cve_asks_for_one_cve_with_the_api_key():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=nvd_answer("CVE-2026-1", score=9.8, kev="2026-11-01"))

    with fetch_client(handler) as client:
        info = fetch.lookup_cve(client, "CVE-2026-1", "https://nvd.example/cves", {"NVD_API_KEY": "k"})
    assert info == CveInfo(True, 9.8, "3.1", kev=True)
    assert seen[0].url.params["cveId"] == "CVE-2026-1"
    assert seen[0].headers["apiKey"] == "k"


def test_lookup_cve_not_found_and_errors():
    empty = {"totalResults": 0, "vulnerabilities": []}
    with fetch_client(lambda r: httpx.Response(200, json=empty)) as client:
        assert fetch.lookup_cve(client, "CVE-2026-1", env={}) == CveInfo(found=False)
    with fetch_client(lambda r: httpx.Response(404)) as client:
        with pytest.raises(FetchError, match="HTTP 404") as exc:
            fetch.lookup_cve(client, "CVE-2026-1", env={})
        assert "https://" not in str(exc.value)
    with fetch_client(lambda r: httpx.Response(200, content=b"<html>")) as client:
        with pytest.raises(FetchError, match="unexpected NVD response"):
            fetch.lookup_cve(client, "CVE-2026-1", env={})


def test_lookup_cve_error_names_nvd_reason_without_the_key():
    def handler(request):
        return httpx.Response(404, headers={"message": f"Invalid apiKey {request.headers['apiKey']}."})

    with fetch_client(handler) as client:
        with pytest.raises(FetchError) as exc:
            fetch.lookup_cve(client, "CVE-2026-1", env={"NVD_API_KEY": "secret-key-123"})
    assert str(exc.value) == "HTTP 404 Not Found: Invalid apiKey [redacted]."


# --- config ----------------------------------------------------------------------


def entry(**fields):
    base = {"name": "Vendor", "url": "https://vendor.example/rss", "type": "rss", "category": "advisories"}
    lines = "".join(f"    {key}: {value}\n" for key, value in {**base, **fields}.items())
    return "sources:\n  -" + lines[3:]


def test_cve_filter_is_an_optional_boolean_for_rss_sources():
    assert parse_sources(entry(cve_filter="true"))[0].cve_filter is True
    assert parse_sources(entry())[0].cve_filter is False
    with pytest.raises(ConfigError, match="'cve_filter' must be true or false"):
        parse_sources(entry(cve_filter="'yes'"))
    with pytest.raises(ConfigError, match="'cve_filter' applies only to type rss"):
        parse_sources(entry(type="nvd", category="vulns", cve_filter="true"))


def test_msrc_is_held_to_the_cve_bar_in_the_committed_config():
    from intel_feeds.config import load_sources

    repo = Path(__file__).resolve().parent.parent
    by_name = {s.name: s for s in load_sources(repo / "sources.yaml")}
    assert by_name["Microsoft MSRC"].cve_filter is True
    assert [s.name for s in by_name.values() if s.cve_filter] == ["Microsoft MSRC"]


# --- a whole run -----------------------------------------------------------------

# No age limit: the fixture dates pass the default 7 days as time goes on (the
# flood guard has its own tests).
CONFIG = """\
settings:
  max_age_days: 36500
  keep_days: 146000
sources:
  - name: MSRC
    url: https://feeds.example.com/msrc.xml
    type: rss
    category: advisories
    revisions: true
    cve_filter: true
"""


def test_a_run_posts_only_the_msrc_entries_that_meet_the_bar(tmp_path, monkeypatch, caplog):
    lookups = []

    def handler(request):
        if request.url.path == "/msrc.xml":
            return httpx.Response(
                200, content=(FIXTURES / "rss20_msrc.xml").read_bytes(), headers={"ETag": '"m1"'}
            )
        if request.url.host == "api.first.org":  # EPSS for the posts
            assert request.url.params["cve"] == "CVE-2026-78524"
            row = {"cve": "CVE-2026-78524", "epss": "0.12300", "percentile": "0.95700"}
            return httpx.Response(200, json={"status": "OK", "data": [row]})
        cve = request.url.params["cveId"]
        lookups.append(cve)
        score = {"CVE-2026-78524": 9.8, "CVE-2026-71331": 7.0}[cve]
        return httpx.Response(200, json=nvd_answer(cve, score=score))

    monkeypatch.setattr(fetch, "make_client", lambda transport=None: fetch_client(handler))
    discord = FakeDiscord()
    monkeypatch.setattr(webhook, "make_client", lambda transport=None: discord.client())
    os.environ.update(HOOKS)
    config = tmp_path / "sources.yaml"
    config.write_text(CONFIG)
    state = State()
    state.add_sources(["MSRC"], NOW)
    state.sources["MSRC"].backlog_at = "2026-11-01T00:00:00Z"
    state_path = tmp_path / "state.json"
    save_state(state_path, state)
    caplog.set_level(logging.INFO)

    assert main(["--config", str(config), "--state", str(state_path)]) == 0
    assert sorted(lookups) == ["CVE-2026-71331", "CVE-2026-78524"]  # once per CVE
    titles = discord.titles("WEBHOOK_ADVISORIES")
    assert titles and all("CVE-2026-78524" in t for t in titles)
    saved = load_state(state_path)
    posted = [k for k, v in saved.items.items() if v.posted_at]
    held = [k for k, v in saved.items.items() if not v.posted_at]
    assert len(posted) == len(titles)
    assert held and all("CVE-2026-71331" in k for k in held)
    assert saved.sources["MSRC"].etag == '"m1"'  # nothing deferred: finished
    embed = discord.posts[0][1]["embeds"][0]
    assert {"name": "CVSS", "value": "9.8 Critical (v3.1)", "inline": True} in embed["fields"]
    assert {"name": "EPSS", "value": "12.3% (96th percentile)", "inline": True} in embed["fields"]


def test_a_run_with_a_deferred_entry_keeps_the_validators_unsaved(tmp_path, monkeypatch):

    def handler(request):
        if request.url.path == "/msrc.xml":
            return httpx.Response(
                200, content=(FIXTURES / "rss20_msrc.xml").read_bytes(), headers={"ETag": '"m1"'}
            )
        return httpx.Response(503)  # NVD is down

    monkeypatch.setattr(fetch, "make_client", lambda transport=None: fetch_client(handler))
    discord = FakeDiscord()
    monkeypatch.setattr(webhook, "make_client", lambda transport=None: discord.client())
    os.environ.update(HOOKS)
    config = tmp_path / "sources.yaml"
    config.write_text(CONFIG)
    state = State()
    state.add_sources(["MSRC"], NOW)
    state.sources["MSRC"].backlog_at = "2026-11-01T00:00:00Z"
    state_path = tmp_path / "state.json"
    save_state(state_path, state)

    assert main(["--config", str(config), "--state", str(state_path)]) == 0
    assert discord.posts == []
    saved = load_state(state_path)
    assert saved.items == {}
    assert saved.sources["MSRC"].etag is None  # fetched in full and retried next run

