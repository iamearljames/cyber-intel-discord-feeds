import json
import logging
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from conftest import fetch_client

from intel_feeds import cvefilter, enrich, fetch, webhook
from intel_feeds.__main__ import main
from intel_feeds.config import Source
from intel_feeds.dedup import NewItem
from intel_feeds.embeds import epss_badge, item_embed, ordinal
from intel_feeds.fetch import CveInfo, EpssScore, FetchError
from intel_feeds.items import Item
from intel_feeds.state import State, load_state, save_state

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)

KEV = Source("CISA KEV", "https://cisa.example/kev.json", "kev", "vulns")
NVD = Source("NVD CVE API", "https://nvd.example/cves/2.0", "nvd", "vulns")
MSRC = Source("MSRC", "https://msrc.example/rss", "rss", "advisories", cve_filter=True)
CISCO = Source("Cisco PSIRT", "https://cisco.example/rss.xml", "rss", "advisories")
SOURCES = {s.name: s for s in (KEV, NVD, MSRC, CISCO)}


def new(cve, source=KEV, *, cvss=None, cves=None):
    item = Item(
        title=f"{cve} something",
        url=f"https://example.com/{cve}",
        source=source.name,
        category=source.category,
        cve_ids=tuple([cve] if cves is None else cves),
        cvss=cvss,
        cvss_version="3.1" if cvss is not None else None,
    )
    return NewItem(item, f"{source.type}:{cve}", item.url)


class Lookups:
    """Fake EPSS and NVD lookups that record what they were asked."""

    def __init__(self, epss=None, cvss=None, epss_error=None, cvss_error=()):
        self.epss_scores = epss or {}
        self.cvss_scores = cvss or {}
        self.epss_error = epss_error
        self.cvss_error = set(cvss_error)
        self.epss_calls = []
        self.cvss_calls = []

    def epss(self, cves):
        self.epss_calls.append(list(cves))
        if self.epss_error:
            raise FetchError(self.epss_error)
        return {c: EpssScore(*self.epss_scores[c]) for c in cves if c in self.epss_scores}

    def cvss(self, cve):
        self.cvss_calls.append(cve)
        if cve in self.cvss_error:
            raise FetchError("HTTP 503 Service Unavailable")
        score = self.cvss_scores.get(cve)
        return CveInfo(True, score, "3.1" if score is not None else None)


def run_apply(batches, fake, *, lookups=20, spacing=0.7, spaced=False):
    return enrich.apply(
        batches, SOURCES, epss=fake.epss, cvss=fake.cvss,
        lookups=lookups, spacing=spacing, spaced=spaced,
    )


# --- own_cve -------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [(KEV, "CVE-2026-1"), (NVD, "CVE-2026-1"), (MSRC, "CVE-2026-1"), (CISCO, None)],
)
def test_only_cve_sources_make_cve_posts(source, expected):
    assert enrich.own_cve(new("CVE-2026-1", source, cves=["CVE-2026-1", "CVE-2026-2"]), source) == expected


def test_an_item_without_a_cve_is_not_a_cve_post():
    assert enrich.own_cve(new("x", KEV, cves=[]), KEV) is None


# --- apply ---------------------------------------------------------------


def test_one_epss_request_covers_every_cve_post_in_every_channel():
    vulns = [new("CVE-2026-1", NVD, cvss=9.8), new("CVE-2026-2", KEV)]
    advisories = [new("CVE-2026-3", MSRC, cvss=9.8), new("CVE-2026-4", CISCO)]
    fake = Lookups(epss={"CVE-2026-1": (0.5, 0.99), "CVE-2026-3": (0.01, 0.4)})
    report = run_apply([vulns, advisories], fake)
    assert fake.epss_calls == [["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"]]
    assert (vulns[0].item.epss, vulns[0].item.epss_percentile) == (0.5, 0.99)
    assert vulns[1].item.epss is None  # FIRST has not scored it yet
    assert advisories[0].item.epss == 0.01
    assert advisories[1].item.epss is None  # not a CVE post
    assert (report.cves, report.epss) == (3, 2)


def test_a_kev_post_gets_its_cvss_score_from_nvd():
    vulns = [new("CVE-2026-2", KEV), new("CVE-2026-1", NVD, cvss=9.8)]
    fake = Lookups(cvss={"CVE-2026-2": 7.5})
    report = run_apply([vulns], fake)
    assert fake.cvss_calls == ["CVE-2026-2"]  # NVD items have their score
    assert (vulns[0].item.cvss, vulns[0].item.cvss_version) == (7.5, "3.1")
    assert (report.lookups, report.cvss_added) == (1, 1)


def test_a_cve_nvd_has_not_scored_posts_without_cvss():
    vulns = [new("CVE-2026-2", KEV)]
    report = run_apply([vulns], Lookups())
    assert vulns[0].item.cvss is None and report.cvss_added == 0


def test_lookups_stop_at_what_the_filter_left_and_are_counted():
    vulns = [new(f"CVE-2026-{n}", KEV) for n in range(1, 5)]
    fake = Lookups(cvss={f"CVE-2026-{n}": 8.0 for n in range(1, 5)})
    report = run_apply([vulns], fake, lookups=2)
    assert fake.cvss_calls == ["CVE-2026-1", "CVE-2026-2"]
    assert [n.item.cvss for n in vulns] == [8.0, 8.0, None, None]
    assert report.no_budget == 2


def test_no_lookups_left_means_no_nvd_requests():
    vulns = [new("CVE-2026-1", KEV)]
    fake = Lookups(epss={"CVE-2026-1": (0.2, 0.9)})
    run_apply([vulns], fake, lookups=0)
    assert fake.cvss_calls == [] and vulns[0].item.epss == 0.2


def test_lookups_are_paced_after_the_filters_lookups(monkeypatch):
    waits = []
    monkeypatch.setattr(enrich, "_sleep", waits.append)
    vulns = [new("CVE-2026-1", KEV), new("CVE-2026-2", KEV)]
    run_apply([vulns], Lookups(), spacing=6.5, spaced=False)
    assert waits == [6.5]  # between the two, not before the first
    waits.clear()
    run_apply([[new("CVE-2026-3", KEV)]], Lookups(), spacing=0.7, spaced=True)
    assert waits == [0.7]  # the filter just made a lookup


def test_a_failed_epss_request_still_posts_and_still_looks_up_cvss(caplog):
    vulns = [new("CVE-2026-2", KEV)]
    fake = Lookups(cvss={"CVE-2026-2": 9.1}, epss_error="HTTP 503 Service Unavailable")
    report = run_apply([vulns], fake)
    assert report.epss_failed and vulns[0].item.epss is None
    assert vulns[0].item.cvss == 9.1
    assert "enrich: EPSS lookup failed, posting without EPSS scores: HTTP 503" in caplog.text


def test_a_failed_nvd_lookup_is_logged_and_the_item_kept(caplog):
    vulns = [new("CVE-2026-2", KEV)]
    report = run_apply([vulns], Lookups(cvss_error={"CVE-2026-2"}))
    assert len(vulns) == 1 and vulns[0].item.cvss is None
    assert report.lookup_failures == 1
    assert "enrich: NVD lookup of CVE-2026-2 failed: HTTP 503" in caplog.text


def test_nothing_to_enrich_makes_no_requests():
    fake = Lookups()
    report = run_apply([[new("CVE-2026-4", CISCO)], []], fake)
    assert fake.epss_calls == [] and fake.cvss_calls == [] and report.cves == 0


def test_the_report_logs_one_line(caplog):
    caplog.set_level(logging.INFO)
    vulns = [new("CVE-2026-1", KEV), new("CVE-2026-2", KEV)]
    fake = Lookups(epss={"CVE-2026-1": (0.2, 0.9)}, cvss={"CVE-2026-1": 9.8})
    enrich.log_report(run_apply([vulns], fake, lookups=1))
    assert (
        "enrich: EPSS for 1 of 2 CVE posts, CVSS added to 1 from 1 NVD lookups, "
        "1 without a CVSS score over the lookup cap"
    ) in caplog.text


# --- lookup_epss ---------------------------------------------------------


def epss_answer(rows):
    return {"status": "OK", "total": len(rows), "data": rows}


def test_lookup_epss_asks_once_per_hundred_cves_and_parses_the_strings():
    seen = []

    def handler(request):
        cves = request.url.params["cve"].split(",")
        seen.append(cves)
        assert request.url.params["limit"] == "100"
        rows = [{"cve": c, "epss": "0.002220000", "percentile": "0.600140000"} for c in cves]
        return httpx.Response(200, json=epss_answer(rows))

    cves = [f"CVE-2026-{n:04d}" for n in range(150)] + ["CVE-2026-0001"]
    scores = fetch.lookup_epss(fetch_client(handler), cves)
    assert [len(batch) for batch in seen] == [100, 50]  # duplicates asked once
    assert len(scores) == 150
    assert scores["CVE-2026-0001"] == EpssScore(0.00222, 0.60014)


def test_lookup_epss_leaves_out_unscored_and_out_of_range_rows():
    def handler(request):
        return httpx.Response(200, json=epss_answer([
            {"cve": "CVE-2026-1", "epss": "1.5", "percentile": "0.5"},
            {"cve": "cve-2026-2", "epss": "0.3", "percentile": "0.9"},
        ]))

    scores = fetch.lookup_epss(fetch_client(handler), ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"])
    assert scores == {"CVE-2026-2": EpssScore(0.3, 0.9)}


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(503), "HTTP 503"),
        (httpx.Response(200, content=b"<html>"), "unexpected EPSS response: JSONDecodeError"),
        (httpx.Response(200, json={"status": "OK"}), "unexpected EPSS response: KeyError"),
        (
            httpx.Response(200, json=epss_answer([{"cve": "CVE-2026-1", "epss": "x", "percentile": "1"}])),
            "unexpected EPSS response: ValueError",
        ),
    ],
)
def test_lookup_epss_raises_fetch_error_on_a_bad_answer(response, message):
    with pytest.raises(FetchError, match=message):
        fetch.lookup_epss(fetch_client(lambda request: response), ["CVE-2026-1"])


def test_lookup_epss_with_no_cves_makes_no_request():
    def handler(request):
        pytest.fail("no request expected")

    assert fetch.lookup_epss(fetch_client(handler), []) == {}


# --- the embed -----------------------------------------------------------


@pytest.mark.parametrize(
    ("epss", "percentile", "shown"),
    [
        (0.123, 0.957, "12.3% (96th percentile)"),
        (0.0054, 0.46, "0.54% (46th percentile)"),
        (0.00004, 0.012, "<0.01% (1st percentile)"),
        (0.99999, 1.0, "99.9% (100th percentile)"),
        (1.0, 1.0, "100.0% (100th percentile)"),
    ],
)
def test_epss_badge(epss, percentile, shown):
    assert epss_badge(epss, percentile) == shown


def test_ordinal_suffixes():
    assert [ordinal(n) for n in (1, 2, 3, 4, 11, 12, 13, 21, 22, 23, 100)] == [
        "1st", "2nd", "3rd", "4th", "11th", "12th", "13th", "21st", "22nd", "23rd", "100th",
    ]


def test_the_epss_field_follows_cvss():
    item = new("CVE-2026-12345", NVD, cvss=9.8).item
    embed = item_embed(replace(item, epss=0.5, epss_percentile=0.99))
    assert [f["name"] for f in embed["fields"]] == ["CVSS", "EPSS"]
    assert embed["fields"][1] == {"name": "EPSS", "value": "50.0% (99th percentile)", "inline": True}


def test_no_epss_field_without_a_score():
    embed = item_embed(new("CVE-2026-12345", NVD, cvss=9.8).item)
    assert [f["name"] for f in embed["fields"]] == ["CVSS"]


# --- the run -------------------------------------------------------------

HOOK = "https://discord.invalid/api/webhooks/2/vulns-secret-token"
CONFIG = (
    "settings:\n  max_age_days: 36500\n  keep_days: 146000\n"
    "sources:\n"
    "  - name: CISA KEV\n    url: https://cisa.example/kev.json\n    type: kev\n"
    "    category: vulns\n"
)


@pytest.mark.parametrize("has_key", [True, False])
def test_a_run_posts_kev_entries_with_cvss_and_epss(tmp_path, monkeypatch, has_key):
    catalog = json.loads((FIXTURES / "kev.json").read_text())
    cves = [v["cveID"] for v in catalog["vulnerabilities"]]
    asked = {"epss": [], "nvd": []}

    def handler(request):
        if request.url.host == "cisa.example":
            return httpx.Response(200, json=catalog)
        if request.url.host == "api.first.org":
            batch = request.url.params["cve"].split(",")
            asked["epss"].append(batch)
            rows = [{"cve": c, "epss": "0.25", "percentile": "0.97"} for c in batch]
            return httpx.Response(200, json=epss_answer(rows))
        cve = request.url.params["cveId"]
        asked["nvd"].append(cve)
        metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8}}]}
        return httpx.Response(200, json={"vulnerabilities": [{"cve": {"id": cve, "metrics": metrics}}]})

    posts = []

    def discord(request):
        posts.append(json.loads(request.content)["embeds"][0])
        return httpx.Response(200, json={})

    monkeypatch.setattr(fetch, "make_client", lambda transport=None: fetch_client(handler))
    monkeypatch.setattr(
        webhook, "make_client",
        lambda transport=None: httpx.Client(transport=httpx.MockTransport(discord)),
    )
    os.environ["WEBHOOK_VULNS"] = HOOK
    if has_key:
        os.environ[fetch.NVD_KEY_ENV] = "test-key"
    config = tmp_path / "sources.yaml"
    config.write_text(CONFIG)
    state = State()
    state.add_sources(["CISA KEV"], NOW - timedelta(days=30))
    state.sources["CISA KEV"].backlog_at = "2026-10-01T00:00:00Z"
    path = tmp_path / "state.json"
    save_state(path, state)

    assert main(["--config", str(config), "--state", str(path)]) == 0
    assert posts and len(asked["epss"]) == 1
    expected_lookups = min(len(posts), 20 if has_key else cvefilter.NO_KEY_LOOKUPS)
    assert len(asked["nvd"]) == expected_lookups
    for embed in posts:
        values = {f["name"]: f["value"] for f in embed["fields"]}
        assert values["EPSS"] == "25.0% (97th percentile)"
    with_cvss = [e for e in posts if any(f["name"] == "CVSS" for f in e["fields"])]
    assert len(with_cvss) == expected_lookups
    assert set(asked["epss"][0]) <= set(cves)
    assert all(v.posted_at for v in load_state(path).items.values())
