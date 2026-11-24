"""The product watchlist: NVD CVEs of watched products post from a lower score."""

import logging
import os
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from conftest import fetch_client
from test_cvefilter import KEV, MSRC, NOW, NVD, SOURCES, FakeNvd, ids, new
from test_route import HOOKS, FakeDiscord
from test_settings import problems, settings

from intel_feeds import __main__ as cli
from intel_feeds import cvefilter, fetch, webhook
from intel_feeds.__main__ import main
from intel_feeds.config import DEFAULTS, Watchlist
from intel_feeds.dedup import Split
from intel_feeds.embeds import item_embed
from intel_feeds.items import parse
from intel_feeds.state import State, load_state, save_state

WATCH = Watchlist(
    7.0, ("Fortinet", "Exchange Server", "PAN-OS", "Check Point", "Confluence", "WebLogic")
)


def nvd(cve, cvss, description, *, hours=0):
    made = new(NVD, cve, cvss=cvss, hours=hours)
    return replace(made, item=replace(made.item, title=cve, description=description))


def run(news, watchlist=WATCH, *, state=None, sources=SOURCES):
    return cvefilter.apply(
        state or State(), news, sources, NOW, FakeNvd(), has_key=True, watchlist=watchlist
    )


# --- settings ----------------------------------------------------------------


def test_the_watchlist_is_off_by_default():
    assert DEFAULTS.watchlist == Watchlist(7.0, ())


def test_the_watchlist_is_read():
    got = settings("  watchlist:\n    min_cvss: 8\n    products:\n      - Fortinet\n      - ' Check   Point '\n")
    assert got.watchlist == Watchlist(8.0, ("Fortinet", "Check Point"))
    assert isinstance(got.watchlist.min_cvss, float)


def test_watchlist_fields_are_optional():
    assert settings("  watchlist:\n").watchlist == Watchlist()
    assert settings("  watchlist:\n    products: [Zyxel]\n").watchlist == Watchlist(7.0, ("Zyxel",))
    assert settings("  watchlist:\n    min_cvss: 6\n").watchlist == Watchlist(6.0, ())


@pytest.mark.parametrize(
    "text, message",
    [
        ("  watchlist: Fortinet\n", "'watchlist' must be a set of fields like 'min_cvss: 7.0' and 'products:', found text"),
        ("  watchlist:\n    min_cvss: high\n", "watchlist: 'min_cvss' must be a number from 0 to 10, found \"high\""),
        ("  watchlist:\n    min_cvss: 11\n", "watchlist: 'min_cvss' must be a number from 0 to 10, found 11 (a number)"),
        ("  watchlist:\n    min_cvss: true\n", "watchlist: 'min_cvss' must be a number from 0 to 10"),
        ("  watchlist:\n    products: Fortinet\n", "watchlist: 'products' must be a list of product names"),
        ("  watchlist:\n    products: [Fortinet, '']\n", "watchlist: product 2 must be a name, found \"\""),
        ("  watchlist:\n    products: [Fortinet, 42]\n", "watchlist: product 2 must be a name, found 42 (a number)"),
        ("  watchlist:\n    products: [Fortinet, ' -- ']\n", "watchlist: product 2 must be a name"),
        ("  watchlist:\n    products: [Fortinet, FORTINET]\n", "watchlist: product \"FORTINET\" appears more than once"),
        ("  watchlist:\n    product: [Fortinet]\n", "watchlist: unknown field \"product\"; did you mean 'products'?"),
    ],
)
def test_a_bad_watchlist_names_the_field(text, message):
    [problem] = problems(text)
    assert problem.startswith("sources.yaml:")
    assert "settings: " in problem
    assert message in problem


def test_the_real_sources_yaml_ships_the_agreed_list():
    config = cli.load_config(Path(__file__).resolve().parents[1] / "sources.yaml")
    watchlist = config.settings.watchlist
    assert watchlist.min_cvss == 7.0
    assert len(watchlist.products) == 31
    assert {"Fortinet", "PAN-OS", "Check Point", "Adaptive Security Appliance"} <= set(watchlist.products)


# --- matching ------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, found",
    [
        ("A flaw in Fortinet FortiOS 7.2", "Fortinet"),
        ("fortinet fortios", "Fortinet"),
        ("Microsoft Exchange Server 2019", "Exchange Server"),
        ("Microsoft Exchange\nServer 2019", "Exchange Server"),
        ("Palo Alto Networks PAN-OS GlobalProtect", "PAN-OS"),
        ("Check Point Quantum gateways", "Check Point"),
        ("Fortinetwork appliance", None),  # whole words only
        ("ExFortinet", None),
        ("Exchange server-side rendering", "Exchange Server"),  # "-" ends a word
        ("PAN-OSX", None),
        ("the checkpoint file", None),
        ("See the release notes (https://confluence.atlassian.com/bamboo/x)", None),
        ("See [https://example.com/fortinet/advisory]", None),
        ("hosted at confluence.atlassian.com", None),
        ("see www.fortinet.com", None),
        ("affects Confluence. Upgrade now", "Confluence"),
        ("versions of Confluence Data Center.", "Confluence"),
        ("Oracle WebLogic Server (component: Core)", "WebLogic"),
        ("", None),
    ],
)
def test_matching_is_case_insensitive_whole_words(text, found):
    assert cvefilter.Matcher(WATCH.products).find(text) == found


def test_the_first_product_in_list_order_wins():
    matcher = cvefilter.Matcher(("PAN-OS", "Fortinet"))
    assert matcher.find("Fortinet and PAN-OS") == "PAN-OS"
    assert not cvefilter.Matcher(())


# --- the filter ----------------------------------------------------------------


def test_watched_cves_post_from_min_cvss_and_others_keep_the_bar():
    news = [
        nvd("CVE-2026-1", 9.8, "Something unwatched"),
        nvd("CVE-2026-2", 7.0, "A Fortinet FortiGate flaw"),
        nvd("CVE-2026-3", 6.9, "A Fortinet FortiGate flaw"),
        nvd("CVE-2026-4", 9.7, "Something unwatched"),
        nvd("CVE-2026-5", None, "A Fortinet flaw, not scored yet"),
        nvd("CVE-2026-6", 8.1, "Exchange Server spoofing"),
    ]
    kept, report = run({NVD.name: Split(new=news)})
    assert ids(kept[NVD.name]) == [news[0].id, news[1].id, news[5].id]
    watched = [n.item.watched for n in kept[NVD.name].new]
    assert watched == [None, "Fortinet", "Exchange Server"]
    counts = report.counts[NVD.name]
    assert (counts.kept, counts.watched, counts.below) == (3, 2, 3)
    assert report.by_product == {"Fortinet": 1, "Exchange Server": 1}


def test_a_cve_at_the_bar_is_not_marked_as_a_watchlist_post():
    kept, report = run({NVD.name: Split(new=[nvd("CVE-2026-1", 9.8, "Fortinet")])})
    assert kept[NVD.name].new[0].item.watched is None
    assert report.by_product == {}


def test_matching_reads_the_whole_description_not_the_excerpt():
    long = "x " * 200 + "affects Fortinet FortiOS"  # past the 300-character excerpt
    kept, _ = run({NVD.name: Split(new=[nvd("CVE-2026-1", 7.5, long)])})
    assert kept[NVD.name].new[0].item.watched == "Fortinet"


def test_a_watched_cve_already_in_kev_still_does_not_post_from_nvd():
    state = State()
    state.mark_seen("kev:CVE-2026-1", KEV.name, NOW)
    kept, report = run({NVD.name: Split(new=[nvd("CVE-2026-1", 7.5, "Fortinet")])}, state=state)
    assert kept[NVD.name].new == []
    assert report.counts[NVD.name].in_kev == 1


def test_the_watchlist_does_not_apply_to_msrc():
    lookup = FakeNvd({"CVE-2026-9": fetch.CveInfo(True, 8.0, "3.1")})
    item = new(MSRC, "CVE-2026-9", title="CVE-2026-9 Microsoft Exchange Server spoofing")
    state = State()
    kept, _ = cvefilter.apply(
        state, {MSRC.name: Split(new=[item])}, SOURCES, NOW, lookup, has_key=True, watchlist=WATCH
    )
    assert kept[MSRC.name].new == []  # held at 9.8


def test_an_empty_watchlist_changes_nothing():
    kept, _ = run({NVD.name: Split(new=[nvd("CVE-2026-1", 8.0, "Fortinet")])}, Watchlist())
    assert kept[NVD.name].new == []


def test_the_log_counts_watchlist_posts_per_product(caplog):
    caplog.set_level(logging.INFO)
    news = [
        nvd("CVE-2026-1", 7.5, "Fortinet"),
        nvd("CVE-2026-2", 7.5, "Fortinet again"),
        nvd("CVE-2026-3", 8.8, "PAN-OS"),
        nvd("CVE-2026-4", 5.0, "nothing"),
    ]
    _, report = run({NVD.name: Split(new=news)})
    cvefilter.log_report(report)
    assert (
        'cve filter "NVD CVE API": 3 kept (3 from the watchlist), 1 below CVSS 9.8 or unscored'
        in caplog.text
    )
    assert "cve filter: watchlist let through Fortinet 2, PAN-OS 1 (CVSS 7 to 9.8)" in caplog.text


def test_no_watchlist_line_when_nothing_was_let_through(caplog):
    caplog.set_level(logging.INFO)
    _, report = run({NVD.name: Split(new=[nvd("CVE-2026-1", 9.9, "Fortinet")])})
    cvefilter.log_report(report)
    assert "watchlist" not in caplog.text


# --- parsing and the embed -------------------------------------------------------


def test_the_nvd_parser_keeps_the_whole_description():
    body = (
        b'{"vulnerabilities": [{"cve": {"id": "CVE-2026-10001", "published": "2026-11-18T10:00:00",'
        b' "descriptions": [{"lang": "en", "value": "' + b"word " * 100 + b'Fortinet"}]}}]}'
    )
    [item] = parse(NVD, body).items
    assert item.description.endswith("Fortinet")
    assert len(item.excerpt) <= 300 and "Fortinet" not in item.excerpt


def test_a_watchlist_post_shows_the_product():
    kept, _ = run({NVD.name: Split(new=[nvd("CVE-2026-1", 7.5, "Fortinet FortiOS")])})
    embed = item_embed(kept[NVD.name].new[0].item)
    assert {"name": "Watchlist", "value": "Fortinet", "inline": True} in embed["fields"]
    assert {"name": "CVSS", "value": "7.5 High (v3.1)", "inline": True} in embed["fields"]


def test_a_post_not_from_the_watchlist_has_no_watchlist_field():
    embed = item_embed(nvd("CVE-2026-1", 9.8, "Fortinet").item)
    assert all(f["name"] != "Watchlist" for f in embed["fields"])


# --- a whole run -----------------------------------------------------------------

CONFIG = """\
settings:
  max_age_days: 36500
  keep_days: 146000
  watchlist:
    min_cvss: 7.0
    products: [Fortinet]
sources:
  - name: NVD
    url: https://nvd.example.com/rest/json/cves/2.0
    type: nvd
    category: vulns
"""


def cve(cve_id, score, description):
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-11-18T10:00:00.000",
            "vulnStatus": "Received",
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [{"type": "Secondary", "cvssData": {"baseScore": score}}]
            },
        }
    }


def test_a_run_posts_watched_cves_with_the_field(tmp_path, monkeypatch, caplog):
    vulns = [
        cve("CVE-2026-90001", 9.8, "An unwatched product"),
        cve("CVE-2026-90002", 7.5, "A heap overflow in Fortinet FortiOS"),
        cve("CVE-2026-90003", 6.5, "A Fortinet FortiOS flaw"),
        cve("CVE-2026-90004", 8.0, "An unwatched product"),
    ]

    def handler(request):
        if request.url.host == "nvd.example.com":
            return httpx.Response(200, json={"totalResults": len(vulns), "vulnerabilities": vulns})
        return httpx.Response(503)  # EPSS: posts go out without it

    monkeypatch.setattr(fetch, "make_client", lambda transport=None: fetch_client(handler))
    discord = FakeDiscord()
    monkeypatch.setattr(webhook, "make_client", lambda transport=None: discord.client())
    os.environ.update(HOOKS)
    config = tmp_path / "sources.yaml"
    config.write_text(CONFIG)
    state = State()
    state.add_sources(["NVD"], NOW)
    state.sources["NVD"].backlog_at = "2026-11-01T00:00:00Z"
    state_path = tmp_path / "state.json"
    save_state(state_path, state)
    caplog.set_level(logging.INFO)

    assert main(["--config", str(config), "--state", str(state_path)]) == 0
    assert sorted(discord.titles("WEBHOOK_VULNS")) == ["CVE-2026-90001", "CVE-2026-90002"]
    by_title = {p[1]["embeds"][0]["title"]: p[1]["embeds"][0] for p in discord.posts}
    assert {"name": "Watchlist", "value": "Fortinet", "inline": True} in by_title["CVE-2026-90002"]["fields"]
    assert all(f["name"] != "Watchlist" for f in by_title["CVE-2026-90001"]["fields"])
    assert "cve filter: watchlist let through Fortinet 1 (CVSS 7 to 9.8)" in caplog.text
    saved = load_state(state_path)
    assert sorted(saved.items) == ["nvd:CVE-2026-90001", "nvd:CVE-2026-90002"]
    raw = state_path.read_text()
    assert "heap overflow" not in raw  # descriptions are never stored
