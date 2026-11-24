import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from conftest import fetch_client

from intel_feeds import fetch, items
from intel_feeds.__main__ import main
from intel_feeds.config import Source
from intel_feeds.items import Item, ParseError, cvss_score, find_cves, parse, strip_html, truncate

FIXTURES = Path(__file__).resolve().parent / "fixtures"

RECORD = Source("The Record", "https://therecord.media/feed", "rss", "news")
CISCO = Source("Cisco PSIRT", "https://cisco.example/rss.xml", "rss", "advisories")
KEV = Source("CISA KEV", "https://cisa.example/kev.json", "kev", "vulns")
NVD = Source("NVD CVE API", "https://nvd.example/cves/2.0", "nvd", "vulns")


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def rss(*entries: str) -> bytes:
    return (
        '<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>'
        + "".join(f"<item>{e}</item>" for e in entries)
        + "</channel></rss>"
    ).encode()


# --- saved fixtures (offline) -------------------------------------------


def test_rss_fixture_parses_into_items():
    parsed = parse(RECORD, fixture("rss20_the_record.xml"))
    assert len(parsed.items) == 5
    assert parsed.skipped == 0
    first = parsed.items[0]
    assert first == Item(
        title="Website management platform Optimizely confirms hackers put malicious code into customer sites",
        url="https://therecord.media/optimizely-malicious-code-customer-sites",
        source="The Record",
        category="news",
        published=datetime(2026, 11, 17, 21, 20, tzinfo=UTC),
        excerpt=(
            "Researchers said they found malicious JavaScript code on 178 different widely "
            "visited websites run through the Optimizely Web experimentation platform. "
            "The company confirmed the breach."
        ),
        tags=("Malware", "News", "Cybercrime"),
        guid="https://therecord.media/optimizely-malicious-code-customer-sites",
    )
    assert all(i.published and i.title and i.url for i in parsed.items)


def test_cisco_fixture_dates_without_a_timezone_are_read_as_utc():
    parsed = parse(CISCO, fixture("rss20_cisco_psirt.xml"))
    assert [i.published for i in parsed.items] == [
        datetime(2026, 11, 17, 23, 53, 12, tzinfo=UTC),
        datetime(2026, 11, 16, 22, 25, 32, tzinfo=UTC),
    ]


def test_cisco_fixture_escaped_html_becomes_plain_text_with_cves():
    first = parse(CISCO, fixture("rss20_cisco_psirt.xml")).items[0]
    assert "<" not in first.excerpt and "&nbsp;" not in first.excerpt
    assert first.excerpt.startswith("On October 21, 2026, Node.js announced")
    assert first.excerpt.endswith("…") and len(first.excerpt) <= 300
    assert first.cve_ids == ("CVE-2026-111497", "CVE-2026-105482", "CVE-2026-105483", "CVE-2026-106069")


def test_kev_fixture_parses_into_items():
    parsed = parse(KEV, fixture("kev.json"))
    assert len(parsed.items) == 5
    first = parsed.items[0]
    assert first.title == "CVE-2026-115731: Perforce Puppet Enterprise Deserialization of Untrusted Data Vulnerability"
    assert first.url == "https://nvd.nist.gov/vuln/detail/CVE-2026-115731"
    assert first.published == datetime(2026, 11, 17, tzinfo=UTC)
    assert first.cve_ids == ("CVE-2026-115731",)
    assert first.guid == "kev:CVE-2026-115731"
    assert first.kev is True
    assert first.category == "vulns"
    assert first.tags == ("Perforce", "Puppet Enterprise")
    # vendor and product are the same name: one tag
    assert parsed.items[1].tags == ("UnrealIRCd",)


def test_nvd_fixture_parses_into_items_with_scores():
    parsed = parse(NVD, fixture("nvd.json"))
    assert [i.title for i in parsed.items] == [
        "CVE-2026-129008", "CVE-2026-129012", "CVE-2026-129031", "CVE-2026-107493", "CVE-2026-109138",
    ]
    assert [(i.cvss, i.cvss_version) for i in parsed.items] == [
        (6.5, "3.1"), (6.5, "3.1"), (6.5, "3.1"), (7.7, "3.1"), (8.3, "4.0"),
    ]
    first = parsed.items[0]
    assert first.published == datetime(2026, 11, 17, 8, 16, 59, 700000, tzinfo=UTC)
    assert first.url == "https://nvd.nist.gov/vuln/detail/CVE-2026-129008"
    assert first.guid == "nvd:CVE-2026-129008"
    assert first.excerpt.startswith("Improper Neutralization of Input")
    assert first.kev is False


# --- RSS and Atom details -----------------------------------------------


def test_atom_feeds_parse_too():
    body = b"""<?xml version="1.0"?>
    <feed xmlns="http://www.w3.org/2005/Atom"><title>A</title>
      <entry><title>Atom post</title><link href="https://a.example/1"/><id>tag:a,1</id>
        <updated>2026-11-18T09:00:00+02:00</updated><content type="html">&lt;p&gt;Body CVE-2026-1234&lt;/p&gt;</content>
        <category term="Research"/></entry>
    </feed>"""
    [item] = parse(RECORD, body).items
    assert item.title == "Atom post"
    assert item.url == "https://a.example/1"
    assert item.guid == "tag:a,1"
    assert item.published == datetime(2026, 11, 18, 7, 0, tzinfo=UTC)
    assert item.excerpt == "Body CVE-2026-1234"
    assert item.cve_ids == ("CVE-2026-1234",)
    assert item.tags == ("Research",)


def test_missing_date_and_guid_are_none():
    [item] = parse(RECORD, rss("<title>No date</title><link>https://a.example/x</link>")).items
    assert item.published is None
    assert item.guid is None


def test_updated_date_is_used_when_there_is_no_published_date():
    body = b"""<feed xmlns="http://www.w3.org/2005/Atom"><title>A</title>
      <entry><title>t</title><link href="https://a.example/1"/><updated>2026-11-18T09:00:00Z</updated></entry></feed>"""
    assert parse(RECORD, body).items[0].published == datetime(2026, 11, 18, 9, 0, tzinfo=UTC)


def test_entries_without_title_and_link_are_skipped_and_counted():
    parsed = parse(
        RECORD,
        rss(
            "<description>orphan</description>",
            "<title>Title only</title>",
            "<link>https://a.example/link-only</link>",
        ),
    )
    assert parsed.skipped == 1
    assert [i.title for i in parsed.items] == ["Title only", "https://a.example/link-only"]


def test_html_in_titles_is_stripped():
    [item] = parse(RECORD, rss("<title>Patch &lt;b&gt;now&lt;/b&gt; &amp;amp; later</title><link>https://a.example/</link>")).items
    assert item.title == "Patch now & later"


def test_wordpress_footer_is_removed():
    summary = (
        "&lt;p&gt;Over 300 patches.&lt;/p&gt;&lt;p&gt;The post &lt;a href='https://sw.example/p'&gt;Oracle Patches&lt;/a&gt;"
        " appeared first on &lt;a href='https://sw.example'&gt;SecurityWeek&lt;/a&gt;.&lt;/p&gt;"
    )
    [item] = parse(RECORD, rss(f"<title>t</title><link>https://a.example/</link><description>{summary}</description>")).items
    assert item.excerpt == "Over 300 patches."


def test_duplicate_tags_are_dropped_ignoring_case():
    [item] = parse(
        RECORD,
        rss("<title>t</title><link>https://a.example/</link><category>News</category><category>news</category><category> </category>"),
    ).items
    assert item.tags == ("News",)


@pytest.mark.parametrize(
    "body",
    [b"<html><body>Not a feed</body></html>", b"", b'{"json": true}'],
)
def test_a_body_that_is_not_a_feed_raises(body):
    with pytest.raises(ParseError, match="not an RSS or Atom feed"):
        parse(RECORD, body)


# --- KEV and NVD details ------------------------------------------------


def kev(*vulns) -> bytes:
    return json.dumps({"vulnerabilities": list(vulns)}).encode()


def test_kev_ransomware_use_becomes_a_tag_and_bad_entries_are_skipped():
    parsed = parse(
        KEV,
        kev(
            {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Box",
             "vulnerabilityName": "Acme Box RCE", "dateAdded": "2026-11-18",
             "shortDescription": "x", "knownRansomwareCampaignUse": "Known"},
            {"cveID": "not-a-cve"},
            "junk",
            {"cveID": "cve-2026-0002", "dateAdded": "bad date"},
        ),
    )
    assert parsed.skipped == 2
    first, second = parsed.items
    assert first.tags == ("Acme", "Box", "ransomware")
    assert second.title == "CVE-2026-0002"  # upper-cased, no name
    assert second.published is None


@pytest.mark.parametrize(
    "source, body, message",
    [
        (KEV, b"nope", "KEV response is not JSON"),
        (KEV, b"[]", 'KEV response has no "vulnerabilities" list'),
        (NVD, b'{"vulnerabilities": {}}', 'NVD response has no "vulnerabilities" list'),
    ],
)
def test_bad_json_bodies_raise(source, body, message):
    with pytest.raises(ParseError, match=message):
        parse(source, body)


def nvd_cve(cve_id="CVE-2026-0001", **fields) -> dict:
    cve = {
        "id": cve_id,
        "published": "2026-11-18T08:00:00.000",
        "vulnStatus": "Received",
        "descriptions": [{"lang": "es", "value": "hola"}, {"lang": "en", "value": "Overflow, see CVE-2025-9999."}],
        "metrics": {},
    }
    cve.update(fields)
    return {"cve": cve}


def test_nvd_rejected_and_broken_cves_are_skipped():
    body = json.dumps({"vulnerabilities": [
        nvd_cve(), nvd_cve("CVE-2026-0002", vulnStatus="Rejected"), {"cve": {"id": "x"}}, 7,
    ]}).encode()
    parsed = parse(NVD, body)
    assert [i.title for i in parsed.items] == ["CVE-2026-0001"]
    assert parsed.skipped == 3
    item = parsed.items[0]
    assert item.excerpt == "Overflow, see CVE-2025-9999."
    assert item.cve_ids == ("CVE-2026-0001", "CVE-2025-9999")
    assert item.cvss is None and item.cvss_version is None


def metric(score, kind="Secondary"):
    return {"source": "x", "type": kind, "cvssData": {"baseScore": score}}


@pytest.mark.parametrize(
    "metrics, expected",
    [
        ({}, (None, None)),
        ({"cvssMetricV2": [metric(10.0)]}, (10.0, "2.0")),
        ({"cvssMetricV31": [metric(7.5)], "cvssMetricV2": [metric(10.0)]}, (7.5, "3.1")),
        ({"cvssMetricV40": [metric(9.3)], "cvssMetricV31": [metric(9.8)]}, (9.3, "4.0")),
        ({"cvssMetricV31": [metric(9.8), metric(7.5, "Primary")]}, (7.5, "3.1")),
        ({"cvssMetricV30": [metric(5.0)]}, (5.0, "3.0")),
        ({"cvssMetricV40": [{"type": "Primary"}], "cvssMetricV31": [metric(8.1)]}, (8.1, "3.1")),
        ({"cvssMetricV31": [metric(True), metric("9")]}, (None, None)),
        ({"cvssMetricV31": [metric(9)]}, (9.0, "3.1")),
    ],
)
def test_cvss_score_takes_the_newest_version_and_nvds_own_score_first(metrics, expected):
    assert cvss_score(metrics) == expected


def test_nvd_time_with_an_offset_is_converted():
    body = json.dumps({"vulnerabilities": [nvd_cve(published="2026-11-18T10:00:00+02:00")]}).encode()
    assert parse(NVD, body).items[0].published == datetime(2026, 11, 18, 8, 0, tzinfo=UTC)


# --- text helpers -------------------------------------------------------


@pytest.mark.parametrize(
    "html, text",
    [
        ("", ""),
        ("plain", "plain"),
        ("<p>One</p><p>Two</p>", "One Two"),
        ("a<br>b", "a b"),
        ("<ul><li>x</li><li>y</li></ul>", "x y"),
        ("<b>bold</b>er", "bolder"),
        ("Tom &amp; Jerry&nbsp;&#8217;s", "Tom & Jerry ’s"),
        ("<script>alert(1)</script>shown<style>p{}</style>", "shown"),
        ("  lots \n\t of   space ", "lots of space"),
        ("unclosed <b", "unclosed"),
    ],
)
def test_strip_html(html, text):
    assert strip_html(html) == text


def test_truncate_keeps_short_text_and_cuts_long_text_at_a_word():
    assert truncate("short", 10) == "short"
    assert truncate("exactly10!", 10) == "exactly10!"
    assert truncate("one two three four five", 16) == "one two three…"
    assert truncate("x" * 50, 10) == "x" * 9 + "…"  # no space to cut at
    assert truncate("ends with a comma, then more", 19) == "ends with a comma…"


def test_find_cves_normalizes_and_keeps_first_appearance_order():
    assert find_cves("cve-2026-12345 and CVE-2025-0001", "again CVE-2026-12345, CVE-2026-123") == (
        "CVE-2026-12345", "CVE-2025-0001",
    )
    assert find_cves("XCVE-2026-1234 CVE-2026-1234X") == ()


# --- the run ------------------------------------------------------------


def test_a_run_parses_each_fetched_source_and_skips_one_that_cannot_be_parsed(
    tmp_path, monkeypatch, caplog
):
    config = tmp_path / "sources.yaml"
    config.write_text(
        "sources:\n"
        "  - name: Good\n    url: https://feeds.example.com/good.xml\n    type: rss\n    category: news\n"
        "  - name: Broken\n    url: https://feeds.example.com/broken.xml\n    type: rss\n    category: news\n"
        "  - name: KEV\n    url: https://feeds.example.com/kev.json\n    type: kev\n    category: vulns\n"
    )
    bodies = {
        "/good.xml": fixture("rss20_the_record.xml"),
        "/broken.xml": b"<html>maintenance</html>",
        "/kev.json": fixture("kev.json"),
    }
    monkeypatch.setattr(
        fetch, "make_client",
        lambda transport=None: fetch_client(lambda r: httpx.Response(200, content=bodies[r.url.path])),
    )
    caplog.set_level(logging.INFO)
    assert main(["--config", str(config)]) == 0
    assert 'parse "Good": 5 items' in caplog.text
    assert 'parse "Broken": failed, skipped this run: not an RSS or Atom feed' in caplog.text
    assert 'parse "KEV": 5 items' in caplog.text
    assert "parse: 10 items from 2 sources, 1 sources failed" in caplog.text


def test_an_unexpected_parser_error_skips_only_that_source(tmp_path, monkeypatch, caplog):
    config = tmp_path / "sources.yaml"
    config.write_text(
        "sources:\n  - name: Good\n    url: https://feeds.example.com/good.xml\n    type: rss\n    category: news\n"
    )
    monkeypatch.setattr(
        fetch, "make_client", lambda transport=None: fetch_client(lambda r: httpx.Response(200, content=b"x"))
    )
    monkeypatch.setattr(items, "parse", lambda source, body: 1 / 0)
    assert main(["--config", str(config)]) == 0
    assert 'parse "Good": failed, skipped this run: unexpected error: ZeroDivisionError' in caplog.text
