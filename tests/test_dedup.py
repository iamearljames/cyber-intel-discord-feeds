import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from conftest import fetch_client

from intel_feeds import __main__ as cli
from intel_feeds import fetch
from intel_feeds.__main__ import main
from intel_feeds.config import ConfigError, Source, parse_sources
from intel_feeds.dedup import Dedup, canonical_url, item_keys, record
from intel_feeds.items import Item, parse
from intel_feeds.state import State, load_state, save_state

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NOW = datetime(2026, 11, 18, 9, 30, tzinfo=UTC)

BLOG = Source("Blog", "https://blog.example/feed", "rss", "news")
OTHER = Source("Other", "https://other.example/feed", "rss", "news")
CISCO = Source("Cisco PSIRT", "https://cisco.example/rss.xml", "rss", "advisories")
MSRC = Source("Microsoft MSRC", "https://msrc.example/rss", "rss", "advisories", revisions=True)
KEV = Source("CISA KEV", "https://cisa.example/kev.json", "kev", "vulns")
NVD = Source("NVD CVE API", "https://nvd.example/cves/2.0", "nvd", "vulns")


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def item(source: Source, url="", guid=None, published=None, title="T") -> Item:
    return Item(
        title=title, url=url, source=source.name, category=source.category,
        published=published, guid=guid,
    )


def ids(split) -> list[str]:
    return [n.id for n in split.new]


# --- canonical URLs -----------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/a/b/", "https://example.com/a/b"),
        ("https://example.com/", "https://example.com"),
        ("HTTP://Example.COM:80/Path/#section", "https://example.com/Path"),
        ("https://example.com:443/a", "https://example.com/a"),
        ("https://example.com:8443/a", "https://example.com:8443/a"),
        ("https://user:pw@example.com/a", "https://example.com/a"),
        ("https://example.com/a?b=2&a=1", "https://example.com/a?a=1&b=2"),
        ("https://example.com/a?utm_source=rss&UTM_Medium=x&id=7&fbclid=z", "https://example.com/a?id=7"),
        ("https://example.com/?p=50880", "https://example.com?p=50880"),
        ("https://example.com/a?flag", "https://example.com/a?flag="),
        ("  https://example.com/a  ", "https://example.com/a"),
        ("https://[2001:db8::1]:8080/a", "https://[2001:db8::1]:8080/a"),
        ("https://example.com:notaport/a", "https://example.com/a"),
        ("", ""),
        ("/node/25806", ""),
        ("CVE-2026-1234", ""),
        ("mailto:someone@example.com", ""),
    ],
)
def test_canonical_url(url, expected):
    assert canonical_url(url) == expected


def test_cisco_tracking_parameters_are_dropped():
    first = parse(CISCO, fixture("rss20_cisco_psirt.xml")).items[0]
    assert "vs_f=" in first.url
    assert canonical_url(first.url) == canonical_url(first.guid)
    assert "?" not in canonical_url(first.url)


# --- item IDs -----------------------------------------------------------


def test_a_url_guid_is_the_id_and_the_link_is_checked_too():
    i = item(BLOG, url="https://blog.example/story-slug/", guid="https://blog.example/?p=12")
    assert item_keys(i, BLOG) == ("https://blog.example?p=12", "https://blog.example/story-slug")


def test_a_bare_guid_is_prefixed_with_the_source_name():
    i = item(BLOG, url="https://blog.example/x", guid="6afc9f9589fda40001d45534")
    assert item_keys(i, BLOG) == ("Blog:6afc9f9589fda40001d45534", "https://blog.example/x")


def test_without_a_guid_the_canonical_url_is_the_id():
    i = item(BLOG, url="https://Blog.example/x/?utm_campaign=feed")
    assert item_keys(i, BLOG) == ("https://blog.example/x", "https://blog.example/x")


def test_no_guid_and_no_url_has_no_id():
    assert item_keys(item(BLOG, title="Only a title"), BLOG) is None


def test_kev_and_nvd_keep_their_own_ids_and_skip_the_url_check():
    kev = parse(KEV, fixture("kev.json")).items[0]
    nvd = parse(NVD, fixture("nvd.json")).items[0]
    assert item_keys(kev, KEV) == (kev.guid, None)
    assert item_keys(nvd, NVD) == (nvd.guid, None)
    assert kev.guid.startswith("kev:CVE-") and nvd.guid.startswith("nvd:CVE-")


def test_a_revision_adds_the_published_time_and_skips_the_url_check():
    i = item(MSRC, url="https://msrc.example/vulnerability/CVE-2026-1", guid="CVE-2026-1",
             published=datetime(2026, 11, 17, 16, 0, tzinfo=UTC))
    assert item_keys(i, MSRC) == ("Microsoft MSRC:CVE-2026-1@2026-11-17T16:00:00Z", None)
    undated = item(MSRC, url="https://msrc.example/vulnerability/CVE-2026-1", guid="CVE-2026-1")
    assert item_keys(undated, MSRC) == ("Microsoft MSRC:CVE-2026-1", None)


# --- splitting new from seen --------------------------------------------


def test_msrc_fixture_each_revision_is_new_once():
    parsed = parse(MSRC, fixture("rss20_msrc.xml")).items
    assert len(parsed) == 8
    split = Dedup(State()).split(MSRC, parsed)
    # CVE-2026-78524 has 5 revisions on 5 dates; CVE-2026-71331 has 3
    # revisions published at the same time, which count as one.
    assert ids(split) == [
        "Microsoft MSRC:CVE-2026-78524@2026-11-17T16:00:00Z",
        "Microsoft MSRC:CVE-2026-78524@2026-10-16T14:00:00Z",
        "Microsoft MSRC:CVE-2026-78524@2026-09-21T14:00:00Z",
        "Microsoft MSRC:CVE-2026-78524@2026-09-17T14:00:00Z",
        "Microsoft MSRC:CVE-2026-78524@2026-09-08T14:00:00Z",
        "Microsoft MSRC:CVE-2026-71331@2026-08-20T14:00:00Z",
    ]
    assert split.seen == 2
    assert all(n.url is None for n in split.new)


def test_msrc_without_revisions_posts_each_guid_once():
    plain = Source("Microsoft MSRC", "https://msrc.example/rss", "rss", "advisories")
    split = Dedup(State()).split(plain, parse(plain, fixture("rss20_msrc.xml")).items)
    assert ids(split) == ["Microsoft MSRC:CVE-2026-78524", "Microsoft MSRC:CVE-2026-71331"]
    assert split.seen == 6


def test_a_new_revision_after_the_first_run_is_new():
    state = State()
    parsed = parse(MSRC, fixture("rss20_msrc.xml")).items
    for new in Dedup(state).split(MSRC, parsed).new:
        record(state, new, NOW, posted=False)
    revised = item(MSRC, url=parsed[0].url, guid=parsed[0].guid,
                   published=datetime(2026, 11, 20, 16, 0, tzinfo=UTC))
    split = Dedup(state).split(MSRC, [revised, *parsed])
    assert ids(split) == ["Microsoft MSRC:CVE-2026-78524@2026-11-20T16:00:00Z"]
    assert split.seen == 8


def test_the_same_bare_guid_in_two_sources_is_two_items():
    checker = Dedup(State())
    a = checker.split(BLOG, [item(BLOG, url="https://blog.example/1", guid="/node/1")])
    b = checker.split(OTHER, [item(OTHER, url="https://other.example/1", guid="/node/1")])
    assert ids(a) == ["Blog:/node/1"] and ids(b) == ["Other:/node/1"]


def test_the_same_url_from_another_source_is_a_duplicate():
    checker = Dedup(State())
    a = checker.split(BLOG, [item(BLOG, url="https://news.example/story", guid="a-1")])
    b = checker.split(OTHER, [item(OTHER, url="http://news.example/story/?utm_source=x", guid="b-9")])
    assert ids(a) == ["Blog:a-1"]
    assert b.new == [] and b.seen == 1


def test_a_repeated_entry_in_one_feed_comes_out_once():
    entry = item(BLOG, url="https://blog.example/x", guid="https://blog.example/x")
    split = Dedup(State()).split(BLOG, [entry, entry])
    assert len(split.new) == 1 and split.seen == 1


def test_kev_still_posts_a_cve_that_nvd_or_a_feed_already_linked():
    kev = parse(KEV, fixture("kev.json")).items[0]
    nvd_page = kev.url  # https://nvd.nist.gov/vuln/detail/CVE-…
    nvd = Item(title=kev.cve_ids[0], url=nvd_page, source=NVD.name, category="vulns",
               guid=f"nvd:{kev.cve_ids[0]}")
    blog = item(BLOG, url=nvd_page, guid="blog-1")
    checker = Dedup(State())
    assert len(checker.split(BLOG, [blog]).new) == 1
    assert len(checker.split(NVD, [nvd]).new) == 1
    assert len(checker.split(KEV, [kev]).new) == 1


def test_items_without_an_id_are_counted():
    split = Dedup(State()).split(BLOG, [item(BLOG), item(BLOG, url="https://blog.example/x")])
    assert split.no_id == 1 and len(split.new) == 1


# --- recording ----------------------------------------------------------


def test_recorded_items_are_seen_next_run_after_a_save_and_load(tmp_path):
    state = State()
    state.add_sources(["Blog"], NOW)
    entries = [
        # ID is the URL: stored once, matched as a URL through the ID.
        item(BLOG, url="https://blog.example/same", guid="https://blog.example/same"),
        # ID differs from the link: the link is stored in "url".
        item(BLOG, url="https://blog.example/slug", guid="https://blog.example/?p=2",
             published=NOW - timedelta(hours=1)),
    ]
    split = Dedup(state).split(BLOG, entries)
    record(state, split.new[0], NOW, posted=True)
    record(state, split.new[1], NOW, posted=False)
    assert state.items["https://blog.example/same"].url is None
    assert state.items["https://blog.example/same"].posted_at == "2026-11-18T09:30:00Z"
    assert state.items["https://blog.example?p=2"].url == "https://blog.example/slug"
    assert state.items["https://blog.example?p=2"].posted_at is None
    assert state.items["https://blog.example?p=2"].published_at == "2026-11-18T08:30:00Z"

    path = tmp_path / "state.json"
    save_state(path, state)
    loaded = load_state(path)
    assert loaded == state
    again = Dedup(loaded)
    assert again.split(BLOG, entries).seen == 2
    # Another source linking either URL is a duplicate too.
    relinks = [item(OTHER, url="https://blog.example/same/", guid="o-1"),
               item(OTHER, url="https://blog.example/slug?utm_source=o", guid="o-2")]
    assert again.split(OTHER, relinks).seen == 2


def test_record_only_writes_the_first_time():
    state = State()
    new = Dedup(state).split(BLOG, [item(BLOG, url="https://blog.example/x")]).new[0]
    record(state, new, NOW, posted=False)
    record(state, new, NOW + timedelta(hours=1), posted=False)
    assert state.items["https://blog.example/x"].first_seen == "2026-11-18T09:30:00Z"


# --- config -------------------------------------------------------------


def entry(extra: str, type_: str = "rss") -> str:
    return (
        "sources:\n  - name: X\n    url: https://x.example/feed\n"
        f"    type: {type_}\n    category: news\n{extra}"
    )


def test_revisions_defaults_to_false_and_accepts_true():
    assert parse_sources(entry("")).pop().revisions is False
    assert parse_sources(entry("    revisions: true\n")).pop().revisions is True


@pytest.mark.parametrize(
    ("extra", "type_", "message"),
    [
        ("    revisions: yes please\n", "rss", "'revisions' must be true or false, found \"yes please\""),
        ("    revisions: 1\n", "rss", "'revisions' must be true or false, found 1 (a number)"),
        ("    revisions: true\n", "kev", "'revisions' applies only to type rss"),
    ],
)
def test_revisions_errors(extra, type_, message):
    with pytest.raises(ConfigError) as caught:
        parse_sources(entry(extra, type_))
    assert any(message in e and 'source "X"' in e for e in caught.value.errors)


def test_the_committed_config_sets_revisions_only_for_msrc():
    from intel_feeds.config import load_sources

    repo = Path(__file__).resolve().parents[1]
    assert [s.name for s in load_sources(repo / "sources.yaml") if s.revisions] == ["Microsoft MSRC"]


# --- the run ------------------------------------------------------------


def test_a_run_logs_new_and_seen_counts(tmp_path, monkeypatch, caplog):
    config = tmp_path / "sources.yaml"
    config.write_text(
        "sources:\n"
        "  - name: MSRC\n    url: https://feeds.example.com/msrc.xml\n    type: rss\n"
        "    category: advisories\n    revisions: true\n"
        "  - name: Record\n    url: https://feeds.example.com/record.xml\n    type: rss\n    category: news\n"
    )
    bodies = {"/msrc.xml": fixture("rss20_msrc.xml"), "/record.xml": fixture("rss20_the_record.xml")}
    monkeypatch.setattr(
        fetch, "make_client",
        lambda transport=None: fetch_client(
            lambda r: httpx.Response(200, content=bodies[r.url.path], headers={"ETag": '"v1"'})
        ),
    )
    # Posting off: the flood guard holds both new sources' whole backlogs,
    # whatever the fixture dates.
    monkeypatch.setattr(cli, "POSTING_ENABLED", False)
    caplog.set_level(logging.INFO)
    state_path = tmp_path / "state.json"
    assert main(["--config", str(config), "--state", str(state_path)]) == 0
    assert 'dedup "MSRC": 6 new, 2 already seen' in caplog.text
    assert 'dedup "Record": 5 new, 0 already seen' in caplog.text
    assert "dedup: 11 new, 2 already seen" in caplog.text
    # Both sources are new, so the flood guard records all 11, none posted.
    saved = load_state(state_path)
    assert len(saved.items) == 11
    assert not any(i.posted_at for i in saved.items.values())
