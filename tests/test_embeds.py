import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from intel_feeds import webhook
from intel_feeds.config import CATEGORIES, Source
from intel_feeds.embeds import (
    EMBED_TOTAL_LIMIT,
    FIELD_VALUE_LIMIT,
    MAX_CVES,
    badge_fields,
    cve_list,
    cvss_badge,
    embed_length,
    item_embed,
    severity,
)
from intel_feeds.items import Item, parse

FIXTURES = Path(__file__).resolve().parent / "fixtures"

KEV = Source("CISA KEV", "https://cisa.example/kev.json", "kev", "vulns")
NVD = Source("NVD CVE API", "https://nvd.example/cves/2.0", "nvd", "vulns")
MSRC = Source("Microsoft MSRC", "https://msrc.example/rss", "rss", "advisories", revisions=True)
RECORD = Source("The Record", "https://therecord.media/feed", "rss", "news")
CISCO = Source("Cisco PSIRT", "https://cisco.example/rss.xml", "rss", "advisories")

FIXTURE_SOURCES = [
    (KEV, "kev.json"),
    (NVD, "nvd.json"),
    (MSRC, "rss20_msrc.xml"),
    (RECORD, "rss20_the_record.xml"),
    (CISCO, "rss20_cisco_psirt.xml"),
]


def parsed(source: Source, name: str) -> list[Item]:
    return parse(source, (FIXTURES / name).read_bytes()).items


def item(**kwargs) -> Item:
    base = dict(title="A story", url="https://example.com/a", source="Src", category="news")
    return Item(**{**base, **kwargs})


def fields(embed: dict) -> dict[str, str]:
    return {f["name"]: f["value"] for f in embed.get("fields", [])}


# --- the base embed ------------------------------------------------------


def test_item_embed_has_title_link_source_time_excerpt_and_color():
    e = item_embed(
        item(
            title="Ransomware gang hits a hospital",
            url="https://therecord.media/x",
            source="The Record",
            category="news",
            published=datetime(2026, 11, 18, 9, 30, tzinfo=UTC),
            excerpt="The attack began on Monday.",
        )
    )
    assert e == {
        "title": "Ransomware gang hits a hospital",
        "url": "https://therecord.media/x",
        "color": webhook.COLORS["news"],
        "author": {"name": "The Record"},
        "description": "The attack began on Monday.",
        "timestamp": "2026-11-18T09:30:00+00:00",
    }


def test_item_embed_shows_the_source_icon_and_site_at_the_top():
    source = Source(
        "The Record", "https://therecord.media/feed", "rss", "news",
        site="https://therecord.media/", icon="https://therecord.media/favicon-192.png",
    )
    e = item_embed(item(title="t", url="https://therecord.media/x", source="The Record"), source)
    assert e["author"] == {
        "name": "The Record",
        "url": "https://therecord.media/",
        "icon_url": "https://therecord.media/favicon-192.png",
    }
    assert "footer" not in e
    assert list(e)[0] == "author"


@pytest.mark.parametrize("category", CATEGORIES)
def test_color_follows_the_category(category):
    assert item_embed(item(category=category))["color"] == webhook.COLORS[category]


def test_colors_differ_between_categories():
    colors = [webhook.COLORS[c] for c in CATEGORIES]
    assert len(set(colors)) == len(colors)


def test_a_plain_story_has_no_fields():
    assert "fields" not in item_embed(item())


# --- badges --------------------------------------------------------------


def test_kev_entry_shows_known_exploited_and_no_repeated_cve():
    kev = parsed(KEV, "kev.json")
    e = item_embed(kev[0])
    assert e["title"].startswith(kev[0].cve_ids[0])
    assert "CVE" not in fields(e) and "CVEs" not in fields(e)
    assert fields(e)["KEV"].startswith("Known exploited")
    assert e["color"] == webhook.COLORS["vulns"]
    assert e["url"].startswith("https://nvd.nist.gov/vuln/detail/CVE-")


def test_kev_ransomware_use_is_shown():
    e = item_embed(
        item(
            title="CVE-2026-1111: X",
            cve_ids=("CVE-2026-1111",),
            kev=True,
            tags=("Acme", "ransomware"),
        )
    )
    assert fields(e)["KEV"] == "Known exploited, used in ransomware"


def test_nvd_entry_shows_its_score_severity_and_version():
    nvd = [i for i in parsed(NVD, "nvd.json") if i.cvss is not None]
    assert nvd, "fixture should hold a scored CVE"
    e = item_embed(nvd[0])
    assert fields(e)["CVSS"] == cvss_badge(nvd[0].cvss, nvd[0].cvss_version)
    assert e["title"] == nvd[0].cve_ids[0]
    assert "KEV" not in fields(e)


def test_cvss_field_comes_after_kev_and_cve():
    e = item_embed(
        item(title="Patch now", cve_ids=("CVE-2026-1",), kev=True, cvss=9.8, cvss_version="3.1")
    )
    assert [f["name"] for f in e["fields"]] == ["CVE", "KEV", "CVSS"]
    assert all(f["inline"] for f in e["fields"])
    assert fields(e) == {"CVE": "CVE-2026-1", "KEV": "Known exploited", "CVSS": "9.8 Critical (v3.1)"}


def test_cves_named_in_a_story_but_not_its_title_are_listed():
    e = item_embed(item(title="Ivanti flaws exploited", cve_ids=("CVE-2026-1", "CVE-2026-2")))
    assert fields(e) == {"CVEs": "CVE-2026-1, CVE-2026-2"}


def test_only_cves_missing_from_the_title_are_listed():
    e = item_embed(item(title="CVE-2026-1234 and more", cve_ids=("CVE-2026-1234", "CVE-2026-12345")))
    assert fields(e) == {"CVE": "CVE-2026-12345"}


def test_title_match_ignores_case():
    e = item_embed(item(title="cve-2026-1234 fixed", cve_ids=("CVE-2026-1234",)))
    assert "fields" not in e


def test_long_cve_lists_are_cut_with_a_count():
    cves = tuple(f"CVE-2026-{n:04d}" for n in range(1, 8))
    assert cve_list(cves) == "CVE-2026-0001, CVE-2026-0002, CVE-2026-0003 +4 more"
    assert cve_list(cves[:MAX_CVES]) == "CVE-2026-0001, CVE-2026-0002, CVE-2026-0003"


def test_msrc_titles_carry_the_cve_so_no_cve_field():
    for msrc in parsed(MSRC, "rss20_msrc.xml"):
        assert msrc.cve_ids
        assert not [f for f in badge_fields(msrc) if f["name"].startswith("CVE")]


@pytest.mark.parametrize(
    ("score", "version", "expected"),
    [
        (10.0, "3.1", "Critical"),
        (9.0, "4.0", "Critical"),
        (8.9, "3.0", "High"),
        (7.0, "3.1", "High"),
        (6.9, "3.1", "Medium"),
        (4.0, "3.1", "Medium"),
        (3.9, "3.1", "Low"),
        (0.1, "3.1", "Low"),
        (0.0, "3.1", "None"),
        (10.0, "2.0", "High"),
        (7.0, "2.0", "High"),
        (5.0, "2.0", "Medium"),
        (0.0, "2.0", "Low"),
    ],
)
def test_severity_follows_each_cvss_versions_ranges(score, version, expected):
    assert severity(score, version) == expected


def test_cvss_badge_formats_one_decimal_and_handles_a_missing_version():
    assert cvss_badge(9.8, "3.1") == "9.8 Critical (v3.1)"
    assert cvss_badge(10, "4.0") == "10.0 Critical (v4.0)"
    assert cvss_badge(7.5, None) == "7.5"


# --- Discord limits ------------------------------------------------------


def test_oversized_item_stays_within_discords_limits():
    e = item_embed(
        item(
            title="T" * 1000,
            source="S" * 1000,
            excerpt="E" * 5000,
            cve_ids=tuple(f"CVE-2026-{n}" for n in range(10000, 10500)),
            kev=True,
            tags=("ransomware",),
            cvss=9.8,
            cvss_version="3.1",
        )
    )
    assert embed_length(e) < EMBED_TOTAL_LIMIT
    assert all(len(f["value"]) <= FIELD_VALUE_LIMIT for f in e["fields"])
    json.dumps(e)


@pytest.mark.parametrize(("source", "name"), FIXTURE_SOURCES, ids=lambda v: getattr(v, "name", v))
def test_every_fixture_item_makes_a_valid_embed(source, name):
    items = parsed(source, name)
    assert items
    for i in items:
        e = item_embed(i)
        assert e["title"] and e["author"]["name"] == source.name
        assert e["color"] == webhook.COLORS[source.category]
        assert e["url"].startswith("https://")
        assert "timestamp" in e
        assert embed_length(e) <= 1000  # far below 6,000: posts stay short
        assert len(e.get("fields", [])) <= 3


def test_embed_length_counts_the_text_discord_counts():
    e = {
        "title": "ab",
        "description": "cde",
        "footer": {"text": "f"},
        "fields": [{"name": "g", "value": "hi", "inline": True}],
        "color": 1,
        "url": "https://x",
    }
    assert embed_length(e) == 9


# --- ransomware victims -------------------------------------------

from intel_feeds import countries  # noqa: E402
from intel_feeds.embeds import sample_victim_embed, victim_fields  # noqa: E402
from intel_feeds.items import Victim  # noqa: E402

RANSOM = Source(
    "ransomware.live",
    "https://api-pro.example/victims/recent",
    "ransomware",
    "ransomware",
    site="https://www.ransomware.live/",
    icon="https://icons.example/rl.png",
)


def victim_item(**victim) -> Item:
    details = {
        "group": "SoulGroup",
        "group_url": "https://www.ransomware.live/group/SoulGroup",
        "country": "US",
        "sector": "Manufacturing",
        "website": "acme.example",
        **victim,
    }
    return Item(
        title="Acme Corp",
        url="https://www.ransomware.live/id/QWNtZUBTb3VsR3JvdXA=",
        source="ransomware.live",
        category="ransomware",
        published=datetime(2026, 11, 20, 1, 22, 3, tzinfo=UTC),
        excerpt="Acme makes things.",
        tags=("SoulGroup",),
        guid="ransomware:QWNtZUBTb3VsR3JvdXA=",
        victim=Victim(**details),
    )


def test_victim_embed_in_full():
    embed = item_embed(victim_item(), RANSOM)
    assert embed["author"] == {
        "name": "ransomware.live",
        "url": "https://www.ransomware.live/",
        "icon_url": "https://icons.example/rl.png",
    }
    assert embed["title"] == "Acme Corp"
    assert embed["url"] == "https://www.ransomware.live/id/QWNtZUBTb3VsR3JvdXA="
    assert embed["description"] == "Acme makes things."
    assert embed["timestamp"] == "2026-11-20T01:22:03+00:00"
    assert embed["color"] == webhook.COLORS["ransomware"] == 0x8B1A1A
    assert embed["color"] != webhook.COLORS["vulns"]
    assert embed["fields"] == [
        {"name": "Group", "value": "[SoulGroup](https://www.ransomware.live/group/SoulGroup)", "inline": True},
        {"name": "Country", "value": "🇺🇸 United States", "inline": True},
        {"name": "Sector", "value": "Manufacturing", "inline": True},
        {"name": "Website", "value": "acme.example", "inline": True},
    ]
    assert "image" not in embed and "thumbnail" not in embed


def test_victim_with_no_country_sector_website_or_description():
    item = victim_item(country="", sector="", website="")
    item = Item(**{**item.__dict__, "excerpt": ""})
    embed = item_embed(item, RANSOM)
    assert "description" not in embed
    assert [f["name"] for f in embed["fields"]] == ["Group"]


def test_victim_never_gets_cve_badges():
    item = Item(**{**victim_item().__dict__, "cve_ids": ("CVE-2026-0001",), "kev": True})
    assert [f["name"] for f in item_embed(item)["fields"]] == ["Group", "Country", "Sector", "Website"]


def test_unknown_country_code_shows_the_code_without_a_flag():
    [_, country, *_] = victim_fields(victim_item(country="QQ").victim)
    assert country["value"] == "QQ"


def test_brackets_in_a_group_name_do_not_break_the_link():
    [group, *_] = victim_fields(victim_item(group="Lock[bit]").victim)
    assert group["value"].startswith("[Lock(bit)](")


def test_a_website_with_a_scheme_is_not_made_a_link():
    [*_, website] = victim_fields(victim_item(website="https://acme.example").victim)
    assert website["value"] == "acme.example"


def test_fixture_victims_fit_discord_limits():
    rl = Source("ransomware.live", "https://rl.example/", "ransomware", "ransomware")
    for item in parse(rl, (FIXTURES / "ransomware_live.json").read_bytes()).items:
        embed = item_embed(item, rl)
        assert embed_length(embed) <= EMBED_TOTAL_LIMIT
        assert len(embed.get("description", "")) <= 300
        assert all(len(f["value"]) <= FIELD_VALUE_LIMIT for f in embed["fields"])
        assert ".onion" not in json.dumps(embed)


@pytest.mark.parametrize(
    "code, shown",
    [
        ("US", "🇺🇸 United States"),
        ("gb", "🇬🇧 United Kingdom"),
        ("UK", "🇬🇧 United Kingdom"),
        ("CH", "🇨🇭 Switzerland"),
        ("KR", "🇰🇷 South Korea"),
        ("XK", "🇽🇰 Kosovo"),
        ("ZZ", "ZZ"),
        ("", ""),
        ("  ", ""),
    ],
)
def test_country_labels(code, shown):
    assert countries.label(code) == shown


def test_country_table_has_every_assigned_code():
    assert len(countries.NAMES) == 250  # 249 assigned in ISO 3166-1, plus XK
    assert all(len(code) == 2 and code.isascii() and code.isupper() for code in countries.NAMES)
    assert all(name.strip() == name and name for name in countries.NAMES.values())


def test_sample_victim_is_made_up_and_drawn_like_a_real_one():
    embed = sample_victim_embed(RANSOM, datetime(2026, 11, 20, tzinfo=UTC))
    assert embed["title"].startswith("intel-feeds test post: ransomware")
    assert embed["author"]["icon_url"] == "https://icons.example/rl.png"
    assert embed["color"] == webhook.COLORS["ransomware"]
    assert [f["name"] for f in embed["fields"]] == ["Group", "Country", "Sector", "Website"]
    assert "example.com" in json.dumps(embed)
