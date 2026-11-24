"""Watchlist groups: a burst of one product's watchlist CVEs posts once."""

from dataclasses import replace
from datetime import timedelta

import pytest
from test_cvefilter import NOW, NVD, new
from test_route import HOOKS, FakeDiscord
from test_settings import problems, settings

from intel_feeds import route
from intel_feeds.config import DEFAULTS, Watchlist
from intel_feeds.dedup import Split
from intel_feeds.embeds import (
    DESCRIPTION_LIMIT,
    EMBED_TOTAL_LIMIT,
    GROUP_LINES,
    common_lead,
    embed_length,
    group_embed,
)
from intel_feeds.state import State

LEAD = "In JetBrains TeamCity before 2026.2.2, 2026.1.6"
FLAWS = ["stored XSS was possible", "remote code execution was possible", "XXE was possible"]


def watched(cve, cvss, product="TeamCity", *, hours=0, text=None):
    """An NVD CVE the watchlist let through for ``product``."""
    made = new(NVD, cve, cvss=cvss, hours=hours)
    item = replace(
        made.item,
        title=cve,
        url=f"https://nvd.nist.gov/vuln/detail/{cve}",
        description=text or f"{LEAD} {FLAWS[int(cve[-1]) % 3]}",
        watched=product,
    )
    return replace(made, item=item)


def critical(cve, *, hours=0):
    """An NVD CVE at the bar: not a watchlist post."""
    made = new(NVD, cve, cvss=9.9, hours=hours)
    return replace(made, item=replace(made.item, title=cve))


def burst(count, product="TeamCity", *, start=0):
    # Newest first, as the NVD split lists them; hours = hours ago.
    return [
        watched(f"CVE-2026-{100 + start + i}", 7.0 + (i % 20) / 10, product, hours=count - i)
        for i in reversed(range(count))
    ]


def plan(news, group_min=3, cap=DEFAULTS.posts_per_channel):
    return route.plan({NVD.name: Split(new=list(news))}, HOOKS, cap=cap, group_min=group_min)


def titles(routing):
    return [n.item.title for r in routing.routes for n in r.items]


# --- settings ----------------------------------------------------------------


def test_group_min_defaults_to_3_and_can_be_set():
    assert DEFAULTS.watchlist.group_min == 3
    assert settings("  watchlist:\n    group_min: 5\n").watchlist == Watchlist(7.0, (), 5)


@pytest.mark.parametrize("value", ["1", "0", "101", "2.5", "true", "many"])
def test_a_bad_group_min_names_the_field(value):
    [problem] = problems(f"  watchlist:\n    group_min: {value}\n")
    assert "watchlist: 'group_min' must be a whole number from 2 to 100" in problem


def test_the_real_sources_yaml_uses_the_default():
    from test_cli import REPO

    from intel_feeds.config import load_config

    assert load_config(REPO / "sources.yaml").settings.watchlist.group_min == 3


# --- grouping ------------------------------------------------------------------


def test_group_min_or_more_cves_of_one_product_become_one_post():
    routing = plan(burst(3))
    [post] = routing.routes[0].items
    assert post.item.title == "TeamCity: 3 CVEs"
    assert [m.item.title for m in post.members] == ["CVE-2026-100", "CVE-2026-101", "CVE-2026-102"]
    assert post.size == 3 and routing.count() == 1


def test_fewer_than_group_min_post_one_by_one():
    routing = plan(burst(2))
    assert titles(routing) == ["CVE-2026-100", "CVE-2026-101"]
    assert all(not n.members for r in routing.routes for n in r.items)


def test_grouping_is_off_with_group_min_0():
    assert len(titles(plan(burst(5), group_min=0))) == 5


def test_each_product_is_grouped_on_its_own_and_others_keep_their_place():
    news = [
        critical("CVE-2026-900", hours=1),  # newest
        *burst(3, "TeamCity", start=0),  # 3, 2, 1 hours ago... oldest at 3
        *burst(2, "Fortinet", start=50),
    ]
    got = titles(plan(news))
    # The TeamCity group sits at its oldest CVE's time (3 h ago); Fortinet's
    # two stay single; the critical CVE posts alone.
    assert got == ["TeamCity: 3 CVEs", "CVE-2026-150", "CVE-2026-151", "CVE-2026-900"]


def test_a_group_counts_as_one_post_toward_the_cap():
    news = [critical(f"CVE-2026-9{i:02}", hours=i) for i in range(3)] + burst(40)
    routing = plan(news, cap=2)
    route_ = routing.routes[0]
    assert [n.item.title for n in route_.items] == ["TeamCity: 40 CVEs", "CVE-2026-902"]
    assert len(route_.overflow) == 2


# --- posting -------------------------------------------------------------------


def test_a_group_posts_one_embed_and_records_every_cve_as_posted():
    news = burst(20)
    discord, state = FakeDiscord(), State()
    report = route.post(discord.client(), plan(news), state, NOW, HOOKS)
    assert discord.titles() == ["TeamCity: 20 CVEs"]
    assert report.posted == 1 and report.grouped == 20
    assert report.posted_by == {NVD.name: 20}
    for n in news:
        assert state.items[n.id].posted_at == "2026-11-18T12:00:00Z"
    assert not any(item_id.startswith("group:") for item_id in state.items)


def test_a_failed_group_post_records_none_of_its_cves():
    news = burst(5)
    discord, state = FakeDiscord(fail={"WEBHOOK_VULNS": 400}), State()
    report = route.post(discord.client(), plan(news), state, NOW, HOOKS)
    assert discord.posts == []
    assert report.failed == 5 and report.failed_by == {NVD.name: 5}
    assert report.incomplete == {NVD.name}
    assert state.items == {}


def test_an_overflowing_group_records_none_and_counts_its_cves():
    news = [critical("CVE-2026-999", hours=10)] + burst(4)
    state = State()
    report = route.post(FakeDiscord().client(), plan(news, cap=1), state, NOW, HOOKS)
    assert report.posted == 1 and report.overflow == 4
    assert list(state.items) == [news[0].id]


# --- the embed -----------------------------------------------------------------


def test_the_summary_lists_cves_highest_score_first_with_the_shared_text_once():
    items = [n.item for n in burst(3)]  # CVSS 7.2 (CVE-102), 7.1, 7.0
    embed = group_embed("TeamCity", items)
    assert embed["title"] == "TeamCity: 3 CVEs"
    assert embed["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-102"
    assert embed["description"].splitlines() == [
        f"{LEAD}:",
        "[CVE-2026-102](https://nvd.nist.gov/vuln/detail/CVE-2026-102) **7.2** XXE was possible",
        "[CVE-2026-101](https://nvd.nist.gov/vuln/detail/CVE-2026-101) **7.1** remote code execution was possible",
        "[CVE-2026-100](https://nvd.nist.gov/vuln/detail/CVE-2026-100) **7.0** stored XSS was possible",
    ]
    assert embed["fields"] == [
        {"name": "CVSS", "value": "7.0 to 7.2 (highest High)", "inline": True},
        {"name": "Watchlist", "value": "TeamCity", "inline": True},
    ]
    newest = max(i.published for i in items)
    assert embed["timestamp"] == newest.isoformat()


def test_a_big_burst_shows_the_top_cves_then_a_count_and_fits_discord():
    long = "remote code execution was possible via " + "a very long explanation " * 40
    items = [
        replace(n.item, description=f"{LEAD} {long}{i}") for i, n in enumerate(burst(200))
    ]
    embed = group_embed("TeamCity", items)
    lines = embed["description"].splitlines()
    assert len(lines) == 1 + GROUP_LINES + 1
    assert lines[-1] == f"+{200 - GROUP_LINES} more"
    assert all(len(line) < 250 for line in lines)
    assert len(embed["description"]) <= DESCRIPTION_LIMIT
    assert embed_length(embed) <= EMBED_TOTAL_LIMIT


def test_unscored_cves_go_last_and_a_single_score_shows_alone():
    items = [n.item for n in burst(3)]
    items = [replace(items[0], cvss=None, cvss_version=None)] + [
        replace(i, cvss=8.8) for i in items[1:]
    ]
    embed = group_embed("TeamCity", items)
    assert embed["description"].splitlines()[-1].startswith(f"[{items[0].title}]")
    assert embed["fields"][0]["value"] == "8.8 (highest High)"


@pytest.mark.parametrize(
    "texts, lead",
    [
        ([f"{LEAD} XSS", f"{LEAD} XXE"], f"{LEAD} "),
        # Most share the longer lead; the odd one out does not shorten it.
        (
            [f"{LEAD} XSS", f"{LEAD} XXE", "In JetBrains TeamCity before 2026.2.2 RCE"],
            f"{LEAD} ",
        ),
        (["Short A", "Short B"], ""),  # under 20 characters: not worth it
        (["Only one text here, long enough to count"], ""),
        (["Alpha beta gamma delta epsilon", "Zeta eta theta iota kappa"], ""),
    ],
)
def test_common_lead_is_the_words_most_texts_start_with(texts, lead):
    assert common_lead(texts) == lead


def test_a_cve_without_the_shared_lead_shows_its_whole_text():
    items = [n.item for n in burst(3)]  # newest first; the last scores 7.0
    odd = replace(items[-1], description="In JetBrains TeamCity before 2026.2.2 RCE was possible")
    lines = group_embed("TeamCity", [*items[:-1], odd])["description"].splitlines()
    assert lines[0] == f"{LEAD}:"
    assert lines[-1].endswith("**7.0** In JetBrains TeamCity before 2026.2.2 RCE was possible")
