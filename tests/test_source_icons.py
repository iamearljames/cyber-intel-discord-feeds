"""The source name, icon and site link at the top of each post."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_route import HOOKS, FakeDiscord

from intel_feeds import route, webhook
from intel_feeds.__main__ import load_config
from intel_feeds.config import ConfigError, parse_sources
from intel_feeds.dedup import NewItem, Split
from intel_feeds.items import Item
from intel_feeds.state import State

ENTRY = "sources:\n  - name: Blog\n    url: https://example.com/feed\n    type: rss\n    category: news\n"


def problems(extra: str) -> list[str]:
    with pytest.raises(ConfigError) as exc:
        parse_sources(ENTRY + extra)
    return exc.value.errors


def test_site_and_icon_are_optional():
    [source] = parse_sources(ENTRY)
    assert (source.site, source.icon) == (None, None)
    [source] = parse_sources(ENTRY + "    site:\n    icon: ''\n")
    assert (source.site, source.icon) == (None, None)


def test_site_and_icon_are_read():
    [source] = parse_sources(
        ENTRY + "    site: https://example.com/\n    icon: ' https://example.com/i.png '\n"
    )
    assert (source.site, source.icon) == ("https://example.com/", "https://example.com/i.png")


@pytest.mark.parametrize(
    "extra, message",
    [
        ("    icon: http://example.com/i.png\n", "'icon' must start with https://"),
        ("    site: example.com\n", "'site' must start with https://"),
        ("    icon: https://localhost/i.png\n", "'icon' has no valid host name"),
        ("    site: https://example.com/a b\n", "'site' contains spaces"),
        ("    icon: 42\n", "'icon' must be text, found a number"),
        ("    icons: https://example.com/i.png\n", "unknown field 'icons'; did you mean 'icon'?"),
    ],
)
def test_bad_site_or_icon_names_the_field(extra, message):
    [problem] = problems(extra)
    assert 'source "Blog"' in problem and message in problem


def test_every_real_source_has_a_site_and_an_https_image_icon():
    config = load_config(Path(__file__).resolve().parents[1] / "sources.yaml")
    for source in config.sources:
        assert source.site and source.icon, source.name
        assert not source.icon.lower().split("?")[0].endswith(".ico"), source.name


def test_posts_carry_their_sources_icon_and_link(monkeypatch):
    [source] = parse_sources(
        ENTRY + "    site: https://example.com/\n    icon: https://example.com/i.png\n"
    )
    item = Item(
        title="Story", url="https://example.com/1", source="Blog", category="news",
        published=datetime(2026, 11, 18, 12, tzinfo=UTC),
    )
    routing = route.plan({"Blog": Split(new=[NewItem(item, "id1", None)])}, HOOKS)
    discord = FakeDiscord()
    with discord.client() as client:
        route.post(client, routing, State(), datetime.now(UTC), HOOKS, sources={"Blog": source})
    author = discord.posts[0][1]["embeds"][0]["author"]
    assert author == {"name": "Blog", "url": "https://example.com/", "icon_url": "https://example.com/i.png"}


def test_without_sources_a_post_shows_the_name_alone():
    item = Item(title="Story", url="https://example.com/1", source="Blog", category="news")
    routing = route.plan({"Blog": Split(new=[NewItem(item, "id1", None)])}, HOOKS)
    discord = FakeDiscord()
    with discord.client() as client:
        route.post(client, routing, State(), datetime.now(UTC), HOOKS)
    assert discord.posts[0][1]["embeds"][0]["author"] == {"name": "Blog"}
