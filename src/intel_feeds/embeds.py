"""Turn an item into the Discord embed that posts it.

Every embed has the source name at the top, with the source's icon and a
link to its site when ``sources.yaml`` gives them, then the item's
title linking to its URL, a short excerpt, the published time and the
category's color (see
:func:`intel_feeds.webhook.build_embed`). An item that names CVEs, is a CISA
KEV entry or carries a CVSS or EPSS score also gets a row of short inline fields:

- ``CVE`` / ``CVEs``: the IDs the title does not already show, at most
  :data:`MAX_CVES`, then "+N more". KEV, NVD and MSRC titles start with
  their CVE, so their posts usually show no CVE field.
- ``KEV``: "Known exploited", plus "used in ransomware" when CISA says so.
- ``CVSS``: score, severity and version, for example "9.8 Critical (v3.1)".
- ``EPSS``: FIRST's probability of exploitation in the next 30 days and
  its percentile, for example "12.3% (96th percentile)".
- ``Watchlist``: the watched product an NVD CVE names, when it posts only
  because of the product watchlist, for example "Fortinet".

A ransomware victim gets its own fields instead, each left out
when empty: ``Group`` (linking to the group's ransomware.live page),
``Country`` (flag and name), ``Sector`` and ``Website`` (plain text, not
a link). The title is the victim and links to its ransomware.live page;
the description is the leak post's text and the time is when
ransomware.live discovered it. Screenshots, infostealer data and press
links are never shown, and nothing is pinged.

A watchlist group posts as one summary (:func:`group_embed`): the
product and CVE count as the title, the CVSS range, and the CVEs listed
highest score first, each linking to NVD with the part of its description
that differs from the others.

This lives outside ``webhook`` because ``items`` imports ``webhook``.
"""

from __future__ import annotations

import re
from collections import Counter

from datetime import datetime

from intel_feeds import countries
from intel_feeds.config import Source
from intel_feeds.items import RANSOMWARE_GROUP_URL, Item, Victim, find_cves
from intel_feeds.webhook import build_embed

MAX_CVES = 3

# A watchlist group's summary lists at most this many CVEs, each with this
# much of its own description.
GROUP_LINES = 15
GROUP_LINE_TEXT = 90
GROUP_LEAD_TEXT = 150
DESCRIPTION_LIMIT = 4096  # Discord's limit for an embed's description

# Discord's limits on one embed (characters).
FIELD_NAME_LIMIT = 256
FIELD_VALUE_LIMIT = 1024
EMBED_TOTAL_LIMIT = 6000


def item_embed(item: Item, source: Source | None = None) -> dict:
    """The embed for one item, ready for ``webhook.post_embed``.

    ``source`` (the item's source config) supplies the icon and site link.
    """
    embed = build_embed(
        title=item.title,
        category=item.category,
        source=item.source,
        url=item.url,
        published=item.published,
        excerpt=item.excerpt,
        source_url=source.site if source else None,
        source_icon=source.icon if source else None,
    )
    fields = victim_fields(item.victim) if item.victim else badge_fields(item)
    if fields:
        embed["fields"] = fields
    return embed


def victim_fields(victim: Victim) -> list[dict]:
    """Group, Country, Sector and Website, each left out when empty."""
    fields = []
    if victim.group:
        fields.append(_field("Group", f"[{_link_text(victim.group)}]({victim.group_url})"))
    country = countries.label(victim.country)
    if country:
        fields.append(_field("Country", country))
    if victim.sector:
        fields.append(_field("Sector", victim.sector))
    if victim.website:
        fields.append(_field("Website", _no_autolink(victim.website)))
    return fields


def sample_victim_embed(source: Source | None = None, now: datetime | None = None) -> dict:
    """A made-up victim post for ``--test-post`` on the ransomware channel."""
    group = "ExampleGroup"
    item = Item(
        title="intel-feeds test post: ransomware (made-up victim)",
        url="https://www.ransomware.live/",
        source=source.name if source else "ransomware.live",
        category="ransomware",
        published=now,
        excerpt=(
            "If you can read this, the ransomware webhook works. A real post "
            "looks like this: the victim as the title, the leak post's text "
            "here, and the group, country, sector and website below."
        ),
        victim=Victim(
            group=group,
            group_url=RANSOMWARE_GROUP_URL.format(group),
            country="US",
            sector="Manufacturing",
            website="example.com",
        ),
    )
    return item_embed(item, source)


def _link_text(text: str) -> str:
    # Square brackets would end a masked link early.
    return text.replace("[", "(").replace("]", ")")


def _no_autolink(host: str) -> str:
    # Discord links a bare "https://..." on its own; a victim's site should
    # not be one click away, so a scheme, if any, is dropped.
    return re.sub(r"^[a-z][a-z0-9+.-]*://", "", host.strip(), flags=re.IGNORECASE)


def group_embed(product: str, members: list[Item], source: Source | None = None) -> dict:
    """One summary embed for a product's watchlist CVEs.

    The title names the product and links to the highest-scoring CVE; the
    description lists the CVEs, highest score first (newest first on a
    tie), then "+N more". Text most descriptions start with ("In JetBrains
    TeamCity before 2026.2.2, 2026.1.6") is shown once above the list.
    """
    ranked = sorted(members, key=_rank)
    scores = [m.cvss for m in members if m.cvss is not None]
    newest = max((m.published for m in members if m.published), default=None)
    top = ranked[0]
    texts = [(m.description or m.excerpt).strip() for m in ranked]
    lead = common_lead(texts)
    lines = []
    if lead:
        lines.append(f"{_clip_words(lead.rstrip(' ,:;'), GROUP_LEAD_TEXT)}:")
    for member, text in zip(ranked[:GROUP_LINES], texts):
        cve = member.cve_ids[0] if member.cve_ids else member.title
        score = f" **{member.cvss:.1f}**" if member.cvss is not None else ""
        text = re.sub(r"\s+", " ", text)
        if lead and text.startswith(lead):
            text = text[len(lead):]
        rest = _clip_words(text.strip(), GROUP_LINE_TEXT)
        line = f"[{cve}]({member.url}){score}"
        lines.append(f"{line} {rest}" if rest else line)
    if len(ranked) > GROUP_LINES:
        lines.append(f"+{len(ranked) - GROUP_LINES} more")
    embed = build_embed(
        title=f"{product}: {len(members)} CVEs",
        category=top.category,
        source=top.source,
        url=top.url,
        published=newest,
        source_url=source.site if source else None,
        source_icon=source.icon if source else None,
    )
    embed["description"] = _fit_lines(lines, DESCRIPTION_LIMIT)
    fields = []
    if scores:
        low, high = min(scores), max(scores)
        shown = f"{low:.1f} to {high:.1f}" if low != high else f"{high:.1f}"
        version = top.cvss_version if top.cvss is not None else None
        if version:
            shown += f" (highest {severity(high, version)})"
        fields.append(_field("CVSS", shown))
    fields.append(_field("Watchlist", product))
    embed["fields"] = fields
    return embed


def common_lead(texts: list[str], minimum: int = 20) -> str:
    """The longest run of whole words that most texts start with.

    "Most" is at least half of them, and at least two. Returns "" when no
    such run is ``minimum`` characters or longer. The result ends with a
    space; texts that do not start with it are shown whole.
    """
    need = max(2, (len(texts) + 1) // 2)
    words = [text.split() for text in texts]
    lead: tuple[str, ...] = ()
    for size in range(1, max(map(len, words), default=0) + 1):
        counts = Counter(tuple(w[:size]) for w in words if len(w) >= size)
        best, count = counts.most_common(1)[0] if counts else ((), 0)
        if count < need:
            break
        lead = best
    shown = " ".join(lead)
    if len(shown) < minimum:
        return ""
    # Each text must start with the lead exactly (whitespace included).
    return shown + " "


def _rank(item: Item):
    published = item.published.timestamp() if item.published else 0.0
    return (-(item.cvss if item.cvss is not None else -1.0), -published, item.title)


def _clip_words(text: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", text)
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    if " " in cut:
        cut = cut[: cut.rfind(" ")]
    return cut.rstrip(" ,.;:") + "…"


def _fit_lines(lines: list[str], limit: int) -> str:
    """Join ``lines``, dropping whole lines from the end to stay within ``limit``."""
    text = "\n".join(lines)
    while len(text) > limit and len(lines) > 1:
        lines = lines[:-1]
        text = "\n".join(lines)
    return text[:limit]


def badge_fields(item: Item) -> list[dict]:
    fields = []
    in_title = set(find_cves(item.title))
    cves = [cve for cve in item.cve_ids if cve not in in_title]
    if cves:
        fields.append(_field("CVE" if len(cves) == 1 else "CVEs", cve_list(cves)))
    if item.kev:
        value = "Known exploited"
        if "ransomware" in item.tags:
            value += ", used in ransomware"
        fields.append(_field("KEV", value))
    if item.cvss is not None:
        fields.append(_field("CVSS", cvss_badge(item.cvss, item.cvss_version)))
    if item.epss is not None and item.epss_percentile is not None:
        fields.append(_field("EPSS", epss_badge(item.epss, item.epss_percentile)))
    if item.watched:
        fields.append(_field("Watchlist", item.watched))
    return fields


def cve_list(cves: list[str] | tuple[str, ...]) -> str:
    shown = ", ".join(cves[:MAX_CVES])
    rest = len(cves) - MAX_CVES
    return f"{shown} +{rest} more" if rest > 0 else shown


def cvss_badge(score: float, version: str | None) -> str:
    """``"9.8 Critical (v3.1)"``; without a version, the score alone."""
    if not version:
        return f"{score:.1f}"
    return f"{score:.1f} {severity(score, version)} (v{version})"


def epss_badge(epss: float, percentile: float) -> str:
    """``"12.3% (96th percentile)"``; small scores keep two decimals."""
    percent = epss * 100
    if percent < 0.01:
        shown = "<0.01%"
    elif percent < 1:
        shown = f"{percent:.2f}%"
    else:
        # Never round a score short of certain up to 100%.
        shown = f"{min(round(percent, 1), 99.9) if epss < 1 else 100.0:.1f}%"
    return f"{shown} ({ordinal(round(percentile * 100))} percentile)"


_SUFFIXES = {1: "st", 2: "nd", 3: "rd"}


def ordinal(n: int) -> str:
    """1st, 2nd, 3rd, 4th, ... 11th, 12th, 13th, ... 21st."""
    suffix = "th" if 10 <= n % 100 <= 20 else _SUFFIXES.get(n % 10, "th")
    return f"{n}{suffix}"


def severity(score: float, version: str) -> str:
    """The rating FIRST and NVD give a score.

    CVSS v3.x and v4.0: None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High
    7.0-8.9, Critical 9.0-10.0. CVSS v2 has no Critical or None: Low
    0.0-3.9, Medium 4.0-6.9, High 7.0-10.0.
    """
    if score >= 9.0 and not version.startswith("2"):
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score == 0.0 and not version.startswith("2"):
        return "None"
    return "Low"


def embed_length(embed: dict) -> int:
    """Characters Discord counts toward its 6,000 limit for one embed."""
    total = len(embed.get("title", "")) + len(embed.get("description", ""))
    total += len(embed.get("footer", {}).get("text", ""))
    total += len(embed.get("author", {}).get("name", ""))
    for field in embed.get("fields", []):
        total += len(field["name"]) + len(field["value"])
    return total


def _field(name: str, value: str) -> dict:
    return {
        "name": name[:FIELD_NAME_LIMIT],
        "value": value[:FIELD_VALUE_LIMIT],
        "inline": True,
    }
