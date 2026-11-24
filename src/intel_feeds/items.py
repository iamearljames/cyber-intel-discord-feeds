"""Turn fetched responses into items with one shape, whatever the source.

Every parser returns :class:`Item` objects with the common fields
(title, url, source, published, excerpt, category, tags, cve_ids) plus a
few later steps need: ``guid`` (the feed's own ID, for dedup),
``cvss`` / ``cvss_version`` (NVD's score, for the CVE filter and the
badge) and ``kev`` (a CISA KEV entry). ``epss`` /
``epss_percentile`` are never set by a parser: :mod:`intel_feeds.enrich`
adds them, and a missing CVSS score, to items about to post.
``description`` is NVD's whole English description (the excerpt is cut
short), for the product watchlist; other parsers leave it empty.
``watched`` is set by :mod:`intel_feeds.cvefilter` on an NVD CVE that
posts only because it names a watched product.

- RSS and Atom: one item per entry, through feedparser. An entry with
  neither a title nor a link is skipped and counted.
- CISA KEV: one item per catalog entry; ``published`` is the day it was
  added (midnight UTC).
- NVD: one item per CVE in the merged response from ``fetch``; rejected
  CVEs are skipped.
- ransomware.live: one item per victim in ``/victims/recent``;
  ``published`` is ``discovered`` (when ransomware.live saw the leak post),
  ``url`` the victim's ransomware.live page, and ``victim`` holds the
  group, country, sector and website for the embed. The leak site's
  own ``.onion`` address (``post_url``) is never kept.

A body that cannot be read at all raises :class:`ParseError`; the caller
skips that source for the run, as it does a failed fetch.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import quote

import feedparser

from intel_feeds.config import Source
from intel_feeds.webhook import EXCERPT_LIMIT

NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{}"
RANSOMWARE_GROUP_URL = "https://www.ransomware.live/group/{}"
RANSOMWARE_VICTIM_URL = "https://www.ransomware.live/id/{}"
# ransomware.live's "activity" (sector) when it does not know.
UNKNOWN_SECTORS = frozenset({"not found", "unknown", "n/a", "none"})
COUNTRY_CODE = re.compile(r"[A-Z]{2}")
CVE_PATTERN = re.compile(r"\bCVE-(\d{4})-(\d{4,})\b", re.IGNORECASE)
# WordPress feeds (SecurityWeek and others) end every summary with this.
WORDPRESS_FOOTER = re.compile(r"\s*The post .{1,400}? appeared first on [^.]{1,100}\.?$")

# Newest CVSS version first. Within a version, NVD's own score ("Primary")
# wins over the CNA's ("Secondary"); NVD often adds its own days later.
CVSS_METRICS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


class ParseError(Exception):
    """A whole response could not be read. The message never holds a URL."""


@dataclass(frozen=True)
class Victim:
    """A ransomware leak-site victim's details. Empty text = unknown."""

    group: str
    group_url: str
    country: str = ""  # ISO 3166-1 alpha-2, upper case
    sector: str = ""
    website: str = ""  # a bare host as listed, e.g. "example.com"


@dataclass(frozen=True)
class Item:
    title: str
    url: str
    source: str
    category: str
    published: datetime | None = None
    excerpt: str = ""
    tags: tuple[str, ...] = ()
    cve_ids: tuple[str, ...] = ()
    guid: str | None = None
    cvss: float | None = None
    cvss_version: str | None = None
    kev: bool = False
    epss: float | None = None  # FIRST EPSS probability, 0 to 1
    epss_percentile: float | None = None  # 0 to 1
    description: str = ""  # NVD only: the full text, never stored in state
    watched: str | None = None  # the watched product that let it post
    victim: Victim | None = None  # ransomware sources only


@dataclass
class Parsed:
    items: list[Item]
    skipped: int = 0  # entries dropped as unusable


def parse(source: Source, body: bytes) -> Parsed:
    """Parse one source's response body into items."""
    if source.type == "kev":
        return parse_kev(source, body)
    if source.type == "nvd":
        return parse_nvd(source, body)
    if source.type == "ransomware":
        return parse_ransomware(source, body)
    return parse_feed(source, body)


# --- RSS and Atom -------------------------------------------------------


def parse_feed(source: Source, body: bytes) -> Parsed:
    feed = feedparser.parse(body)
    if not feed.get("version"):
        error = feed.get("bozo_exception")
        problem = type(error).__name__ if error else "no feed found"
        raise ParseError(f"not an RSS or Atom feed ({problem})")
    parsed = Parsed([])
    for entry in feed.entries:
        title = strip_html(entry.get("title", ""))
        link = (entry.get("link") or "").strip()
        if not title and not link:
            parsed.skipped += 1
            continue
        text = WORDPRESS_FOOTER.sub("", strip_html(_entry_text(entry)))
        parsed.items.append(
            Item(
                title=title or link,
                url=link,
                source=source.name,
                category=source.category,
                published=_entry_time(entry),
                excerpt=truncate(text),
                tags=_unique(tag.get("term", "") for tag in entry.get("tags", [])),
                cve_ids=find_cves(title, text),
                guid=(entry.get("id") or "").strip() or None,
            )
        )
    return parsed


def _entry_text(entry) -> str:
    if entry.get("summary"):
        return entry.summary
    for content in entry.get("content", []):
        if content.get("value"):
            return content.value
    return ""


def _entry_time(entry) -> datetime | None:
    # feedparser converts every date it understands to a UTC struct_time;
    # a date without a timezone (Cisco PSIRT) is read as UTC.
    moment = entry.get("published_parsed") or entry.get("updated_parsed")
    return datetime(*moment[:6], tzinfo=UTC) if moment else None


# --- CISA KEV -----------------------------------------------------------


def parse_kev(source: Source, body: bytes) -> Parsed:
    vulns = _json_list(body, "vulnerabilities", "KEV")
    parsed = Parsed([])
    for vuln in vulns:
        cve = _cve_id(vuln.get("cveID") if isinstance(vuln, dict) else None)
        if cve is None:
            parsed.skipped += 1
            continue
        name = (vuln.get("vulnerabilityName") or "").strip()
        tags = [vuln.get("vendorProject") or "", vuln.get("product") or ""]
        if vuln.get("knownRansomwareCampaignUse") == "Known":
            tags.append("ransomware")
        description = strip_html(vuln.get("shortDescription") or "")
        parsed.items.append(
            Item(
                title=f"{cve}: {name}" if name else cve,
                url=NVD_DETAIL_URL.format(cve),
                source=source.name,
                category=source.category,
                published=_date(vuln.get("dateAdded")),
                excerpt=truncate(description),
                tags=_unique(tags),
                cve_ids=(cve,),
                guid=f"kev:{cve}",
                kev=True,
            )
        )
    return parsed


def _date(value: object) -> datetime | None:
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        return None


# --- NVD ----------------------------------------------------------------


def parse_nvd(source: Source, body: bytes) -> Parsed:
    vulns = _json_list(body, "vulnerabilities", "NVD")
    parsed = Parsed([])
    for vuln in vulns:
        cve = vuln.get("cve") if isinstance(vuln, dict) else None
        cve_id = _cve_id(cve.get("id") if isinstance(cve, dict) else None)
        if cve_id is None or cve.get("vulnStatus") == "Rejected":
            parsed.skipped += 1
            continue
        description = next(
            (
                d.get("value", "")
                for d in cve.get("descriptions", [])
                if isinstance(d, dict) and d.get("lang") == "en"
            ),
            "",
        )
        description = strip_html(description)
        score, version = cvss_score(cve.get("metrics") or {})
        parsed.items.append(
            Item(
                title=cve_id,
                url=NVD_DETAIL_URL.format(cve_id),
                source=source.name,
                category=source.category,
                published=_iso_time(cve.get("published")),
                excerpt=truncate(description),
                description=description,
                cve_ids=_unique([cve_id, *find_cves(description)]),
                guid=f"nvd:{cve_id}",
                cvss=score,
                cvss_version=version,
            )
        )
    return parsed


def cvss_score(metrics: dict) -> tuple[float | None, str | None]:
    """The base score of the newest CVSS version, NVD's own before the CNA's."""
    for key, version in CVSS_METRICS:
        entries = [m for m in metrics.get(key) or [] if isinstance(m, dict)]
        entries.sort(key=lambda m: m.get("type") != "Primary")
        for metric in entries:
            score = (metric.get("cvssData") or {}).get("baseScore")
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                return float(score), version
    return None, None


def _iso_time(value: object) -> datetime | None:
    # NVD times have no timezone and are UTC; ransomware.live's end in +00:00.
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


# --- ransomware.live ----------------------------------------------------


def parse_ransomware(source: Source, body: bytes) -> Parsed:
    victims = _json_list(body, "victims", "ransomware.live")
    parsed = Parsed([])
    for victim in victims:
        if not isinstance(victim, dict):
            parsed.skipped += 1
            continue
        name = _text(victim.get("victim"))
        group = _text(victim.get("group"))
        victim_id = _text(victim.get("id"))
        if not (name and group and victim_id):
            parsed.skipped += 1
            continue
        url = _text(victim.get("permalink"))
        if not url.startswith("https://"):
            url = RANSOMWARE_VICTIM_URL.format(quote(victim_id, safe=""))
        country = _text(victim.get("country")).upper()
        sector = _text(victim.get("activity"))
        description = strip_html(_text(victim.get("description")))
        parsed.items.append(
            Item(
                title=name,
                url=url,
                source=source.name,
                category=source.category,
                published=_iso_time(victim.get("discovered")),
                excerpt=truncate(description),
                tags=_unique([group]),
                guid=f"ransomware:{victim_id}",
                victim=Victim(
                    group=group,
                    group_url=RANSOMWARE_GROUP_URL.format(quote(group, safe="")),
                    country=country if COUNTRY_CODE.fullmatch(country) else "",
                    sector="" if sector.casefold() in UNKNOWN_SECTORS else sector,
                    website=_text(victim.get("website")),
                ),
            )
        )
    return parsed


def _text(value: object) -> str:
    return " ".join(value.split()) if isinstance(value, str) else ""


# --- shared helpers -----------------------------------------------------


def _json_list(body: bytes, key: str, label: str) -> list:
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise ParseError(f"{label} response is not JSON") from exc
    value = data.get(key) if isinstance(data, dict) else None
    if not isinstance(value, list):
        raise ParseError(f'{label} response has no "{key}" list')
    return value


def _cve_id(value: object) -> str | None:
    match = CVE_PATTERN.fullmatch(str(value).strip()) if value else None
    return f"CVE-{match[1]}-{match[2]}" if match else None


def find_cves(*texts: str) -> tuple[str, ...]:
    """CVE IDs in ``texts``, upper-cased, first appearance first."""
    return _unique(
        f"CVE-{year}-{number}"
        for text in texts
        for year, number in CVE_PATTERN.findall(text)
    )


def _unique(values) -> tuple[str, ...]:
    kept, folded = [], set()
    for value in values:
        value = value.strip()
        if value and value.casefold() not in folded:
            kept.append(value)
            folded.add(value.casefold())
    return tuple(kept)


class _TextExtractor(HTMLParser):
    BREAKS = {"p", "br", "div", "li", "ul", "ol", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote"}
    HIDDEN = {"script", "style"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.HIDDEN:
            self.hidden += 1
        elif tag in self.BREAKS:
            self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag in self.HIDDEN:
            self.hidden = max(0, self.hidden - 1)
        elif tag in self.BREAKS:
            self.parts.append(" ")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def strip_html(text: str) -> str:
    """Plain text: tags removed, entities decoded, whitespace collapsed."""
    if not text:
        return ""
    extractor = _TextExtractor()
    extractor.feed(text)
    extractor.close()
    return " ".join("".join(extractor.parts).split())


def truncate(text: str, limit: int = EXCERPT_LIMIT) -> str:
    """Cut ``text`` to ``limit`` characters at a word boundary, adding "…"."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    space = cut.rfind(" ")
    if space > limit * 0.6:
        cut = cut[:space]
    return cut.rstrip(" ,;:.-") + "…"
