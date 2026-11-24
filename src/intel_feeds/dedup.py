"""Decide which parsed items are new, and record them in state.

Each item gets one ID, its key under ``items`` in ``state.json``:

- KEV, NVD and ransomware.live: the parser's own ID (``kev:CVE-…``,
  ``nvd:CVE-…``, ``ransomware:<ransomware.live id>``).
- A GUID that is a web address: that address, canonicalized.
- Any other GUID: ``<source name>:<guid>``. Bare GUIDs such as CISA's
  ``/node/25806`` or MSRC's ``CVE-2026-1234`` could repeat in another feed.
- No GUID: the canonical URL.
- Neither: no ID. The item is skipped and counted; it cannot be deduped.

For a source with ``revisions: true`` the published time is added, as in
``Microsoft MSRC:CVE-2026-1234@2026-11-17T16:00:00Z``, so each revision is a
new item. Two revisions with the same published time count as one.

An item is also a duplicate when its canonical URL was recorded before,
from any source (one story linked by two feeds). KEV, NVD and
ransomware.live items skip this check: KEV and NVD link to the same NVD
page for a CVE, every KEV addition must post, and a victim's ID
already names its own page. Sources with revisions skip it too, because
all of an advisory's revisions share one URL.

:class:`Dedup` only reads state. The caller records an item with
:func:`record` once it is posted, or once it is deliberately not posted
(by the flood guard or the CVE filter), never before.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from intel_feeds.config import Source
from intel_feeds.items import Item
from intel_feeds.state import State, format_time

# Query parameters that only track where a click came from. Cisco PSIRT
# adds vs_f, vs_cat, vs_type, vs_p and vs_k to every link.
TRACKING_PREFIXES = ("utm_",)
TRACKING_PARAMS = frozenset(
    {
        "fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid",
        "_hsenc", "_hsmi", "mkt_tok", "ocid", "cmpid",
        "vs_f", "vs_cat", "vs_type", "vs_p", "vs_k",
    }
)
OWN_ID_TYPES = ("kev", "nvd", "ransomware")  # parser-made IDs; no URL check


def canonical_url(url: str) -> str:
    """One spelling per address, so the same link compares equal.

    Lower-cases the scheme and host, treats http as https, drops the
    default port, user info, fragment, trailing slashes and tracking
    parameters, and sorts the remaining query parameters. The path keeps
    its case. Returns ``""`` for an empty or non-web address.
    """
    url = url.strip()
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        return ""
    host = parts.hostname  # already lower-case, without user info or port
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host if port in (None, 80, 443) else f"{host}:{port}"
    query = urlencode(
        sorted(
            (key, value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
            if not _is_tracking(key)
        )
    )
    return urlunsplit(("https", netloc, parts.path.rstrip("/"), query, ""))


def _is_tracking(key: str) -> bool:
    key = key.lower()
    return key in TRACKING_PARAMS or key.startswith(TRACKING_PREFIXES)


@dataclass(frozen=True)
class NewItem:
    """An item not seen before, with the keys to record it under.

    A watchlist group is one post standing for several NVD CVEs:
    ``members`` holds them, and they, not the group, are what gets recorded.
    """

    item: Item
    id: str
    url: str | None  # canonical URL to record, or None when not URL-checked
    members: tuple[NewItem, ...] = ()  # a watchlist group's CVEs, oldest first

    @property
    def size(self) -> int:
        """How many items this post stands for."""
        return len(self.members) or 1

    def recorded(self) -> tuple[NewItem, ...]:
        """What to record when this post is made: its members, or itself."""
        return self.members or (self,)


def item_keys(item: Item, source: Source) -> tuple[str, str | None] | None:
    """Return ``(id, canonical URL or None)``, or None if the item has no ID."""
    url = canonical_url(item.url)
    if source.type in OWN_ID_TYPES and item.guid:
        return item.guid, None
    guid = (item.guid or "").strip()
    if guid:
        guid_url = canonical_url(guid)
        item_id = guid_url or f"{source.name}:{guid}"
    elif url:
        item_id = url
    else:
        return None
    if source.revisions:
        if item.published is not None:
            item_id = f"{item_id}@{format_time(item.published)}"
        return item_id, None
    return item_id, url or None


def listed(source: Source, items: list[Item]) -> set[str]:
    """Every ID and URL key ``items`` would be checked under.

    The run passes these to :meth:`State.prune`, so an item a feed still
    lists is never pruned.
    """
    keys = set()
    for item in items:
        found = item_keys(item, source)
        if found is not None:
            keys.add(found[0])
            if found[1] is not None:
                keys.add(found[1])
    return keys


@dataclass
class Split:
    """One source's items, divided."""

    new: list[NewItem] = field(default_factory=list)
    seen: int = 0  # already in state, or repeated earlier in this run
    no_id: int = 0  # neither a GUID nor a usable URL


class Dedup:
    """Finds new items for one run.

    Items handed out as new are remembered for the rest of the run, so an
    item repeated in one feed, or a URL shared by two feeds, comes out once.
    """

    def __init__(self, state: State):
        self._state = state
        self._urls = {i.url for i in state.items.values() if i.url}
        self._urls.update(i for i in state.items if i.startswith("https://"))
        self._ids_this_run: set[str] = set()

    def split(self, source: Source, items: list[Item]) -> Split:
        result = Split()
        for item in items:
            keys = item_keys(item, source)
            if keys is None:
                result.no_id += 1
                continue
            item_id, url = keys
            if (
                item_id in self._ids_this_run
                or self._state.seen(item_id)
                or (url is not None and url in self._urls)
            ):
                result.seen += 1
                continue
            self._ids_this_run.add(item_id)
            if url is not None:
                self._urls.add(url)
                if item_id.startswith("https://"):
                    self._urls.add(item_id)  # as the next run will see it
            result.new.append(NewItem(item, item_id, url))
        return result


def record(state: State, new: NewItem, now: datetime, *, posted: bool) -> None:
    """Record ``new`` in state; ``posted`` also stamps the post time.

    Call it after a successful post, or for an item that is deliberately
    not posted. The URL is stored only when it differs from the ID.
    """
    state.mark_seen(
        new.id,
        new.item.source,
        now,
        new.item.published,
        url=new.url if new.url != new.id else None,
    )
    if posted:
        state.mark_posted(new.id, now)
