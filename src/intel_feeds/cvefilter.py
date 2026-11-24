"""CVE filter: every KEV addition, and only critical CVEs otherwise.

Applied to each source's new items after the flood guard, before routing:

- **KEV** (``type: kev``): every new catalog entry posts. Dedup already
  finds the new entries by diffing the catalog against state.
- **NVD** (``type: nvd``): a CVE posts only if it scores CVSS
  ``cvss_min`` or higher, and only if KEV does not have it (a CVE
  posted from KEV is not posted again from NVD; the other way round both
  post). The score is the one NVD lists at publish time, often the CNA's.
  CVEs that fail are dropped *without* being recorded: the publish-date
  window does not return them again, except in its 2-hour overlap, where
  they fail again. That keeps about 1,250 CVEs a day out of state.
  **Product watchlist**: a CVE below the bar still posts when its
  title or description names a watched product (case-insensitive, whole
  words) and it scores the watchlist's ``min_cvss`` or more. The item is
  marked with that product for the embed. MSRC and KEV are not affected.
- **Sources with** ``cve_filter: true`` (Microsoft MSRC): an entry posts
  only if its CVE is in KEV or scores CVSS ``cvss_min`` or higher. The
  feed has no scores, so each entry's CVE is looked up in NVD, one request
  each, paced for NVD's rate limit and capped per run. An entry that fails
  is recorded as not posted, as is one with no CVE. An entry whose lookup
  failed, found nothing yet, or did not fit under the cap is *deferred*:
  left unrecorded, so its source keeps its validators unsaved and the next
  run tries again. The flood guard records it once it is 7 days old.

"In KEV" means a ``kev:`` item in state (the whole catalog, posted or not)
or in this run's KEV items, or NVD's own KEV flag on a looked-up CVE.

The bar and the lookup cap come from the ``settings:`` section of sources.yaml
(``cvss_min``, ``cve_lookups_per_run``, ``watchlist``; defaults in
:class:`config.Settings`).
"""

from __future__ import annotations

import logging
import re
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace

from intel_feeds import dedup
from intel_feeds.config import DEFAULTS, Source, Watchlist
from intel_feeds.dedup import NewItem, Split
from intel_feeds.fetch import CveInfo, FetchError
from intel_feeds.state import State

log = logging.getLogger(__name__)

# NVD allows 50 requests per 30 s with an API key and 5 without, so a run
# without a key makes at most this many lookups, whatever the setting says.
NO_KEY_LOOKUPS = 4
LOOKUP_SPACING = {True: 0.7, False: 6.5}  # seconds between lookups

Lookup = Callable[[str], CveInfo]  # raises FetchError when NVD cannot answer

# Looked up at call time so tests can replace it.
_sleep = time.sleep


@dataclass
class Counts:
    kept: int = 0
    watched: int = 0  # NVD: of those kept, let through by the watchlist
    below: int = 0  # NVD: dropped, not recorded (below the bar or unscored)
    in_kev: int = 0  # NVD: dropped, not recorded (KEV has the CVE)
    held: int = 0  # cve_filter: recorded as not posted
    deferred: int = 0  # cve_filter: left unrecorded for the next run


@dataclass
class Report:
    counts: dict[str, Counts] = field(default_factory=dict)  # filtered sources only
    lookups: int = 0
    lookup_failures: int = 0
    cvss_min: float = DEFAULTS.cvss_min  # for the log
    watchlist_min: float = DEFAULTS.watchlist.min_cvss  # for the log
    by_product: Counter[str] = field(default_factory=Counter)  # watchlist posts

    @property
    def deferred_sources(self) -> set[str]:
        """Sources with unrecorded items: their validators must not be saved."""
        return {name for name, c in self.counts.items() if c.deferred}

    def total(self, attr: str) -> int:
        return sum(getattr(c, attr) for c in self.counts.values())


def kev_cves(state: State, splits: Mapping[str, Split], sources: Mapping[str, Source]) -> set[str]:
    """CVE IDs in the KEV catalog: every ``kev:`` ID in state, plus this run's."""
    known = {item_id[4:] for item_id in state.items if item_id.startswith("kev:")}
    for name, split in splits.items():
        if sources[name].type == "kev":
            known.update(cve for new in split.new for cve in new.item.cve_ids)
    return known


def apply(
    state: State,
    splits: Mapping[str, Split],
    sources: Mapping[str, Source],
    now,
    lookup: Lookup,
    *,
    has_key: bool,
    cvss_min: float = DEFAULTS.cvss_min,
    lookups: int = DEFAULTS.cve_lookups_per_run,
    watchlist: Watchlist = DEFAULTS.watchlist,
) -> tuple[dict[str, Split], Report]:
    """Drop, hold back or defer what must not post; return the splits that remain.

    ``lookups`` caps NVD lookups with an API key; without one the cap is
    also at most :data:`NO_KEY_LOOKUPS`.
    """
    kev = kev_cves(state, splits, sources)
    report = Report(cvss_min=cvss_min, watchlist_min=watchlist.min_cvss)
    matcher = Matcher(watchlist.products)
    limit = lookups if has_key else min(lookups, NO_KEY_LOOKUPS)
    budget = _Budget(lookup, limit, LOOKUP_SPACING[has_key], report, cvss_min)
    result: dict[str, Split] = {}
    for name, split in splits.items():
        source = sources[name]
        if source.type == "nvd":
            news, counts = _filter_nvd(split.new, kev, cvss_min, watchlist.min_cvss, matcher)
            report.by_product.update(n.item.watched for n in news if n.item.watched)
        elif source.cve_filter:
            news, counts = _filter_by_lookup(state, split.new, kev, budget, now)
        else:
            result[name] = split
            continue
        report.counts[name] = counts
        result[name] = Split(new=news, seen=split.seen, no_id=split.no_id)
    return result, report


def log_report(report: Report) -> None:
    for name, c in report.counts.items():
        parts = [f"{c.kept} kept"]
        if c.watched:
            parts[0] += f" ({c.watched} from the watchlist)"
        if c.below:
            parts.append(f"{c.below} below CVSS {report.cvss_min:g} or unscored")
        if c.in_kev:
            parts.append(f"{c.in_kev} already in KEV")
        if c.held:
            parts.append(f"{c.held} held back")
        if c.deferred:
            parts.append(f"{c.deferred} deferred to the next run")
        log.info('cve filter "%s": %s', name, ", ".join(parts))
    if report.by_product:
        log.info(
            "cve filter: watchlist let through %s (CVSS %g to %g)",
            ", ".join(f"{p} {n}" for p, n in sorted(report.by_product.items())),
            report.watchlist_min,
            report.cvss_min,
        )
    if report.lookup_failures:
        log.warning("cve filter: %d NVD lookups failed; deferred", report.lookup_failures)
    log.info(
        "cve filter: %d kept, %d dropped, %d held back, %d deferred, %d NVD lookups",
        report.total("kept"),
        report.total("below") + report.total("in_kev"),
        report.total("held"),
        report.total("deferred"),
        report.lookups,
    )


# Links in a description are not mentions: Atlassian's Jira and Bamboo CVEs
# link to release notes on confluence.atlassian.com.
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)


class Matcher:
    """Finds the first watched product a text names: case-insensitive, whole words.

    A product's words may be split by any whitespace in the text
    ("Check  Point"). URLs are ignored, and so is a name that is part of a
    dotted name like a host name ("confluence.atlassian.com"); a sentence's
    full stop still ends a word. Products are tried in list order.
    """

    def __init__(self, products: Iterable[str]):
        self._patterns = [
            (product, re.compile(
                r"(?<!\w)(?<!\w\.)"
                + r"\s+".join(map(re.escape, product.split()))
                + r"(?!\w|\.\w)",
                re.IGNORECASE,
            ))
            for product in products
        ]

    def __bool__(self) -> bool:
        return bool(self._patterns)

    def find(self, *texts: str) -> str | None:
        text = _URL.sub(" ", "\n".join(texts))
        return next((product for product, pattern in self._patterns if pattern.search(text)), None)


def _filter_nvd(
    news: Iterable[NewItem],
    kev: set[str],
    cvss_min: float,
    watch_min: float = DEFAULTS.watchlist.min_cvss,
    matcher: Matcher | None = None,
) -> tuple[list[NewItem], Counts]:
    counts = Counts()
    kept = []
    for new in news:
        item = new.item
        own = item.cve_ids[0] if item.cve_ids else None  # the parser puts it first
        if own in kev:
            counts.in_kev += 1
        elif item.cvss is not None and item.cvss >= cvss_min:
            kept.append(new)
        elif (
            matcher
            and item.cvss is not None
            and item.cvss >= watch_min
            and (product := matcher.find(item.title, item.description or item.excerpt))
        ):
            kept.append(replace(new, item=replace(item, watched=product)))
            counts.watched += 1
        else:
            counts.below += 1
    counts.kept = len(kept)
    return kept, counts


def _filter_by_lookup(
    state: State, news: list[NewItem], kev: set[str], budget: _Budget, now
) -> tuple[list[NewItem], Counts]:
    counts = Counts()
    kept = []
    # Oldest first, so a deferred entry is a newer one; undated last.
    for new in sorted(news, key=_oldest_first):
        decision = _decide(new, kev, budget)
        if isinstance(decision, NewItem):
            kept.append(decision)
        elif decision == "held":
            dedup.record(state, new, now, posted=False)
            counts.held += 1
        else:
            counts.deferred += 1
    counts.kept = len(kept)
    # Keep the feed's order (newest first) for routing.
    order = {n.id: i for i, n in enumerate(news)}
    kept.sort(key=lambda n: order[n.id])
    return kept, counts


def _oldest_first(new: NewItem):
    published = new.item.published
    return (published is None, published.timestamp() if published else 0.0)


def _decide(new: NewItem, kev: set[str], budget: _Budget) -> NewItem | str:
    cves = new.item.cve_ids
    if not cves:
        return "held"
    if any(cve in kev for cve in cves):
        return replace(new, item=replace(new.item, kev=True))
    info = budget.lookup(cves[0])
    if info is None or not info.found:
        return "deferred"
    if info.kev:
        new = replace(new, item=replace(new.item, kev=True))
    if info.cvss is not None:
        new = replace(
            new, item=replace(new.item, cvss=info.cvss, cvss_version=info.cvss_version)
        )
    if info.kev or (info.cvss is not None and info.cvss >= budget.cvss_min):
        return new
    if info.cvss is None:
        return "deferred"  # NVD has not scored it yet
    return "held"


class _Budget:
    """Paced, capped NVD lookups for one run, each CVE looked up once."""

    def __init__(
        self, lookup: Lookup, limit: int, spacing: float, report: Report, cvss_min: float
    ):
        self.cvss_min = cvss_min  # the bar _decide holds looked-up CVEs to
        self._lookup = lookup
        self._limit = limit
        self._spacing = spacing
        self._report = report
        self._cache: dict[str, CveInfo | None] = {}

    def lookup(self, cve: str) -> CveInfo | None:
        """NVD's answer, or None when it failed or the cap is reached."""
        if cve in self._cache:
            return self._cache[cve]
        if self._report.lookups >= self._limit:
            return None
        if self._report.lookups:
            _sleep(self._spacing)
        self._report.lookups += 1
        try:
            info = self._lookup(cve)
        except FetchError as exc:
            log.warning("cve filter: NVD lookup of %s failed: %s", cve, exc)
            self._report.lookup_failures += 1
            info = None
        self._cache[cve] = info
        return info
