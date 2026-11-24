"""Add EPSS scores, and a missing CVSS score, to CVE posts before they go out.

Runs after routing, on the items this run will post (within each
channel's cap), so nothing is looked up for an item that waits.

A CVE post is an item from a CVE source (``type: kev``, ``type: nvd``, or
``cve_filter: true`` such as MSRC); its CVE is the first in its
``cve_ids`` (the parsers put the item's own CVE first). Other posts (news,
vendor advisories naming several CVEs) are left as they are.

- **EPSS**: every CVE post's CVE goes into one batched request to FIRST's
  EPSS API. A CVE that FIRST has not scored yet (new CVEs are scored once
  a day) posts without one.
- **CVSS**: a CVE post with no score yet (KEV additions, whose catalog has
  none, and MSRC entries that passed the filter because KEV has their CVE)
  gets NVD's score through one lookup each, oldest first, within what the
  CVE filter left of ``cve_lookups_per_run`` and paced like its lookups.
  A CVE NVD has not scored posts without one.

Enrichment never stops a post: a failed EPSS request or NVD lookup is
logged and the item posts without that score.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace

from intel_feeds.config import Source
from intel_feeds.dedup import NewItem
from intel_feeds.fetch import CveInfo, EpssScore, FetchError

log = logging.getLogger(__name__)

EpssLookup = Callable[[list[str]], Mapping[str, EpssScore]]  # raises FetchError
CvssLookup = Callable[[str], CveInfo]  # raises FetchError

# Looked up at call time so tests can replace it.
_sleep = time.sleep


@dataclass
class Report:
    cves: int = 0  # CVE posts this run
    epss: int = 0  # of those, with an EPSS score
    epss_failed: bool = False
    lookups: int = 0  # NVD lookups for a missing CVSS score
    lookup_failures: int = 0
    cvss_added: int = 0
    no_budget: int = 0  # missing a CVSS score, not looked up (cap reached)


def own_cve(new: NewItem, source: Source | None) -> str | None:
    """The CVE a CVE post is about, or None for any other item."""
    if source is None or not new.item.cve_ids:
        return None
    if source.type in ("kev", "nvd") or source.cve_filter:
        return new.item.cve_ids[0]
    return None


def apply(
    batches: Iterable[list[NewItem]],
    sources: Mapping[str, Source],
    *,
    epss: EpssLookup,
    cvss: CvssLookup,
    lookups: int,
    spacing: float,
    spaced: bool = False,
) -> Report:
    """Enrich each CVE post in ``batches`` in place (each list is a route's items).

    ``lookups`` is how many NVD lookups are left this run; ``spacing`` the
    seconds between two of them, and ``spaced`` says one was just made
    (by the CVE filter), so the first here waits too.
    """
    batches = list(batches)
    report = Report()
    targets = [
        (batch, index, cve)
        for batch in batches
        for index, new in enumerate(batch)
        if (cve := own_cve(new, sources.get(new.item.source)))
    ]
    report.cves = len(targets)
    if not targets:
        return report

    try:
        scores = epss([cve for _, _, cve in targets])
    except FetchError as exc:
        log.warning("enrich: EPSS lookup failed, posting without EPSS scores: %s", exc)
        report.epss_failed = True
        scores = {}

    found: dict[str, CveInfo | None] = {}
    for batch, index, cve in targets:
        item = batch[index].item
        score = scores.get(cve)
        if score is not None:
            item = replace(item, epss=score.epss, epss_percentile=score.percentile)
            report.epss += 1
        if item.cvss is None:
            if cve not in found:
                if report.lookups >= lookups:
                    report.no_budget += 1
                    batch[index] = replace(batch[index], item=item)
                    continue
                if spaced or report.lookups:
                    _sleep(spacing)
                report.lookups += 1
                try:
                    found[cve] = cvss(cve)
                except FetchError as exc:
                    log.warning("enrich: NVD lookup of %s failed: %s", cve, exc)
                    report.lookup_failures += 1
                    found[cve] = None
            info = found[cve]
            if info is not None and info.cvss is not None:
                item = replace(item, cvss=info.cvss, cvss_version=info.cvss_version)
                report.cvss_added += 1
        batch[index] = replace(batch[index], item=item)
    return report


def log_report(report: Report) -> None:
    if not report.cves:
        return
    parts = [f"EPSS for {report.epss} of {report.cves} CVE posts"]
    if report.epss_failed:
        parts[0] += " (EPSS lookup failed)"
    if report.lookups or report.no_budget:
        parts.append(
            f"CVSS added to {report.cvss_added} from {report.lookups} NVD lookups"
        )
    if report.no_budget:
        parts.append(f"{report.no_budget} without a CVSS score over the lookup cap")
    log.info("enrich: %s", ", ".join(parts))
