"""Flood guard: hold back a source's backlog and stale items.

Two rules, applied to each source's new items after dedup and before
routing:

- **New source.** A source counts as new until one run has taken in its
  backlog; ``backlog_at`` in its state entry marks that run. On that run
  the ``new_source_posts`` newest items published within
  ``max_age_days`` go on to post, and every other new item is held back.
  This covers the first run and any source added later. Being listed in
  state is not the test: a run with posting off lists every source.
- **Stale item.** On later runs, a new item published more than
  ``max_age_days`` before the run is held back. Palo Alto's feed swaps
  which of its oldest advisories it lists, so a month-old advisory can
  show up as new. Undated items are not held back: their age is unknown.

A held-back item is recorded in state as seen and not posted, so it never
posts later and its source can save its fetch validators. A source that
fails to fetch or parse is not in the splits, so it stays new until a run
parses it.

Both limits come from the ``settings:`` section of sources.yaml
(``new_source_posts``, ``max_age_days``; defaults in :class:`config.Settings`).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from intel_feeds import dedup
from intel_feeds.config import DEFAULTS
from intel_feeds.dedup import NewItem, Split
from intel_feeds.state import State, format_time

log = logging.getLogger(__name__)



@dataclass
class Held:
    backlog: int = 0  # new source: everything but its newest few
    stale: int = 0  # published more than max_age before the run


@dataclass
class Report:
    held: dict[str, Held] = field(default_factory=dict)  # by source name
    new_sources: list[str] = field(default_factory=list)  # backlog taken in this run
    max_age: timedelta = DEFAULTS.max_age  # for the log

    @property
    def backlog(self) -> int:
        return sum(h.backlog for h in self.held.values())

    @property
    def stale(self) -> int:
        return sum(h.stale for h in self.held.values())


def apply(
    state: State,
    splits: Mapping[str, Split],
    now: datetime,
    *,
    new_source_posts: int | None = None,
    max_age: timedelta | None = None,
) -> tuple[dict[str, Split], Report]:
    """Hold back what must not post; return the splits that remain.

    Held items are recorded with ``posted=False`` and dropped from the
    returned splits; the ``seen`` and ``no_id`` counts are kept. Pass
    ``new_source_posts=0`` to hold a new source's whole backlog (posting
    switched off). Unset limits use the defaults in :data:`config.DEFAULTS`.
    """
    if new_source_posts is None:
        new_source_posts = DEFAULTS.new_source_posts
    if max_age is None:
        max_age = DEFAULTS.max_age
    cutoff = now - max_age
    report = Report(max_age=max_age)
    kept: dict[str, Split] = {}
    for name, split in splits.items():
        source_state = state.sources[name]
        held = Held()
        if source_state.backlog_at is None:
            allowed = _newest(split.new, cutoff, new_source_posts)
            keep = [n for n in split.new if n.id in allowed]
            hold = [n for n in split.new if n.id not in allowed]
            held.backlog = len(hold)
            source_state.backlog_at = format_time(now)
            report.new_sources.append(name)
        else:
            keep = [n for n in split.new if not _stale(n, cutoff)]
            hold = [n for n in split.new if _stale(n, cutoff)]
            held.stale = len(hold)
        for new in hold:
            dedup.record(state, new, now, posted=False)
        report.held[name] = held
        kept[name] = Split(new=keep, seen=split.seen, no_id=split.no_id)
    return kept, report


def log_report(report: Report) -> None:
    for name, held in report.held.items():
        if name in report.new_sources:
            log.info('guard "%s": new source, held back %d', name, held.backlog)
        elif held.stale:
            log.info(
                'guard "%s": held back %d published more than %d days ago',
                name,
                held.stale,
                report.max_age.days,
            )
    log.info(
        "flood guard: held back %d (new source), %d (older than %d days)",
        report.backlog,
        report.stale,
        report.max_age.days,
    )


def _newest(news: list[NewItem], cutoff: datetime, count: int) -> set[str]:
    """IDs of the ``count`` newest dated items published after ``cutoff``."""
    recent = [n for n in news if n.item.published is not None and n.item.published >= cutoff]
    recent.sort(key=lambda n: n.item.published, reverse=True)  # stable: ties keep feed order
    return {n.id for n in recent[:count]}


def _stale(new: NewItem, cutoff: datetime) -> bool:
    return new.item.published is not None and new.item.published < cutoff
