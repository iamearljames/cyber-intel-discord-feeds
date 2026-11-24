"""Load and save ``state.json``: what earlier runs fetched and posted.

The file's path comes from ``--state`` or ``INTEL_FEEDS_STATE`` (in Docker,
``/data/state.json`` on a volume). This module only reads and writes that
path.

Schema (version 1)::

    {
      "version": 1,
      "sources": {
        "<source name>": {
          "first_seen": "2026-11-18T09:30:00Z",
          "etag": null,
          "last_modified": null,
          "cursor": null,
          "backlog_at": null,
          "failing_since": null,
          "failures": null,
          "alerted_at": null
        }
      },
      "items": {
        "<item id>": {
          "source": "<source name>",
          "first_seen": "2026-11-18T09:30:00Z",
          "published_at": "2026-11-18T09:12:00Z",
          "posted_at": null,
          "url": "https://example.com/story"
        }
      }
    }

Sources are keyed by name, so renaming a source in ``sources.yaml`` makes it
look new. ``etag`` and ``last_modified`` are the validators to send on the
next conditional request; ``cursor`` is where the next date-window query
starts (NVD only). ``backlog_at`` is when the flood guard took in the
source's backlog; null means the source is still new to it. ``failing_since``, ``failures`` (a whole
number) and ``alerted_at`` track a source that keeps failing (see
:mod:`intel_feeds.health`); all three are null while it works. Items are keyed by the ID from ``dedup``; ``url`` is the
item's canonical URL when it is checked for duplicates and differs from the
ID, else null. Older files without ``cursor``, ``backlog_at``, ``url`` or
the health fields still load. Times
are UTC ISO 8601 strings ending in ``Z``.

The file is written with sorted keys and fixed indentation, and only when its
content changed, so a run that learns nothing new leaves it byte-for-byte
the same (easy to back up or diff). Nothing in it changes just
because a run happened: no "last run" or "last success" time. Only a
failing source's ``failures`` count changes on every run while it fails.

Items are pruned once they were first seen more than
:data:`KEEP_FOR` ago and no feed lists them any more; see
:meth:`State.prune`.

A missing file is an empty state (the first run). A file that cannot be read
or does not match the schema raises :class:`StateError` instead of being
treated as empty, because starting over would repost every item.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from intel_feeds.config import DEFAULTS

VERSION = 1
# How long an item is kept after it was first seen, once no feed lists it
#: ``keep_days`` in the sources.yaml settings. Validation keeps it well
# above the flood guard's ``max_age_days``: an item pruned and then listed
# again must count as stale there, or it would post again.
KEEP_FOR = DEFAULTS.keep_for  # the default


class StateError(Exception):
    """The state file exists but cannot be used."""


@dataclass
class SourceState:
    first_seen: str
    etag: str | None = None
    last_modified: str | None = None
    cursor: str | None = None
    backlog_at: str | None = None  # flood guard: backlog taken in
    # Source health: the current run of failures, null while it works.
    failing_since: str | None = None
    failures: int | None = None
    alerted_at: str | None = None


@dataclass
class ItemState:
    source: str
    first_seen: str
    published_at: str | None = None
    posted_at: str | None = None
    url: str | None = None


@dataclass
class State:
    sources: dict[str, SourceState] = field(default_factory=dict)
    items: dict[str, ItemState] = field(default_factory=dict)

    def add_sources(self, names: list[str], now: datetime) -> list[str]:
        """Record sources not seen before; return the names that were new."""
        added = []
        for name in names:
            if name not in self.sources:
                self.sources[name] = SourceState(first_seen=format_time(now))
                added.append(name)
        return added

    def set_fetch_info(
        self,
        source: str,
        etag: str | None,
        last_modified: str | None,
        cursor: str | None = None,
    ) -> None:
        """Remember what the next fetch of ``source`` should send."""
        entry = self.sources[source]
        entry.etag = etag
        entry.last_modified = last_modified
        entry.cursor = cursor

    def seen(self, item_id: str) -> bool:
        return item_id in self.items

    def mark_seen(
        self,
        item_id: str,
        source: str,
        now: datetime,
        published_at: datetime | None = None,
        url: str | None = None,
    ) -> None:
        """Record an item the first time it is seen; later calls do nothing."""
        if item_id in self.items:
            return
        self.items[item_id] = ItemState(
            source=source,
            first_seen=format_time(now),
            published_at=format_time(published_at) if published_at else None,
            url=url,
        )

    def mark_posted(self, item_id: str, now: datetime) -> None:
        self.items[item_id].posted_at = format_time(now)

    def prune(
        self,
        now: datetime,
        *,
        listed: Collection[str],
        parsed: Collection[str],
        active: Collection[str],
        keep_for: timedelta | None = None,
    ) -> int:
        """Drop old items no feed lists any more; return how many went.

        An item first seen more than ``keep_for`` (default :data:`KEEP_FOR`)
        before ``now`` is dropped when:

        - its source was parsed this run (``parsed``) and neither its ID
          nor its URL is among the IDs and URLs the run's feeds listed
          (``listed``), or
        - its source is no longer an enabled source (``active``): disabled,
          removed or renamed in ``sources.yaml``.

        Items a feed still lists are kept at any age. Feeds such as CISA KEV
        and MSRC list every entry they ever published; dropping those would
        make them look new again each time the feed changes. Items of a
        source that answered 304 or failed this run are kept until a run
        parses it.
        """
        cutoff = format_time(now - (KEEP_FOR if keep_for is None else keep_for))
        gone = [
            item_id
            for item_id, item in self.items.items()
            if item.first_seen < cutoff  # same format, so text order is time order
            and (
                item.source not in active
                or (
                    item.source in parsed
                    and item_id not in listed
                    and not (item.url and item.url in listed)
                )
            )
        ]
        for item_id in gone:
            del self.items[item_id]
        return len(gone)

    def to_dict(self) -> dict:
        return {
            "version": VERSION,
            "sources": {name: vars(s) for name, s in self.sources.items()},
            "items": {item_id: vars(i) for item_id, i in self.items.items()},
        }


def format_time(moment: datetime) -> str:
    """UTC, whole seconds, ``Z`` suffix. Naive datetimes are taken as UTC."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_state(path: str | os.PathLike[str]) -> State:
    """Read ``path``; a missing file is an empty state."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return State()
    except (OSError, UnicodeDecodeError) as exc:
        raise StateError(f"{path}: cannot read: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise StateError(
            f"{path}:{exc.lineno}: not valid JSON: {exc.msg}"
        ) from exc
    return _parse(path, data)


def dumps(state: State) -> str:
    return json.dumps(state.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def save_state(path: str | os.PathLike[str], state: State) -> bool:
    """Write ``state`` to ``path`` atomically; return False if nothing changed.

    Writes a temporary file in the same folder and renames it over ``path``,
    so a crash mid-write never leaves a half-written state file.
    """
    path = Path(path)
    text = dumps(state)
    try:
        if path.read_text(encoding="utf-8") == text:
            return False
    except (FileNotFoundError, UnicodeDecodeError):
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return True


def _parse(path: Path, data: object) -> State:
    def fail(problem: str) -> StateError:
        return StateError(f"{path}: {problem}")

    if not isinstance(data, dict):
        raise fail("expected a JSON object at the top level")
    version = data.get("version")
    if version != VERSION:
        raise fail(f"unsupported version {version!r} (this job reads version {VERSION})")
    unknown = sorted(set(data) - {"version", "sources", "items"})
    if unknown:
        raise fail(f"unknown top-level field {unknown[0]!r}")

    sources = _section(data, "sources", fail)
    items = _section(data, "items", fail)
    state = State()
    for name, entry in sources.items():
        state.sources[name] = _record(
            SourceState, entry, f'source "{name}"', fail,
            required={"first_seen"},
            optional={
                "etag", "last_modified", "cursor", "backlog_at",
                "failing_since", "failures", "alerted_at",
            },
            counts={"failures"},
        )
    for item_id, entry in items.items():
        state.items[item_id] = _record(
            ItemState, entry, f'item "{item_id}"', fail,
            required={"source", "first_seen"}, optional={"published_at", "posted_at", "url"},
        )
    return state


def _section(data: dict, key: str, fail) -> dict:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise fail(f'"{key}" must be an object')
    return value


def _record(
    cls, entry: object, label: str, fail, *, required: set, optional: set, counts: set = frozenset()
):
    if not isinstance(entry, dict):
        raise fail(f"{label}: must be an object")
    missing = sorted(required - set(entry))
    if missing:
        raise fail(f"{label}: missing {missing[0]!r}")
    unknown = sorted(set(entry) - required - optional)
    if unknown:
        raise fail(f"{label}: unknown field {unknown[0]!r}")
    for key, value in entry.items():
        if key in counts:
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise fail(f"{label}: {key!r} must be a whole number or null")
            continue
        allowed = (str,) if key in required else (str, type(None))
        if not isinstance(value, allowed):
            raise fail(f"{label}: {key!r} must be text")
    return cls(**entry)
