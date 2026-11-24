"""Per-run summary: one table of what each source did, and the run time.

Each stage of a run reports into a :class:`Summary` as it goes; the run
logs it at the end as one table, one line per enabled source plus a total:

- ``fetch``: ``ok``, ``not modified`` (HTTP 304) or ``failed``
- ``items``: entries parsed from the response (0 unless fetched in full)
- ``new``: items dedup had not seen before
- ``filtered``: new items held back by the flood guard or dropped or held
  back by the CVE filter
- ``posted``: new items posted to Discord
- ``left``: new items left for the next run (CVE filter deferrals, over the
  per-channel cap, no webhook, a failed post, or posting switched off), so
  ``new = filtered + posted + left``
- ``errors``: a failed fetch or parse counts 1, plus each failed post
- ``seconds``: fetch plus parse time for that source. Sources are fetched
  at the same time, so these add up to more than the run time.

NVD CVEs below the CVSS bar are not recorded, so they count as new (and
filtered) again on each run while they stay in the query window.

The run time is measured from the start of ``main`` to the end of the run.
A run over :data:`RUN_BUDGET` logs a warning: most runs take well under
it, so a slower one usually means a source is slow or a big backlog came in.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

log = logging.getLogger(__name__)

RUN_BUDGET = 60.0  # seconds; see the module docstring

FETCH_LABELS = {"ok": "ok", "not_modified": "not modified", "failed": "failed"}


@dataclass
class Row:
    source: str
    fetch: str = "-"
    items: int = 0
    new: int = 0
    filtered: int = 0
    posted: int = 0
    errors: int = 0
    seconds: float = 0.0

    @property
    def left(self) -> int:
        return self.new - self.filtered - self.posted


COUNTS = ("items", "new", "filtered", "posted", "left", "errors")


class Summary:
    """Collects one :class:`Row` per enabled source, in config order."""

    def __init__(self, names: Iterable[str]):
        self.rows: dict[str, Row] = {name: Row(name) for name in names}

    def _row(self, name: str) -> Row:
        # A name the run did not list up front still gets a row.
        return self.rows.setdefault(name, Row(name))

    def fetched(self, name: str, status: str, seconds: float) -> None:
        row = self._row(name)
        row.fetch = FETCH_LABELS.get(status, status)
        row.seconds += seconds
        row.errors += status == "failed"

    def parsed(self, name: str, items: int, seconds: float) -> None:
        row = self._row(name)
        row.items = items
        row.seconds += seconds

    def parse_failed(self, name: str, seconds: float) -> None:
        row = self._row(name)
        row.fetch = "parse failed"
        row.seconds += seconds
        row.errors += 1

    def new(self, counts: Mapping[str, int]) -> None:
        for name, count in counts.items():
            self._row(name).new += count

    def filtered(self, counts: Mapping[str, int]) -> None:
        for name, count in counts.items():
            self._row(name).filtered += count

    def posted(self, counts: Mapping[str, int]) -> None:
        for name, count in counts.items():
            self._row(name).posted += count

    def failed_posts(self, counts: Mapping[str, int]) -> None:
        for name, count in counts.items():
            self._row(name).errors += count

    def total(self) -> dict[str, int]:
        rows = self.rows.values()
        return {attr: sum(getattr(r, attr) for r in rows) for attr in COUNTS}

    def table(self) -> list[str]:
        """The summary as aligned text lines: a header, the sources, the total."""
        header = ["source", "fetch", *COUNTS, "seconds"]
        body = [
            [r.source, r.fetch, *(str(getattr(r, a)) for a in COUNTS), f"{r.seconds:.1f}"]
            for r in self.rows.values()
        ]
        total = self.total()
        body.append(["total", "", *(str(total[a]) for a in COUNTS), ""])
        widths = [max(len(line[i]) for line in [header, *body]) for i in range(len(header))]

        def render(cells: list[str]) -> str:
            text = [cells[0].ljust(widths[0]), cells[1].ljust(widths[1])]
            text += [c.rjust(w) for c, w in zip(cells[2:], widths[2:])]
            return "  ".join(text).rstrip()

        return [render(header), *(render(line) for line in body)]

    def log(self, run_seconds: float) -> None:
        for line in self.table():
            log.info("summary: %s", line)
        total = self.total()
        log.info(
            "run: finished in %.1f s; %d new, %d filtered, %d posted, %d left, %d errors",
            run_seconds,
            total["new"],
            total["filtered"],
            total["posted"],
            total["left"],
            total["errors"],
        )
        if run_seconds > RUN_BUDGET:
            log.warning(
                "run: took %.1f s, over the %.0f s budget",
                run_seconds,
                RUN_BUDGET,
            )
