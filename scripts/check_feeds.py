#!/usr/bin/env python3
"""Fetch every enabled source once and report whether it works.

    python scripts/check_feeds.py                     # all enabled sources
    python scripts/check_feeds.py --source "Unit 42"  # just one (repeatable)
    python scripts/check_feeds.py --save-fixtures tests/fixtures

For each source it prints the HTTP status, the format found in the body (not
the Content-Type header, which some feeds get wrong), the item count, the
newest item's date, the response size, and whether the server sends ETag and
Last-Modified for conditional requests.

Exits 0 when every checked source returned at least one item, 1 otherwise.
It never sends webhook requests and never reads webhook variables. A
ransomware source sends the ``RANSOMWARE_LIVE_API`` key (never printed); the
checker does not load ``.env``, so export the key first.

``--save-fixtures DIR`` writes one sample response per source type and feed
format (the smallest one seen) for offline parser tests. The KEV catalog and
the ransomware.live victims are cut down to their 5 newest entries (the
ransomware.live ``client`` field is blanked); the NVD query already asks for
5 CVEs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import feedparser
import httpx

from intel_feeds import __version__
from intel_feeds.config import RANSOMWARE_KEY_ENV, ConfigError, Source, load_sources

TIMEOUT = 30.0
USER_AGENT = f"intel-feeds/{__version__} (feed checker)"
NVD_WINDOW = timedelta(days=1)
NVD_PAGE = 5
KEV_SAMPLE = 5
RANSOMWARE_SAMPLE = 5


@dataclass
class Result:
    source: Source
    status: str = "-"
    format: str = "-"
    items: int = 0
    newest: datetime | None = None
    size: int = 0
    etag: bool = False
    last_modified: bool = False
    content_type: str = ""
    problem: str = ""
    body: bytes = b""

    @property
    def ok(self) -> bool:
        return not self.problem and self.items > 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", default="sources.yaml", metavar="PATH")
    parser.add_argument(
        "--source", action="append", default=[], metavar="NAME",
        help="check only this source (repeatable); disabled sources too",
    )
    parser.add_argument("--save-fixtures", metavar="DIR", help="write sample responses here")
    args = parser.parse_args(argv)

    try:
        sources = load_sources(args.config)
    except ConfigError as exc:
        print("Config check failed:", *exc.errors, sep="\n  ", file=sys.stderr)
        return 2

    if args.source:
        wanted = {name.casefold() for name in args.source}
        chosen = [s for s in sources if s.name.casefold() in wanted]
        missing = wanted - {s.name.casefold() for s in chosen}
        if missing:
            print(f"No source named: {', '.join(sorted(missing))}", file=sys.stderr)
            return 2
    else:
        chosen = [s for s in sources if s.enabled]

    now = datetime.now(UTC)
    with make_client() as client:
        results = [check(client, source, now) for source in chosen]

    print_table(results, now)
    if args.save_fixtures:
        save_fixtures(results, Path(args.save_fixtures))
    failed = [r for r in results if not r.ok]
    print(f"\n{len(results) - len(failed)} of {len(results)} sources returned items")
    return 1 if failed else 0


def make_client(transport: httpx.BaseTransport | None = None) -> httpx.Client:
    return httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
        transport=transport,
    )


def check(client: httpx.Client, source: Source, now: datetime) -> Result:
    result = Result(source)
    url, params, headers = source.url, None, {}
    if source.type == "nvd":
        params = {
            "pubStartDate": _nvd_time(now - NVD_WINDOW),
            "pubEndDate": _nvd_time(now),
            "resultsPerPage": NVD_PAGE,
        }
        if os.environ.get("NVD_API_KEY"):
            headers["apiKey"] = os.environ["NVD_API_KEY"]
    elif source.type == "ransomware":
        if not os.environ.get(RANSOMWARE_KEY_ENV):
            result.problem = f"no API key: {RANSOMWARE_KEY_ENV} is not set"
            return result
        headers["X-API-KEY"] = os.environ[RANSOMWARE_KEY_ENV]
    started = time.monotonic()
    try:
        response = client.get(url, params=params, headers=headers)
    except httpx.HTTPError as exc:
        # The exception text can include the URL; the type is enough here.
        result.problem = f"network error: {type(exc).__name__}"
        return result
    result.status = str(response.status_code)
    result.body = response.content
    result.size = len(response.content)
    result.etag = "etag" in response.headers
    result.last_modified = "last-modified" in response.headers
    result.content_type = response.headers.get("content-type", "").split(";")[0]
    if response.status_code != 200:
        result.problem = f"HTTP {response.status_code} {response.reason_phrase}"
        return result
    try:
        if source.type == "kev":
            _check_kev(result)
        elif source.type == "nvd":
            _check_nvd(result)
        elif source.type == "ransomware":
            _check_ransomware(result)
        else:
            _check_rss(result)
    except (ValueError, KeyError, TypeError) as exc:
        result.problem = f"unexpected body: {exc}"
    result.problem = result.problem or ("" if result.items else "no items")
    elapsed = time.monotonic() - started
    if elapsed > 10:
        print(f"note: {source.name} took {elapsed:.1f} s", file=sys.stderr)
    return result


def _check_rss(result: Result) -> None:
    head = result.body.lstrip()[:200].lower()
    if head.startswith(b"{") or head.startswith(b"["):
        result.format = "json"
        result.problem = "JSON body for an rss source"
        return
    feed = feedparser.parse(result.body)
    result.format = feed.version or "unknown"
    if not feed.version:
        result.problem = "not an RSS or Atom feed (HTML page?)"
        return
    result.items = len(feed.entries)
    dates = [
        datetime(*parsed[:6], tzinfo=UTC)
        for entry in feed.entries
        if (parsed := entry.get("published_parsed") or entry.get("updated_parsed"))
    ]
    result.newest = max(dates, default=None)
    if feed.entries and not dates:
        result.problem = "items have no parseable dates"


def _check_kev(result: Result) -> None:
    data = json.loads(result.body)
    result.format = "json (kev)"
    vulns = data["vulnerabilities"]
    result.items = len(vulns)
    result.newest = max(
        (datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=UTC) for v in vulns),
        default=None,
    )


def _check_nvd(result: Result) -> None:
    data = json.loads(result.body)
    result.format = "json (nvd)"
    result.items = int(data["totalResults"])
    published = [
        datetime.fromisoformat(v["cve"]["published"]).replace(tzinfo=UTC)
        for v in data["vulnerabilities"]
    ]
    result.newest = max(published, default=None)


def _check_ransomware(result: Result) -> None:
    data = json.loads(result.body)
    result.format = "json (ransomware)"
    victims = data["victims"]
    result.items = len(victims)
    result.newest = max(
        (datetime.fromisoformat(v["discovered"]) for v in victims if v.get("discovered")),
        default=None,
    )


def _nvd_time(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000")


def print_table(results: list[Result], now: datetime) -> None:
    rows = [("source", "type", "http", "format", "items", "newest", "size", "etag", "last-mod", "problem")]
    for r in results:
        rows.append((
            r.source.name,
            r.source.type,
            r.status,
            r.format,
            str(r.items) + ("/day" if r.source.type == "nvd" and r.status == "200" else ""),
            _age(r.newest, now),
            _size(r.size),
            "yes" if r.etag else "no",
            "yes" if r.last_modified else "no",
            r.problem or "ok",
        ))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for row in rows:
        print("  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip())


def _age(moment: datetime | None, now: datetime) -> str:
    if moment is None:
        return "-"
    hours = (now - moment).total_seconds() / 3600
    ago = f"{hours:.0f} h ago" if hours < 48 else f"{hours / 24:.0f} d ago"
    return f"{moment:%Y-%m-%d} ({ago})"


def _size(size: int) -> str:
    return f"{size / 1_000_000:.1f} MB" if size >= 995_000 else f"{size / 1000:.0f} kB"


def save_fixtures(results: list[Result], folder: Path) -> None:
    """One fixture per (type, format), the smallest working response of each."""
    folder.mkdir(parents=True, exist_ok=True)
    best: dict[tuple[str, str], Result] = {}
    for r in results:
        if not r.ok:
            continue
        key = (r.source.type, r.format)
        if key not in best or r.size < best[key].size:
            best[key] = r
    for (kind, fmt), r in sorted(best.items()):
        body = r.body
        if kind == "kev":
            body = _trim_kev(body)
            name = "kev.json"
        elif kind == "nvd":
            body = json.dumps(json.loads(body), indent=2).encode() + b"\n"
            name = "nvd.json"
        elif kind == "ransomware":
            body = _trim_ransomware(body)
            name = "ransomware_live.json"
        else:
            name = f"{fmt}_{_slug(r.source.name)}.xml"
        (folder / name).write_bytes(body)
        print(f"saved {folder / name} ({_size(len(body))}) from {r.source.name}")


def _trim_kev(body: bytes) -> bytes:
    data = json.loads(body)
    newest = sorted(data["vulnerabilities"], key=lambda v: v["dateAdded"], reverse=True)
    data["vulnerabilities"] = newest[:KEV_SAMPLE]
    data["count"] = len(data["vulnerabilities"])
    return json.dumps(data, indent=2).encode() + b"\n"


def _trim_ransomware(body: bytes) -> bytes:
    data = json.loads(body)
    newest = sorted(data["victims"], key=lambda v: v.get("discovered") or "", reverse=True)
    data["victims"] = newest[:RANSOMWARE_SAMPLE]
    data["count"] = len(data["victims"])
    data["client"] = "example"  # may identify the API account
    return json.dumps(data, indent=2, ensure_ascii=False).encode() + b"\n"


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


if __name__ == "__main__":
    sys.exit(main())
