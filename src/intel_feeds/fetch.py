"""Fetch every enabled source once per run.

Sources are fetched at the same time on a small thread pool. Each request
sends the validators saved in state (``If-None-Match`` from the ETag,
``If-Modified-Since`` from Last-Modified), so an unchanged feed answers 304
and nothing is downloaded. A source that fails (network error, timeout,
non-200 status, oversized or malformed body) becomes a ``failed`` result
and is logged; it never stops the other sources or the run.

NVD has no validators. It is queried by publish-date window instead: from
the cursor saved in state (minus an overlap, since CVEs can show up in the
API after their publish time) to now, page by page, and the pages are
merged into one JSON body shaped like a single NVD response.

ransomware.live sends no validators either; its ``/victims/recent``
(the 100 newest victims, about a day's worth) is fetched in full each run
with the PRO API key from ``RANSOMWARE_LIVE_API`` in the ``X-API-KEY``
header. Without the key the source fails at once, naming only the
variable.

This module only fetches. It does not touch state: the caller saves a
result's validators and cursor with :func:`remember` once the items from
that response are recorded. Saving them earlier would let the next run get
a 304 for items that were never recorded.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx

from intel_feeds import __version__
from intel_feeds.config import RANSOMWARE_KEY_ENV, Source
from intel_feeds.items import cvss_score
from intel_feeds.state import SourceState, State, format_time

log = logging.getLogger(__name__)

USER_AGENT = f"intel-feeds/{__version__}"
# Optional contact (a URL or email) the operator sets; some feeds and APIs
# ask automated clients for one. Added to the User-Agent as "(+<contact>)".
CONTACT_ENV = "INTEL_FEEDS_CONTACT"
CONTACT_MAX = 200


def user_agent(env: Mapping[str, str] = os.environ) -> str:
    """``intel-feeds/<version>``, plus ``(+<contact>)`` when one is set.

    A contact that is too long or holds anything but printable ASCII (a
    header could otherwise be split) is left out with a warning that does
    not repeat it.
    """
    contact = env.get(CONTACT_ENV, "").strip()
    if not contact:
        return USER_AGENT
    if len(contact) > CONTACT_MAX or not all(" " <= c <= "~" for c in contact):
        log.warning(
            "%s is ignored: use up to %d printable ASCII characters",
            CONTACT_ENV,
            CONTACT_MAX,
        )
        return USER_AGENT
    return f"{USER_AGENT} (+{contact})"

WORKERS = 8
# httpx applies this to each connect and each read, not to the whole
# request; DEADLINE caps the whole download (checked between chunks, so a
# stalled read can add up to one more TIMEOUT).
TIMEOUT = 10.0
DEADLINE = 20.0  # seconds per request
MAX_BYTES = 20_000_000  # the largest feed (MSRC) is about 3.3 MB

NVD_PAGE_SIZE = 2000  # the API's maximum
# A full page can take several seconds to start; without an API key, 7.7 s
# and one read timeout were seen from Actions (2026-11-18).
NVD_TIMEOUT = 25.0  # seconds, for each read and for the whole page
NVD_MAX_PAGES = 5
NVD_FIRST_WINDOW = timedelta(days=1)  # no cursor yet
NVD_MAX_WINDOW = timedelta(days=2)  # a longer gap is skipped, with a warning
NVD_OVERLAP = timedelta(hours=2)
NVD_KEY_ENV = "NVD_API_KEY"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 100  # CVEs per request: the API's page size
EPSS_TIMEOUT = 10.0  # seconds; EPSS is optional, so it must not hold a run up

# NVD answers a rejected request with an empty body and gives the reason in
# this response header, e.g. "Invalid apiKey.".
NVD_REASON_HEADER = "message"
RANSOMWARE_KEY_HEADER = "X-API-KEY"
REASON_MAX = 200  # characters of a server's reason kept in an error

OK = "ok"
NOT_MODIFIED = "not_modified"
FAILED = "failed"

# Looked up at call time so tests can replace it.
_clock = time.monotonic


class FetchError(Exception):
    """One source could not be fetched. The message never holds a URL."""


@dataclass
class FetchResult:
    source: Source
    status: str  # OK, NOT_MODIFIED or FAILED
    body: bytes = b""
    etag: str | None = None
    last_modified: str | None = None
    cursor: str | None = None  # NVD: the end of the window fetched
    error: str = ""
    seconds: float = 0.0


def make_client(transport: httpx.BaseTransport | None = None) -> httpx.Client:
    return httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": user_agent()},
        transport=transport,
    )


def fetch_all(
    client: httpx.Client,
    sources: Iterable[Source],
    state: State,
    now: datetime,
    env: Mapping[str, str] = os.environ,
) -> list[FetchResult]:
    """Fetch ``sources`` concurrently; results come back in the same order."""
    sources = list(sources)
    if not sources:
        return []
    with ThreadPoolExecutor(max_workers=min(WORKERS, len(sources))) as pool:
        return list(
            pool.map(
                lambda s: fetch_source(client, s, state.sources.get(s.name), now, env),
                sources,
            )
        )


def fetch_source(
    client: httpx.Client,
    source: Source,
    saved: SourceState | None,
    now: datetime,
    env: Mapping[str, str] = os.environ,
) -> FetchResult:
    started = _clock()
    try:
        if source.type == "nvd":
            result = _fetch_nvd(client, source, saved, now, env)
        elif source.type == "ransomware":
            result = _fetch_ransomware(client, source, env)
        else:
            result = _fetch_feed(client, source, saved)
    except FetchError as exc:
        result = FetchResult(source, FAILED, error=str(exc))
    except Exception as exc:  # a bug in one source's handling skips only it
        result = FetchResult(source, FAILED, error=f"unexpected error: {type(exc).__name__}")
    result.seconds = _clock() - started
    _log_result(result)
    return result


def remember(state: State, result: FetchResult) -> None:
    """Save what the next run should send: validators, and NVD's cursor.

    Only a full 200 response changes anything. Call this after the items
    from ``result`` are recorded in state, never before.
    """
    if result.status != OK:
        return
    state.set_fetch_info(
        result.source.name, result.etag, result.last_modified, cursor=result.cursor
    )


def _fetch_feed(
    client: httpx.Client, source: Source, saved: SourceState | None
) -> FetchResult:
    headers = {}
    if saved and saved.etag:
        headers["If-None-Match"] = saved.etag
    if saved and saved.last_modified:
        headers["If-Modified-Since"] = saved.last_modified
    status, body, response_headers = _get(client, source.url, headers=headers)
    if status == 304:
        return FetchResult(source, NOT_MODIFIED)
    return FetchResult(
        source,
        OK,
        body=body,
        etag=response_headers.get("etag"),
        last_modified=response_headers.get("last-modified"),
    )


def _fetch_ransomware(
    client: httpx.Client, source: Source, env: Mapping[str, str]
) -> FetchResult:
    key = env.get(RANSOMWARE_KEY_ENV, "").strip()
    if not key:
        raise FetchError(f"no API key: {RANSOMWARE_KEY_ENV} is not set")
    status, body, _ = _get(
        client,
        source.url,
        headers={RANSOMWARE_KEY_HEADER: key, "Accept": "application/json"},
    )
    if status == 304:
        raise FetchError("unexpected HTTP 304 from ransomware.live")
    return FetchResult(source, OK, body=body)


def _fetch_nvd(
    client: httpx.Client,
    source: Source,
    saved: SourceState | None,
    now: datetime,
    env: Mapping[str, str],
) -> FetchResult:
    start, end = nvd_window(saved.cursor if saved else None, now)
    headers = {}
    if env.get(NVD_KEY_ENV):
        headers["apiKey"] = env[NVD_KEY_ENV]
    vulnerabilities: list = []
    total = None
    for _ in range(NVD_MAX_PAGES):
        params = {
            "pubStartDate": _nvd_time(start),
            "pubEndDate": _nvd_time(end),
            "resultsPerPage": NVD_PAGE_SIZE,
            # Continue from what arrived, in case a page comes back short.
            "startIndex": len(vulnerabilities),
        }
        status, body, _ = _get(
            client,
            source.url,
            params=params,
            headers=headers,
            timeout=NVD_TIMEOUT,
            reason_header=NVD_REASON_HEADER,
        )
        if status == 304:
            raise FetchError("unexpected HTTP 304 from the NVD API")
        try:
            data = json.loads(body)
            total = int(data["totalResults"])
            vulnerabilities.extend(data["vulnerabilities"])
        except (ValueError, KeyError, TypeError) as exc:
            raise FetchError(f"unexpected NVD response: {type(exc).__name__}") from exc
        if len(vulnerabilities) >= total or not data["vulnerabilities"]:
            break
    else:
        raise FetchError(
            f"NVD window has {total} CVEs, more than {NVD_MAX_PAGES} pages"
        )
    merged = {
        "totalResults": total,
        "resultsPerPage": len(vulnerabilities),
        "startIndex": 0,
        "vulnerabilities": vulnerabilities,
    }
    return FetchResult(
        source, OK, body=json.dumps(merged).encode(), cursor=format_time(end)
    )


@dataclass(frozen=True)
class CveInfo:
    """What NVD says about one CVE."""

    found: bool  # NVD has the CVE
    cvss: float | None = None
    cvss_version: str | None = None
    kev: bool = False  # NVD lists a CISA KEV addition date


def lookup_cve(
    client: httpx.Client,
    cve_id: str,
    url: str = NVD_API_URL,
    env: Mapping[str, str] = os.environ,
) -> CveInfo:
    """Look up one CVE in the NVD API (one request); raise FetchError if it fails."""
    headers = {"apiKey": env[NVD_KEY_ENV]} if env.get(NVD_KEY_ENV) else {}
    status, body, _ = _get(
        client,
        url,
        params={"cveId": cve_id},
        headers=headers,
        timeout=NVD_TIMEOUT,
        reason_header=NVD_REASON_HEADER,
    )
    if status == 304:
        raise FetchError("unexpected HTTP 304 from the NVD API")
    try:
        vulns = json.loads(body)["vulnerabilities"]
        cve = vulns[0]["cve"] if vulns else None
    except (ValueError, KeyError, TypeError, IndexError) as exc:
        raise FetchError(f"unexpected NVD response: {type(exc).__name__}") from exc
    if not isinstance(cve, dict):
        return CveInfo(found=False)
    score, version = cvss_score(cve.get("metrics") or {})
    return CveInfo(True, score, version, kev=bool(cve.get("cisaExploitAdd")))


@dataclass(frozen=True)
class EpssScore:
    epss: float  # probability of exploitation in the next 30 days, 0 to 1
    percentile: float  # 0 to 1


def lookup_epss(
    client: httpx.Client, cve_ids: Iterable[str], url: str = EPSS_API_URL
) -> dict[str, EpssScore]:
    """EPSS scores from FIRST, :data:`EPSS_BATCH` CVEs a request.

    A CVE FIRST has not scored yet (new CVEs are scored once a day) is left
    out of the result. Raises FetchError if any request fails.
    """
    cves = sorted(set(cve_ids))
    scores: dict[str, EpssScore] = {}
    for start in range(0, len(cves), EPSS_BATCH):
        batch = cves[start : start + EPSS_BATCH]
        status, body, _ = _get(
            client,
            url,
            params={"cve": ",".join(batch), "limit": EPSS_BATCH},
            timeout=EPSS_TIMEOUT,
        )
        if status == 304:
            raise FetchError("unexpected HTTP 304 from the EPSS API")
        try:
            rows = json.loads(body)["data"]
            for row in rows:
                epss, percentile = float(row["epss"]), float(row["percentile"])
                if 0.0 <= epss <= 1.0 and 0.0 <= percentile <= 1.0:
                    scores[str(row["cve"]).upper()] = EpssScore(epss, percentile)
        except (ValueError, KeyError, TypeError) as exc:
            raise FetchError(f"unexpected EPSS response: {type(exc).__name__}") from exc
    return scores


def nvd_window(cursor: str | None, now: datetime) -> tuple[datetime, datetime]:
    """The publish-date window to query: cursor minus overlap, to now."""
    if cursor is None:
        return now - NVD_FIRST_WINDOW, now
    start = datetime.strptime(cursor, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    start = min(start - NVD_OVERLAP, now)
    if now - start > NVD_MAX_WINDOW:
        log.warning(
            "NVD: last fetched up to %s; skipping CVEs published before %s",
            cursor,
            format_time(now - NVD_MAX_WINDOW),
        )
        start = now - NVD_MAX_WINDOW
    return start, now


def _nvd_time(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000")


def _get(
    client: httpx.Client,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: float | None = None,
    reason_header: str | None = None,
) -> tuple[int, bytes, httpx.Headers]:
    """GET within a deadline and MAX_BYTES; return status, body, headers.

    ``timeout`` replaces both the client's read timeout and DEADLINE.
    Returns only for 200 and 304; anything else raises FetchError. For an
    error status, the ``reason_header`` response header (when given and
    present) is added to the message, cleaned by :func:`_reason`.
    """
    limit = timeout or DEADLINE
    deadline = _clock() + limit
    extra = {"timeout": httpx.Timeout(TIMEOUT, read=timeout)} if timeout else {}
    try:
        with client.stream("GET", url, params=params, headers=headers, **extra) as response:
            if response.status_code == 304:
                return 304, b"", response.headers
            if response.status_code != 200:
                error = f"HTTP {response.status_code} {response.reason_phrase}".rstrip()
                reason = _reason(response, reason_header, headers)
                raise FetchError(f"{error}: {reason}" if reason else error)
            chunks, size = [], 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_BYTES:
                    raise FetchError(f"response larger than {MAX_BYTES // 1_000_000} MB")
                if _clock() > deadline:
                    raise FetchError(f"took longer than {limit:.0f} s")
                chunks.append(chunk)
            return 200, b"".join(chunks), response.headers
    except httpx.HTTPError as exc:
        # The exception text can include the URL; the type is enough.
        raise FetchError(f"network error: {type(exc).__name__}") from exc


def _reason(
    response: httpx.Response, header: str | None, sent: dict | None
) -> str:
    """The server's reason from ``header``: one line, no secrets, clipped.

    The values of the headers we sent (the NVD API key) and the request URL
    (its query string too) are replaced with ``[redacted]`` in case the
    server echoes them back.
    """
    if not header:
        return ""
    raw = response.headers.get(header, "")
    text = " ".join("".join(c if c.isprintable() else " " for c in raw).split())
    secrets = [str(v) for v in (sent or {}).values()]
    request_url = response.request.url
    secrets += [str(request_url), str(request_url.copy_with(query=None))]
    if request_url.query:
        secrets.append(request_url.query.decode())
    for secret in sorted(filter(None, set(secrets)), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    if len(text) > REASON_MAX:
        text = text[: REASON_MAX - 1].rstrip() + "…"
    return text


def _log_result(result: FetchResult) -> None:
    name = result.source.name
    if result.status == OK:
        log.info(
            'fetch "%s": %d bytes in %.1f s', name, len(result.body), result.seconds
        )
    elif result.status == NOT_MODIFIED:
        log.info('fetch "%s": not modified (%.1f s)', name, result.seconds)
    else:
        log.warning(
            'fetch "%s": failed, skipped this run: %s', name, result.error
        )
