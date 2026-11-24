"""Run the job on a schedule, one run at a time, and alert when runs fail.

In a container there is no systemd timer, so ``--every 15m`` (or
``INTEL_FEEDS_INTERVAL``) keeps the process running: one run at start, then
one at each slot aligned to the clock (``15m`` runs at :00, :15, :30 and
:45 UTC). A run that takes longer than the interval skips the slots it
missed instead of running them back to back.

One run at a time: each run holds an exclusive lock on ``<state>.lock``. A
run that finds it taken (another container, or a manual
``docker compose run``) skips its turn and exits 0.

Stopping: the first SIGTERM or SIGINT lets the current run finish, then the
loop exits 0. A second one abandons the run at once; state saves are atomic
(a temporary file renamed over the old one), so nothing is corrupted.

Run status lives in ``<state stem>.status.json`` beside the state file,
not in ``state.json``, which changes only when a run learns something::

    {
      "version": 1,
      "last_run_at": "2026-11-24T10:15:00Z",
      "last_exit": 0,
      "last_ok_at": "2026-11-24T10:15:00Z",
      "failing_since": null,
      "failures": null,
      "alerted_at": null
    }

The first failed run of a streak posts one "Runs failing" alert to
``WEBHOOK_OPS``; the first run that works again posts "Runs working again".
An alert that cannot be posted is tried again on the next run. Alerts name
the exit code and, for a crash, the exception's type, never its message
(it could hold a URL).
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import re
import signal
import tempfile
import threading
from collections.abc import Callable, Iterator, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from intel_feeds import __version__, webhook
from intel_feeds.state import format_time

log = logging.getLogger(__name__)

INTERVAL_ENV = "INTEL_FEEDS_INTERVAL"
MIN_INTERVAL = timedelta(minutes=1)
MAX_INTERVAL = timedelta(hours=24)
STATUS_VERSION = 1

EXIT_MEANINGS = {
    1: "a post or an alert could not be sent",
    2: "sources.yaml has a problem",
    3: "the state file could not be read or written",
    4: "the run crashed",
}

_UNITS = {"s": 1, "m": 60, "h": 3600}
_INTERVAL = re.compile(r"(\d+)\s*([smh])")


class IntervalError(ValueError):
    pass


def parse_interval(text: str) -> timedelta:
    """``90s``, ``15m``, ``1h`` or combinations like ``1h30m``; 1 min to 24 h."""
    compact = text.strip().lower().replace(" ", "")
    parts = _INTERVAL.findall(compact)
    if not compact or "".join(n + u for n, u in parts) != compact:
        raise IntervalError(
            f"interval {text!r} is not valid: use a number with s, m or h, like 15m or 1h"
        )
    interval = timedelta(seconds=sum(int(n) * _UNITS[u] for n, u in parts))
    if not MIN_INTERVAL <= interval <= MAX_INTERVAL:
        raise IntervalError(f"interval {text!r} must be between 1m and 24h")
    return interval


def next_slot(now: datetime, interval: timedelta) -> datetime:
    """The first slot after ``now`` on the grid of ``interval`` since the epoch."""
    step = interval.total_seconds()
    return datetime.fromtimestamp((now.timestamp() // step + 1) * step, UTC)


def lock_path(state_path: str | os.PathLike) -> Path:
    path = Path(state_path)
    return path.with_name(path.name + ".lock")


def status_path(state_path: str | os.PathLike) -> Path:
    path = Path(state_path)
    return path.with_name(path.stem + ".status.json")


@contextlib.contextmanager
def run_lock(path: Path) -> Iterator[bool]:
    """Hold an exclusive lock on ``path``; yields False if another run has it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


@dataclass
class Status:
    last_run_at: str | None = None
    last_exit: int | None = None
    last_ok_at: str | None = None
    failing_since: str | None = None
    failures: int | None = None
    alerted_at: str | None = None


def load_status(path: Path) -> Status:
    """The saved status, or a fresh one if the file is missing or unreadable."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return Status()
    except (OSError, ValueError) as exc:
        log.warning("status: %s is unreadable (%s); starting fresh", path.name, type(exc).__name__)
        return Status()
    if not isinstance(data, dict):
        return Status()
    known = Status.__dataclass_fields__
    return Status(**{k: v for k, v in data.items() if k in known})


def save_status(path: Path, status: Status) -> None:
    text = json.dumps({"version": STATUS_VERSION, **asdict(status)}, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def record(
    path: Path,
    exit_code: int,
    now: datetime,
    *,
    detail: str = "",
    env: Mapping[str, str] = os.environ,
    posting: bool = True,
    client_factory: Callable[[], httpx.Client] | None = None,
) -> Status:
    """Save this run's outcome and post a failing or recovery alert if due."""
    status = load_status(path)
    stamp = format_time(now)
    status.last_run_at, status.last_exit = stamp, exit_code
    alert = None
    if exit_code == 0:
        status.last_ok_at = stamp
        if status.alerted_at:
            alert = _recovered(status, now)
        else:
            status.failing_since = status.failures = None
    else:
        status.failing_since = status.failing_since or stamp
        status.failures = (status.failures or 0) + 1
        if not status.alerted_at:
            alert = _failing(status, exit_code, detail, now)

    # An alert that is not sent leaves the streak as it is, so the next run
    # tries again.
    if alert and _send(alert, env, posting, client_factory):
        if exit_code == 0:
            status.failing_since = status.failures = status.alerted_at = None
        else:
            status.alerted_at = stamp

    try:
        save_status(path, status)
    except OSError as exc:
        log.warning("status: cannot write %s: %s", path.name, type(exc).__name__)
    return status


def _failing(status: Status, exit_code: int, detail: str, now: datetime) -> dict:
    meaning = EXIT_MEANINGS.get(exit_code, "unknown error")
    runs = status.failures or 1
    excerpt = f"Exit code {exit_code}: {meaning}"
    if detail:
        excerpt += f" ({detail})"
    excerpt += (
        f". Failing since {_show(status.failing_since)}"
        f" ({runs} failed run{'' if runs == 1 else 's'} in a row). See the container log."
    )
    return _embed("Runs failing", excerpt, now)


def _recovered(status: Status, now: datetime) -> dict:
    runs = status.failures or 0
    excerpt = (
        f"Working again. Runs had been failing since {_show(status.failing_since)}"
        f" ({runs} failed run{'' if runs == 1 else 's'})."
    )
    return _embed("Runs working again", excerpt, now)


def _embed(title: str, excerpt: str, now: datetime) -> dict:
    return webhook.build_embed(
        title=title,
        category="ops",
        source=f"intel-feeds {__version__} · runs",
        published=now,
        excerpt=excerpt,
    )


def _send(alert: dict, env: Mapping[str, str], posting: bool, client_factory) -> bool:
    title = alert.get("title", "alert")
    if not posting:
        log.info('status: would post "%s" (posting is off)', title)
        return False
    url = env.get(webhook.OPS_ENV, "").strip()
    if not url:
        log.warning('status: "%s" not sent: %s is not set', title, webhook.OPS_ENV)
        return False
    try:
        with (client_factory or webhook.make_client)() as client:
            webhook.post_embed(client, url, alert, label=webhook.OPS_ENV)
    except webhook.WebhookError as exc:
        log.warning('status: "%s" not sent: %s', title, exc)
        return False
    log.info('status: "%s" posted to %s', title, webhook.OPS_ENV)
    return True


DEFAULT_INTERVAL = timedelta(minutes=15)
HEALTH_SLACK = timedelta(minutes=5)


def health(path: Path, interval: timedelta, now: datetime) -> tuple[bool, str]:
    """Healthy if a run worked within two intervals plus five minutes.

    For a container healthcheck: no status file yet (before the first run
    finishes) or only failing runs since then counts as unhealthy.
    """
    status = load_status(path)
    if not status.last_ok_at:
        return False, f"no working run recorded in {path.name} yet"
    try:
        last_ok = datetime.strptime(status.last_ok_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (TypeError, ValueError):
        return False, f"{path.name} has an unreadable last_ok_at"
    age = now - last_ok
    limit = 2 * interval + HEALTH_SLACK
    minutes = int(age.total_seconds() // 60)
    if age > limit:
        return False, f"last working run {minutes} min ago, over the {int(limit.total_seconds() // 60)} min limit"
    return True, f"last working run {minutes} min ago"


def _show(stamp: str | None) -> str:
    if not stamp:
        return "unknown"
    return stamp.replace("T", " ").removesuffix("Z") + " UTC"


def loop(
    run: Callable[[], int],
    interval: timedelta,
    *,
    stop: threading.Event | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    handle_signals: bool = True,
) -> int:
    """Call ``run`` now and at every slot after, until a stop signal."""
    stop = stop or threading.Event()
    restore = _install_signals(stop) if handle_signals else {}
    log.info("schedule: every %s, starting now", _show_interval(interval))
    try:
        while not stop.is_set():
            run()
            if stop.is_set():
                break
            slot = next_slot(now(), interval)
            log.info("schedule: next run at %s", slot.strftime("%Y-%m-%d %H:%M:%S UTC"))
            while not stop.is_set():
                left = (slot - now()).total_seconds()
                if left <= 0:
                    break
                stop.wait(min(left, 60.0))
    finally:
        for signum, handler in restore.items():
            signal.signal(signum, handler)
    log.info("schedule: stopped")
    return 0


def _install_signals(stop: threading.Event) -> dict:
    def handler(signum, frame):
        if stop.is_set():
            log.warning("schedule: second %s, stopping now", signal.Signals(signum).name)
            raise SystemExit(128 + signum)
        log.info(
            "schedule: %s received, stopping after the current run (send it again to stop now)",
            signal.Signals(signum).name,
        )
        stop.set()

    restore = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        restore[signum] = signal.getsignal(signum)
        signal.signal(signum, handler)
    return restore


def _show_interval(interval: timedelta) -> str:
    seconds = int(interval.total_seconds())
    for unit, size in (("h", 3600), ("m", 60)):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"
