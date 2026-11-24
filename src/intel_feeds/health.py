"""Source health: alert the ops channel when a source stays broken.

Each run reports every enabled source as working (fetched and parsed, or
answered 304) or failed (the fetch or the parse failed). State keeps, per
source, when its current run of failures began (``failing_since``), how
many runs in a row failed (``failures``) and when the ops channel was told
(``alerted_at``). A working source has all three null, so a healthy run
changes nothing in state.

Once a source has been failing for :data:`ALERT_AFTER` (24 hours), one
"source down" alert goes to the ops channel (``WEBHOOK_OPS``). When it
works again, one "source back" alert follows and its health fields are
cleared. A source that recovers before the alert was sent recovers quietly.

An alert that cannot be posted (no ops webhook, or Discord refused it)
leaves state as it was, so the next run tries again: the down alert while
the source still fails, the recovery once it works. Disabled or removed
sources are not checked.

Alerts never hold a URL: fetch and parse errors are written without one.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx

from intel_feeds import __version__, webhook
from intel_feeds.state import State, format_time

log = logging.getLogger(__name__)

ALERT_AFTER = timedelta(hours=24)
DOWN = "down"
UP = "up"


@dataclass(frozen=True)
class Alert:
    source: str
    kind: str  # DOWN or UP
    failing_since: str
    failures: int
    error: str = ""  # the latest error, for a down alert


@dataclass
class Report:
    posted: int = 0
    failed: int = 0
    unsent: int = 0  # no ops webhook set


def check(
    state: State,
    outcomes: Mapping[str, str | None],
    now: datetime,
    *,
    alert_after: timedelta = ALERT_AFTER,
) -> list[Alert]:
    """Update each source's health from this run; return the alerts due.

    ``outcomes`` maps each enabled source to its error this run, or None
    when it worked. Every name must already be in ``state.sources``.
    """
    alerts = []
    for name, error in outcomes.items():
        entry = state.sources[name]
        if error is None:
            if entry.failing_since is None:
                continue
            if entry.alerted_at is not None:
                alerts.append(Alert(name, UP, entry.failing_since, entry.failures or 0))
                continue  # cleared once the recovery is posted
            log.info(
                'health "%s": working again after %d failed runs; no alert was sent',
                name,
                entry.failures or 0,
            )
            entry.failing_since = entry.failures = None
            continue
        if entry.failing_since is None:
            entry.failing_since = format_time(now)
            entry.failures = 0
        entry.failures = (entry.failures or 0) + 1
        log.warning(
            'health "%s": failing since %s (%d runs in a row)',
            name,
            entry.failing_since,
            entry.failures,
        )
        if entry.alerted_at is None and now - parse_time(entry.failing_since) >= alert_after:
            alerts.append(Alert(name, DOWN, entry.failing_since, entry.failures, error))
    return alerts


def send(
    client: httpx.Client,
    alerts: list[Alert],
    state: State,
    now: datetime,
    env: Mapping[str, str],
) -> Report:
    """Post each alert to the ops channel and record the ones that went out."""
    report = Report()
    if not alerts:
        return report
    url = env.get(webhook.OPS_ENV, "").strip()
    if not url:
        report.unsent = len(alerts)
        log.warning(
            "health: %d alert%s not sent: %s is not set (%s)",
            len(alerts),
            "" if len(alerts) == 1 else "s",
            webhook.OPS_ENV,
            ", ".join(f'"{a.source}" {a.kind}' for a in alerts),
        )
        return report
    for alert in alerts:
        try:
            webhook.post_embed(client, url, embed(alert, now), label=webhook.OPS_ENV)
        except webhook.WebhookError as exc:
            report.failed += 1
            log.warning('health "%s": %s alert not sent: %s', alert.source, alert.kind, exc)
            continue
        report.posted += 1
        entry = state.sources[alert.source]
        if alert.kind == DOWN:
            entry.alerted_at = format_time(now)
        else:
            entry.failing_since = entry.failures = entry.alerted_at = None
        log.info('health "%s": %s alert posted', alert.source, alert.kind)
    return report


def log_alerts(alerts: list[Alert]) -> None:
    """With posting off: say which alerts would go out."""
    for alert in alerts:
        log.info('health "%s": would post a %s alert (posting is off)', alert.source, alert.kind)


def embed(alert: Alert, now: datetime) -> dict:
    since = _show(alert.failing_since)
    runs = f"{alert.failures} failed run{'' if alert.failures == 1 else 's'}"
    if alert.kind == DOWN:
        title = f"Source down: {alert.source}"
        excerpt = f"Failing since {since} ({runs} in a row)."
        if alert.error:
            excerpt += f" Last error: {alert.error}"
    else:
        title = f"Source back: {alert.source}"
        excerpt = f"Working again. It had been failing since {since} ({runs})."
    return webhook.build_embed(
        title=title,
        category="ops",
        source=f"intel-feeds {__version__} · source health",
        published=now,
        excerpt=excerpt,
    )


def parse_time(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _show(text: str) -> str:
    return parse_time(text).strftime("%Y-%m-%d %H:%M UTC")
