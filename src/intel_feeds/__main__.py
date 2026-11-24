"""Command-line entry point: ``python -m intel_feeds``."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
import traceback
from datetime import UTC, datetime

from intel_feeds import (
    __version__,
    cvefilter,
    dedup,
    embeds,
    enrich,
    fetch,
    guard,
    health,
    items,
    route,
    schedule,
    summary,
    webhook,
)
from intel_feeds.config import (
    ConfigError,
    Settings,
    Source,
    key_warnings,
    load_config,
    webhook_warnings,
)
from intel_feeds.envfile import load_env_file
from intel_feeds.state import StateError, load_state, save_state

log = logging.getLogger("intel_feeds")

EXIT_OK = 0
EXIT_POST_FAILED = 1
EXIT_CONFIG_ERROR = 2
EXIT_STATE_ERROR = 3
EXIT_CRASHED = 4  # an unexpected error; the traceback is in the log

# Where state lives when --state is not given; the Docker image sets it to
# /data/state.json. Read after the .env file is loaded, so it can sit there.
STATE_ENV = "INTEL_FEEDS_STATE"
DEFAULT_STATE = "state.json"

# On since the CVE filter. Set it to False to stop posting without
# stopping runs: the flood guard then records each new source's whole
# backlog as not posted, and a run logs what it would post without
# recording it.
POSTING_ENABLED = True

# Looked up at call time so tests can replace it.
_clock = time.monotonic


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="intel_feeds",
        description=(
            "Fetch the configured cybersecurity feeds and post new items "
            "to Discord through webhooks."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="log debug messages"
    )
    parser.add_argument(
        "--config",
        default="sources.yaml",
        metavar="PATH",
        help="sources file to read (default: sources.yaml)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate the sources file, report any problems, and exit",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        metavar="PATH",
        help=(
            "local file of webhook variables, if it exists (default: .env); "
            "variables already set in the environment win"
        ),
    )
    parser.add_argument(
        "--test-post",
        action="store_true",
        help="post one sample embed to each webhook that is set, and exit",
    )
    parser.add_argument(
        "--state",
        default=None,
        metavar="PATH",
        help=(
            f"state file to read and update (default: ${STATE_ENV}, "
            f"else {DEFAULT_STATE})"
        ),
    )
    parser.add_argument(
        "--every",
        metavar="INTERVAL",
        help=(
            "keep running: one run now, then one every INTERVAL on the clock "
            f"(15m, 1h; default: ${schedule.INTERVAL_ENV}, else run once and exit)"
        ),
    )
    parser.add_argument(
        "--health",
        action="store_true",
        help=(
            "exit 0 if a run worked within two intervals plus 5 minutes, else 1 "
            "(for a container healthcheck)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    names, env_warnings = load_env_file(args.env_file)
    for warning in env_warnings:
        log.warning(warning)
    if names:
        log.debug("loaded %d variables from %s", len(names), args.env_file)

    if args.check_config or args.test_post:
        config = _load_config(args.config)
        if config is None:
            return EXIT_CONFIG_ERROR
        if args.check_config:
            enabled = sum(1 for s in config.sources if s.enabled)
            print(f"{args.config}: OK, {len(config.sources)} sources ({enabled} enabled)")
            return EXIT_OK
        return _test_post(config.settings, config.sources)

    every = args.every or os.environ.get(schedule.INTERVAL_ENV, "").strip()
    interval = schedule.DEFAULT_INTERVAL
    if every:
        try:
            interval = schedule.parse_interval(every)
        except schedule.IntervalError as exc:
            print(f"Schedule problem: {exc}", file=sys.stderr)
            return EXIT_CONFIG_ERROR
    if args.health:
        state_path = args.state or os.environ.get(STATE_ENV) or DEFAULT_STATE
        ok, why = schedule.health(schedule.status_path(state_path), interval, datetime.now(UTC))
        print(f"{'healthy' if ok else 'unhealthy'}: {why}")
        return EXIT_OK if ok else 1
    if not every:
        return _scheduled_run(args)
    return schedule.loop(lambda: _scheduled_run(args), interval)


def _load_config(path: str):
    """The checked config with its warnings logged, or None after printing why."""
    try:
        config = load_config(path)
    except ConfigError as exc:
        count = len(exc.errors)
        print(
            f"Config check failed with {count} problem{'s' if count != 1 else ''}:",
            file=sys.stderr,
        )
        for error in exc.errors:
            print(f"  {error}", file=sys.stderr)
        return None
    for warning in webhook_warnings(config.sources, settings=config.settings) + key_warnings(
        config.sources
    ):
        log.warning(warning)
    return config


def _scheduled_run(args) -> int:
    """One run under the run lock, with its outcome saved and alerted.

    ``sources.yaml`` is read on every run, so an edit takes effect on the
    next run without a restart.
    """
    started = _clock()
    state_path = args.state or os.environ.get(STATE_ENV) or DEFAULT_STATE
    lock = schedule.lock_path(state_path)
    with schedule.run_lock(lock) as mine:
        if not mine:
            log.info("run: another run holds %s; skipping this one", lock.name)
            return EXIT_OK
        detail = ""
        try:
            exit_code = _config_and_run(args.config, state_path, started)
        except Exception as exc:
            # The type and the frames only: an exception's message can hold a URL.
            log.error(
                "run: crashed with %s\n%s",
                type(exc).__name__,
                "".join(traceback.format_tb(exc.__traceback__)).rstrip(),
            )
            exit_code, detail = EXIT_CRASHED, type(exc).__name__
        schedule.record(
            schedule.status_path(state_path),
            exit_code,
            datetime.now(UTC),
            detail=detail,
            posting=POSTING_ENABLED,
        )
    return exit_code


def _config_and_run(config_path: str, state_path: str, started: float) -> int:
    config = _load_config(config_path)
    if config is None:
        return EXIT_CONFIG_ERROR
    enabled = sum(1 for s in config.sources if s.enabled)
    log.info(
        "intel_feeds %s: loaded %d sources (%d enabled)",
        __version__,
        len(config.sources),
        enabled,
    )
    return _run(config.sources, config.settings, state_path, started)


def _run(sources, settings: Settings, state_path: str, started: float) -> int:
    """Load state, fetch every enabled source, save state if it changed.

    Ends with the per-run summary; ``started`` is when ``main`` began.
    """
    try:
        state = load_state(state_path)
    except StateError as exc:
        print(f"State file problem: {exc}", file=sys.stderr)
        print(
            "Fix or remove the file; it is not "
            "replaced automatically because starting empty would repost items.",
            file=sys.stderr,
        )
        return EXIT_STATE_ERROR
    log.info(
        "state: %d sources, %d items from %s",
        len(state.sources),
        len(state.items),
        state_path,
    )

    now = datetime.now(UTC)
    enabled = [s for s in sources if s.enabled]
    added = state.add_sources([s.name for s in enabled], now)
    for name in added:
        log.info('state: new source "%s"', name)
    tally = summary.Summary(s.name for s in enabled)

    with fetch.make_client() as client:
        results = fetch.fetch_all(client, enabled, state, now)
    for result in results:
        tally.fetched(result.source.name, result.status, result.seconds)
    counts = {
        status: sum(1 for r in results if r.status == status)
        for status in (fetch.OK, fetch.NOT_MODIFIED, fetch.FAILED)
    }
    log.info(
        "fetch: %d fetched, %d not modified, %d failed",
        counts[fetch.OK],
        counts[fetch.NOT_MODIFIED],
        counts[fetch.FAILED],
    )
    parse_errors: dict[str, str] = {}
    parsed = _parse(results, tally, parse_errors)
    log.info(
        "parse: %d items from %d sources, %d sources failed",
        sum(len(p.items) for p in parsed.values()),
        len(parsed),
        counts[fetch.OK] - len(parsed),
    )
    splits = _dedup(state, enabled, parsed)
    tally.new({name: len(split.new) for name, split in splits.items()})
    exit_code = _route_and_post(state, enabled, settings, results, parsed, splits, now, tally)
    if not _health(state, results, parse_errors, now):
        exit_code = EXIT_POST_FAILED
    _prune(state, enabled, parsed, now, settings)

    try:
        changed = save_state(state_path, state)
    except OSError as exc:
        print(f"State file problem: {state_path}: cannot write: {exc}", file=sys.stderr)
        return EXIT_STATE_ERROR
    log.info("state: %s", "saved" if changed else "unchanged, not written")
    run_seconds = _clock() - started
    tally.log(run_seconds)
    return exit_code


def _route_and_post(
    state,
    sources,
    settings: Settings,
    results,
    parsed,
    splits,
    now: datetime,
    tally: summary.Summary,
) -> int:
    """Post new items to their channels, then save each finished source's validators.

    The flood guard and the CVE filter first take out what
    must not post. An item goes into state only once it is posted, or
    deliberately held back by either, through dedup.record. Items the
    filter defers stay unrecorded, and so does an NVD CVE it drops. Validators and
    the NVD cursor (fetch.remember) are saved per source only after all its
    new items are recorded: saving them first would turn the next fetch
    into a 304 for items that were never recorded.
    """
    splits, held = guard.apply(
        state,
        splits,
        now,
        new_source_posts=settings.new_source_posts if POSTING_ENABLED else 0,
        max_age=settings.max_age,
    )
    guard.log_report(held)
    tally.filtered({name: h.backlog + h.stale for name, h in held.held.items()})
    splits, filtered = _filter(state, sources, splits, now, settings)
    tally.filtered(
        {name: c.below + c.in_kev + c.held for name, c in filtered.counts.items()}
    )
    routing = route.plan(
        splits,
        os.environ,
        cap=settings.posts_per_channel,
        caps=settings.channel_caps,
        webhooks=settings.webhooks,
        group_min=settings.watchlist.group_min,
    )
    if not POSTING_ENABLED:
        route.log_plan(routing)
        # Sources left with nothing to post are fully recorded.
        done = {name for name, split in splits.items() if not split.new}
        _remember(results, done - filtered.deferred_sources, state)
        log.info(
            "post: posting is switched off; %d items not posted or recorded",
            routing.count() + routing.overflow() + sum(len(r.items) for r in routing.unrouted),
        )
        return EXIT_OK
    _enrich(routing, sources, settings, filtered)
    with webhook.make_client() as client:
        report = route.post(
            client,
            routing,
            state,
            now,
            os.environ,
            sources={s.name: s for s in sources},
        )
    _remember(results, set(parsed) - report.incomplete - filtered.deferred_sources, state)
    tally.posted(report.posted_by)
    tally.failed_posts(report.failed_by)
    log.info(
        "post: %d posted, %d failed, %d over the per-channel cap, %d kept for a missing webhook",
        report.posted,
        report.failed,
        report.overflow,
        report.unrouted,
    )
    return EXIT_POST_FAILED if report.failed else EXIT_OK


def _nvd_url(sources) -> str:
    return next((s.url for s in sources if s.type == "nvd"), fetch.NVD_API_URL)


def _enrich(routing: route.Plan, sources, settings: Settings, filtered) -> None:
    """Add EPSS and missing CVSS scores to the CVE posts going out."""
    has_key = bool(os.environ.get(fetch.NVD_KEY_ENV))
    limit = settings.cve_lookups_per_run
    if not has_key:
        limit = min(limit, cvefilter.NO_KEY_LOOKUPS)
    nvd_url = _nvd_url(sources)
    with fetch.make_client() as client:
        report = enrich.apply(
            (r.items for r in routing.routes),
            {s.name: s for s in sources},
            epss=lambda cves: fetch.lookup_epss(client, cves),
            cvss=lambda cve: fetch.lookup_cve(client, cve, nvd_url),
            lookups=max(0, limit - filtered.lookups),
            spacing=cvefilter.LOOKUP_SPACING[has_key],
            spaced=filtered.lookups > 0,
        )
    enrich.log_report(report)


def _filter(state, sources, splits, now: datetime, settings: Settings):
    """Apply the CVE filter, looking scores up in NVD with one shared client."""
    by_name = {s.name: s for s in sources}
    nvd_url = _nvd_url(sources)
    with fetch.make_client() as client:
        splits, report = cvefilter.apply(
            state,
            splits,
            by_name,
            now,
            lambda cve: fetch.lookup_cve(client, cve, nvd_url),
            has_key=bool(os.environ.get(fetch.NVD_KEY_ENV)),
            cvss_min=settings.cvss_min,
            lookups=settings.cve_lookups_per_run,
            watchlist=settings.watchlist,
        )
    cvefilter.log_report(report)
    return splits, report


def _health(state, results, parse_errors: dict[str, str], now: datetime) -> bool:
    """Track each source's failures and alert the ops channel.

    Returns False when an alert failed to post (a missing ops webhook is
    only a warning).
    """
    outcomes = {
        result.source.name: (
            result.error or "fetch failed"
            if result.status == fetch.FAILED
            else parse_errors.get(result.source.name)
        )
        for result in results
    }
    alerts = health.check(state, outcomes, now)
    if not POSTING_ENABLED:
        health.log_alerts(alerts)
        return True
    with webhook.make_client() as client:
        report = health.send(client, alerts, state, now, os.environ)
    return not report.failed


def _prune(
    state, sources, parsed: dict[str, items.Parsed], now: datetime, settings: Settings
) -> None:
    """Drop items first seen over keep_days ago that no feed lists any more."""
    by_name = {s.name: s for s in sources}
    listed = set()
    for name, result in parsed.items():
        listed |= dedup.listed(by_name[name], result.items)
    pruned = state.prune(
        now,
        listed=listed,
        parsed=set(parsed),
        active=set(by_name),
        keep_for=settings.keep_for,
    )
    log.info(
        "state: pruned %d items first seen more than %d days ago that no feed lists",
        pruned,
        settings.keep_days,
    )


def _remember(results, names: set[str], state) -> None:
    """Save validators and the NVD cursor for the named (finished) sources."""
    for result in results:
        if result.source.name in names:
            fetch.remember(state, result)


def _parse(
    results: list[fetch.FetchResult],
    tally: summary.Summary,
    errors: dict[str, str] | None = None,
) -> dict[str, items.Parsed]:
    """Parse each fetched body; a source that cannot be parsed is skipped.

    Each skipped source's reason goes into ``errors`` (for source health).
    """
    if errors is None:
        errors = {}
    parsed = {}
    for result in results:
        if result.status != fetch.OK:
            continue
        name = result.source.name
        started = _clock()
        try:
            parsed[name] = items.parse(result.source, result.body)
        except items.ParseError as exc:
            log.warning('parse "%s": failed, skipped this run: %s', name, exc)
            errors[name] = f"parse failed: {exc}"
            tally.parse_failed(name, _clock() - started)
            continue
        except Exception as exc:  # a bug in one parser skips only that source
            log.warning(
                'parse "%s": failed, skipped this run: unexpected error: %s',
                name,
                type(exc).__name__,
            )
            errors[name] = f"parse failed: unexpected error: {type(exc).__name__}"
            tally.parse_failed(name, _clock() - started)
            continue
        tally.parsed(name, len(parsed[name].items), _clock() - started)
        skipped = parsed[name].skipped
        log.info(
            'parse "%s": %d items%s',
            name,
            len(parsed[name].items),
            f", {skipped} unusable entries skipped" if skipped else "",
        )
    return parsed


def _dedup(state, sources, parsed: dict[str, items.Parsed]) -> dict[str, dedup.Split]:
    """Split each source's items into new and already seen."""
    by_name = {s.name: s for s in sources}
    checker = dedup.Dedup(state)
    splits = {}
    for name, result in parsed.items():
        split = checker.split(by_name[name], result.items)
        splits[name] = split
        log.info(
            'dedup "%s": %d new, %d already seen%s',
            name,
            len(split.new),
            split.seen,
            f", {split.no_id} without a GUID or URL skipped" if split.no_id else "",
        )
    log.info(
        "dedup: %d new, %d already seen",
        sum(len(s.new) for s in splits.values()),
        sum(s.seen for s in splits.values()),
    )
    return splits


def _test_post(settings: Settings, sources: list[Source]) -> int:
    """Post a sample embed per set webhook; non-zero unless every one posted.

    The ransomware channel gets a made-up victim, drawn as a real one would
    be, with the ransomware source's name and icon when one is configured.
    """
    source = next((s for s in sources if s.type == "ransomware"), None)
    with webhook.make_client() as client:
        samples = {"ransomware": embeds.sample_victim_embed(source, datetime.now(UTC))}
        results = webhook.send_test_posts(client, os.environ, settings.webhooks, samples)
    for variable, outcome in results:
        print(f"{variable}: {outcome}")
    posted = sum(1 for _, outcome in results if outcome == "posted")
    failed = sum(1 for _, outcome in results if outcome.startswith("failed"))
    print(f"Test post: {posted} posted, {failed} failed")
    if failed or not posted:
        if not posted and not failed:
            print("No webhook variables are set; see .env.example", file=sys.stderr)
        return EXIT_POST_FAILED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
