"""The built-in scheduler: interval, run lock, run status alerts, stop signals."""

import json
import logging
import os
import signal
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from intel_feeds import __main__ as cli
from intel_feeds import schedule, webhook
from intel_feeds.__main__ import main

OPS = "https://discord.invalid/api/webhooks/9/ops-secret-token"
NOW = datetime(2026, 11, 24, 10, 7, 30, tzinfo=UTC)
GOOD_CONFIG = """\
sources:
  - name: Feed
    url: https://feeds.example.com/a.xml
    type: rss
    category: news
"""


class Ops:
    """A fake ops channel; ``status`` is its answer to each post."""

    def __init__(self, status=204):
        self.status = status
        self.posts = []

    def client(self):
        def handler(request):
            assert request.url.path.endswith("ops-secret-token")
            self.posts.append(json.loads(request.content)["embeds"][0])
            return httpx.Response(self.status)

        return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def info_logs(caplog):
    caplog.set_level(logging.INFO)


@pytest.fixture
def ops(monkeypatch):
    fake = Ops()
    monkeypatch.setattr(webhook, "make_client", lambda transport=None: fake.client())
    monkeypatch.setenv(webhook.OPS_ENV, OPS)
    return fake


@pytest.fixture
def config(tmp_path):
    path = tmp_path / "sources.yaml"
    path.write_text(GOOD_CONFIG)
    return path


# --- interval ---------------------------------------------------------------


@pytest.mark.parametrize(
    "text, seconds",
    [("15m", 900), ("1h", 3600), ("90s", 90), ("1h30m", 5400), (" 15M ", 900), ("24h", 86400), ("1m", 60)],
)
def test_intervals(text, seconds):
    assert schedule.parse_interval(text) == timedelta(seconds=seconds)


@pytest.mark.parametrize("text", ["", "15", "m", "15 minutes", "-5m", "1.5h", "15m!", "59s", "25h"])
def test_bad_intervals(text):
    with pytest.raises(schedule.IntervalError):
        schedule.parse_interval(text)


def test_slots_line_up_with_the_clock():
    every = timedelta(minutes=15)
    assert schedule.next_slot(NOW, every) == datetime(2026, 11, 24, 10, 15, tzinfo=UTC)
    on_the_dot = datetime(2026, 11, 24, 10, 15, tzinfo=UTC)
    assert schedule.next_slot(on_the_dot, every) == datetime(2026, 11, 24, 10, 30, tzinfo=UTC)
    assert schedule.next_slot(NOW, timedelta(hours=1)) == datetime(2026, 11, 24, 11, 0, tzinfo=UTC)


def test_lock_and_status_sit_beside_the_state_file(tmp_path):
    state = tmp_path / "data" / "state.json"
    assert schedule.lock_path(state) == tmp_path / "data" / "state.json.lock"
    assert schedule.status_path(state) == tmp_path / "data" / "state.status.json"


def test_a_bad_interval_stops_before_any_run(config, tmp_path, capsys):
    assert main(["--config", str(config), "--every", "soon"]) == cli.EXIT_CONFIG_ERROR
    assert "Schedule problem" in capsys.readouterr().err
    assert not (tmp_path / "state.json").exists()


def test_interval_from_the_environment_starts_the_loop(config, monkeypatch):
    seen = {}

    def fake_loop(run, interval, **kwargs):
        seen["interval"] = interval
        return 0

    monkeypatch.setattr(schedule, "loop", fake_loop)
    monkeypatch.setenv(schedule.INTERVAL_ENV, "30m")
    assert main(["--config", str(config)]) == 0
    assert seen["interval"] == timedelta(minutes=30)


# --- run lock ---------------------------------------------------------------


def test_a_run_skips_while_another_holds_the_lock(config, tmp_path, caplog):
    state = tmp_path / "state.json"
    with schedule.run_lock(schedule.lock_path(state)) as mine:
        assert mine
        assert main(["--config", str(config), "--state", str(state)]) == 0
    assert "another run holds state.json.lock; skipping" in caplog.text
    assert not state.exists()
    assert not schedule.status_path(state).exists()


def test_the_lock_is_free_again_after_a_run(config, tmp_path):
    state = tmp_path / "state.json"
    assert main(["--config", str(config), "--state", str(state)]) == 0
    with schedule.run_lock(schedule.lock_path(state)) as mine:
        assert mine


# --- run status and alerts --------------------------------------------------


def status_of(path):
    return json.loads(path.read_text())


def test_a_working_run_records_its_time(config, tmp_path):
    state = tmp_path / "state.json"
    assert main(["--config", str(config), "--state", str(state)]) == 0
    status = status_of(schedule.status_path(state))
    assert status["version"] == 1
    assert status["last_exit"] == 0
    assert status["last_ok_at"] == status["last_run_at"]
    assert status["failing_since"] is None and status["alerted_at"] is None


def test_failing_runs_alert_once_and_recovery_once(ops, tmp_path):
    path = tmp_path / "state.status.json"
    schedule.record(path, 2, NOW)
    schedule.record(path, 2, NOW + timedelta(minutes=15))
    schedule.record(path, 3, NOW + timedelta(minutes=30))
    assert [p["title"] for p in ops.posts] == ["Runs failing"]
    assert "Exit code 2: sources.yaml has a problem" in ops.posts[0]["description"]
    assert "Failing since 2026-11-24 10:07:30 UTC (1 failed run in a row)" in ops.posts[0]["description"]
    assert ops.posts[0]["color"] == webhook.COLORS["ops"]
    status = status_of(path)
    assert status["failures"] == 3 and status["alerted_at"] == "2026-11-24T10:07:30Z"

    schedule.record(path, 0, NOW + timedelta(minutes=45))
    schedule.record(path, 0, NOW + timedelta(hours=1))
    assert [p["title"] for p in ops.posts] == ["Runs failing", "Runs working again"]
    assert "(3 failed runs)" in ops.posts[1]["description"]
    status = status_of(path)
    assert status["failing_since"] is None and status["failures"] is None
    assert status["alerted_at"] is None and status["last_ok_at"] == "2026-11-24T11:07:30Z"


def test_a_working_run_without_an_alert_sends_nothing(ops, tmp_path):
    path = tmp_path / "state.status.json"
    schedule.record(path, 0, NOW)
    assert ops.posts == []


def test_an_unsent_alert_is_tried_on_the_next_failing_run(ops, tmp_path, caplog):
    path = tmp_path / "state.status.json"
    ops.status = 400
    schedule.record(path, 1, NOW)
    assert status_of(path)["alerted_at"] is None
    assert '"Runs failing" not sent' in caplog.text
    assert "ops-secret-token" not in caplog.text
    ops.status = 204
    schedule.record(path, 1, NOW + timedelta(minutes=15))
    assert status_of(path)["alerted_at"] == "2026-11-24T10:22:30Z"
    assert "(2 failed runs in a row)" in ops.posts[-1]["description"]


def test_an_unsent_recovery_is_tried_on_the_next_run(ops, tmp_path):
    path = tmp_path / "state.status.json"
    schedule.record(path, 1, NOW)
    ops.status = 400
    schedule.record(path, 0, NOW + timedelta(minutes=15))
    assert status_of(path)["alerted_at"] is not None
    ops.status = 204
    schedule.record(path, 0, NOW + timedelta(minutes=30))
    assert ops.posts[-1]["title"] == "Runs working again"
    assert status_of(path)["alerted_at"] is None


def test_no_ops_webhook_only_warns(tmp_path, caplog):
    path = tmp_path / "state.status.json"
    schedule.record(path, 1, NOW)
    assert '"Runs failing" not sent: WEBHOOK_OPS is not set' in caplog.text
    assert status_of(path)["failures"] == 1


def test_posting_off_only_logs(ops, tmp_path, caplog):
    schedule.record(tmp_path / "state.status.json", 1, NOW, posting=False)
    assert ops.posts == []
    assert 'would post "Runs failing" (posting is off)' in caplog.text


def test_an_unreadable_status_file_starts_fresh(tmp_path, caplog):
    path = tmp_path / "state.status.json"
    path.write_text("{not json")
    schedule.record(path, 0, NOW)
    assert "unreadable (JSONDecodeError); starting fresh" in caplog.text
    assert status_of(path)["last_exit"] == 0


def test_a_config_error_in_a_run_alerts(ops, tmp_path):
    bad = tmp_path / "sources.yaml"
    bad.write_text("sources: nope\n")
    state = tmp_path / "state.json"
    assert main(["--config", str(bad), "--state", str(state)]) == cli.EXIT_CONFIG_ERROR
    assert [p["title"] for p in ops.posts] == ["Runs failing"]
    assert status_of(schedule.status_path(state))["last_exit"] == 2


def test_a_crash_alerts_with_the_type_never_the_message(ops, config, tmp_path, monkeypatch, caplog):
    secret = "https://discord.invalid/api/webhooks/1/news-secret-token"

    def crash(*args):
        raise RuntimeError(f"boom while posting to {secret}")

    monkeypatch.setattr(cli, "_run", crash)
    state = tmp_path / "state.json"
    assert main(["--config", str(config), "--state", str(state)]) == cli.EXIT_CRASHED
    assert "run: crashed with RuntimeError" in caplog.text
    assert "in crash" in caplog.text  # the frames are logged
    assert secret not in caplog.text
    [alert] = ops.posts
    assert "Exit code 4: the run crashed (RuntimeError)" in alert["description"]
    assert secret not in json.dumps(alert)
    assert status_of(schedule.status_path(state))["last_exit"] == 4


def test_check_config_and_test_post_take_no_lock_and_write_no_status(config, tmp_path):
    assert main(["--check-config", "--config", str(config)]) == 0
    assert not (tmp_path / "state.json.lock").exists()
    assert not (tmp_path / "state.status.json").exists()


# --- the loop ---------------------------------------------------------------


class FakeClock:
    """``now`` jumps to whatever the test sets; ``Event.wait`` moves it on."""

    def __init__(self, start):
        self.time = start

    def now(self):
        return self.time


def test_loop_runs_now_then_at_each_slot_until_stopped(caplog):
    clock = FakeClock(NOW)
    stop = threading.Event()
    runs = []
    real_wait = stop.wait

    def wait(seconds):
        clock.time += timedelta(seconds=seconds)
        return real_wait(0)

    stop.wait = wait

    def run():
        runs.append(clock.time)
        clock.time += timedelta(seconds=20)  # a run takes 20 s
        if len(runs) == 3:
            stop.set()
        return 0

    assert schedule.loop(run, timedelta(minutes=15), stop=stop, now=clock.now, handle_signals=False) == 0
    assert runs[0] == NOW
    assert runs[1] == datetime(2026, 11, 24, 10, 15, tzinfo=UTC)
    assert runs[2] == datetime(2026, 11, 24, 10, 30, tzinfo=UTC)
    assert "schedule: next run at 2026-11-24 10:30:00 UTC" in caplog.text
    assert "schedule: stopped" in caplog.text


def test_a_slow_run_skips_the_slots_it_missed():
    clock = FakeClock(NOW)
    stop = threading.Event()
    runs = []
    real_wait = stop.wait

    def wait(seconds):
        clock.time += timedelta(seconds=seconds)
        return real_wait(0)

    stop.wait = wait

    def run():
        runs.append(clock.time)
        clock.time += timedelta(minutes=40)  # longer than two intervals
        if len(runs) == 2:
            stop.set()
        return 1

    schedule.loop(run, timedelta(minutes=15), stop=stop, now=clock.now, handle_signals=False)
    assert runs[1] == datetime(2026, 11, 24, 11, 0, tzinfo=UTC)


def test_sigterm_lets_the_current_run_finish_then_stops(caplog):
    finished = []

    def run():
        os.kill(os.getpid(), signal.SIGTERM)
        finished.append(True)  # still runs after the signal
        return 0

    before = signal.getsignal(signal.SIGTERM)
    assert schedule.loop(run, timedelta(minutes=15)) == 0
    assert finished == [True]
    assert "SIGTERM received, stopping after the current run" in caplog.text
    assert signal.getsignal(signal.SIGTERM) is before  # handlers restored


def test_a_second_signal_stops_at_once():
    finished = []

    def run():
        os.kill(os.getpid(), signal.SIGINT)
        os.kill(os.getpid(), signal.SIGINT)
        finished.append(True)
        return 0

    with pytest.raises(SystemExit) as exc:
        schedule.loop(run, timedelta(minutes=15))
    assert exc.value.code == 128 + signal.SIGINT
    assert finished == []


def test_every_keeps_running_through_main(config, tmp_path, monkeypatch):
    """--every runs the real job in the loop; stop it after two runs."""
    state = tmp_path / "state.json"
    calls = []
    real = cli._scheduled_run

    def counted(args):
        calls.append(1)
        code = real(args)
        if len(calls) == 2:
            os.kill(os.getpid(), signal.SIGTERM)
        return code

    monkeypatch.setattr(cli, "_scheduled_run", counted)
    monkeypatch.setattr(schedule, "next_slot", lambda now, interval: now)  # no waiting
    assert main(["--config", str(config), "--state", str(state), "--every", "1m"]) == 0
    assert len(calls) == 2
    assert status_of(schedule.status_path(state))["last_exit"] == 0


# --- healthcheck ------------------------------------------------------------


def test_health_needs_a_working_run(tmp_path):
    path = tmp_path / "state.status.json"
    ok, why = schedule.health(path, timedelta(minutes=15), NOW)
    assert not ok and "no working run recorded" in why
    schedule.record(path, 1, NOW)
    assert not schedule.health(path, timedelta(minutes=15), NOW)[0]


def test_health_allows_two_intervals_plus_five_minutes(tmp_path):
    path = tmp_path / "state.status.json"
    schedule.record(path, 0, NOW)
    every = timedelta(minutes=15)
    assert schedule.health(path, every, NOW + timedelta(minutes=35)) == (True, "last working run 35 min ago")
    ok, why = schedule.health(path, every, NOW + timedelta(minutes=35, seconds=1))
    assert not ok and "over the 35 min limit" in why


def test_health_flag_reads_the_status_beside_the_state(config, tmp_path, capsys, monkeypatch):
    state = tmp_path / "data" / "state.json"
    monkeypatch.setenv("INTEL_FEEDS_STATE", str(state))
    assert main(["--health"]) == 1
    assert capsys.readouterr().out.startswith("unhealthy: no working run")
    assert main(["--config", str(config)]) == 0
    assert main(["--health", "--every", "1h"]) == 0
    assert capsys.readouterr().out.strip().startswith("healthy: last working run 0 min ago")
