import json
import subprocess
import sys
from pathlib import Path

import pytest

from intel_feeds.__main__ import main


def test_help_exits_cleanly(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "Discord" in capsys.readouterr().out


REPO = Path(__file__).resolve().parents[1]
WEBHOOK_VARS = ("WEBHOOK_NEWS", "WEBHOOK_VULNS", "WEBHOOK_ADVISORIES", "WEBHOOK_RESEARCH")


def test_run_with_the_committed_config_returns_zero():
    assert main(["--config", str(REPO / "sources.yaml")]) == 0


def test_check_config_reports_ok(capsys):
    assert main(["--check-config", "--config", str(REPO / "sources.yaml")]) == 0
    assert "OK, 21 sources (20 enabled)" in capsys.readouterr().out


def test_bad_config_exits_non_zero_and_lists_every_problem(tmp_path, capsys):
    bad = tmp_path / "sources.yaml"
    bad.write_text(
        "sources:\n"
        "  - name: SecurityWeek\n    url: http://www.securityweek.com/feed/\n"
        "    type: rss\n    category: new\n"
    )
    assert main(["--check-config", "--config", str(bad)]) == 2
    err = capsys.readouterr().err
    assert "Config check failed with 2 problems:" in err
    assert 'source "SecurityWeek": unknown category "new"' in err
    assert "must start with https://" in err


def test_missing_config_exits_non_zero(tmp_path, capsys):
    assert main(["--config", str(tmp_path / "missing.yaml")]) == 2
    assert "file not found" in capsys.readouterr().err


def test_webhook_warning_never_shows_the_url(monkeypatch, caplog, capsys):
    secret = "https://webhook.invalid/sentinel-value-must-not-be-logged"
    for var in WEBHOOK_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("WEBHOOK_NEWS", secret)
    assert main(["--check-config", "--config", str(REPO / "sources.yaml")]) == 0
    out = capsys.readouterr()
    logged = caplog.text + out.out + out.err
    assert "WEBHOOK_VULNS is not set" in logged
    assert "WEBHOOK_NEWS" not in logged
    assert secret not in logged


def test_module_entry_point():
    result = subprocess.run(
        [sys.executable, "-m", "intel_feeds", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "usage: intel_feeds" in result.stdout


# --- .env loading and --test-post -----------------------------------------

import os  # noqa: E402

import httpx  # noqa: E402

from intel_feeds import webhook  # noqa: E402

SECRET = "https://webhook.invalid/api/webhooks/0/sentinel-token"
ALL_WEBHOOKS = WEBHOOK_VARS + ("WEBHOOK_OPS",)


def fake_discord(monkeypatch, *statuses):
    """Route webhook posts to a fake that answers with ``statuses`` in turn."""
    requests = []
    replies = list(statuses)

    def handler(request):
        requests.append(request)
        return httpx.Response(replies.pop(0) if replies else 200, json={})

    monkeypatch.setattr(
        webhook,
        "make_client",
        lambda transport=None: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return requests


def run(*args):
    return main([*args, "--config", str(REPO / "sources.yaml")])


def test_env_file_in_the_working_folder_is_loaded(tmp_path, caplog):
    # conftest runs each test in tmp_path, so this is the default ".env".
    (tmp_path / ".env").write_text("".join(f"{v}={SECRET}/{v}\n" for v in (*WEBHOOK_VARS, "WEBHOOK_RANSOM")))
    assert run("--check-config") == 0
    assert "no webhook for" not in caplog.text


def test_env_file_option_and_shell_values_win(tmp_path, monkeypatch):
    other = tmp_path / "other.env"
    other.write_text(f"WEBHOOK_NEWS={SECRET}/file\n")
    monkeypatch.setenv("WEBHOOK_NEWS", SECRET + "/shell")
    assert run("--check-config", "--env-file", str(other)) == 0
    assert os.environ["WEBHOOK_NEWS"] == SECRET + "/shell"


def test_test_post_posts_to_every_set_webhook(tmp_path, monkeypatch, capsys, caplog):
    requests = fake_discord(monkeypatch)
    (tmp_path / ".env").write_text("".join(f"{v}={SECRET}/{v}\n" for v in ALL_WEBHOOKS))
    caplog.set_level("DEBUG")
    assert run("--test-post", "--verbose") == 0
    out = capsys.readouterr()
    assert len(requests) == 5
    for var in ALL_WEBHOOKS:
        assert f"{var}: posted" in out.out
    assert "Test post: 5 posted, 0 failed" in out.out
    logged = caplog.text + out.out + out.err
    assert "sentinel-token" not in logged and "/api/webhooks/" not in logged


def test_test_post_fails_if_any_post_fails(monkeypatch, capsys):
    fake_discord(monkeypatch, 404)
    monkeypatch.setenv("WEBHOOK_NEWS", SECRET + "/a")
    monkeypatch.setenv("WEBHOOK_VULNS", SECRET + "/b")
    assert run("--test-post") == 1
    out = capsys.readouterr().out
    assert "WEBHOOK_NEWS: failed: WEBHOOK_NEWS: Discord rejected the webhook (HTTP 404)" in out
    assert "WEBHOOK_VULNS: posted" in out
    assert "WEBHOOK_OPS: skipped (not set)" in out
    assert "Test post: 1 posted, 1 failed" in out
    assert "sentinel-token" not in out


def test_test_post_with_no_webhooks_set_fails(monkeypatch, capsys):
    requests = fake_discord(monkeypatch)
    assert run("--test-post") == 1
    assert requests == []
    assert "No webhook variables are set" in capsys.readouterr().err


def test_bad_config_fails_before_any_test_post(tmp_path, monkeypatch, capsys):
    requests = fake_discord(monkeypatch)
    monkeypatch.setenv("WEBHOOK_NEWS", SECRET)
    bad = tmp_path / "bad.yaml"
    bad.write_text("sources: []\nextra: 1\n")
    assert main(["--test-post", "--config", str(bad)]) == 2
    assert requests == []


def test_test_post_sends_the_ransomware_channel_a_made_up_victim(tmp_path, monkeypatch, capsys):
    requests = fake_discord(monkeypatch)
    (tmp_path / ".env").write_text(f"WEBHOOK_RANSOM={SECRET}/WEBHOOK_RANSOM\n")
    assert run("--test-post") == 0
    assert "WEBHOOK_RANSOM: posted" in capsys.readouterr().out
    [request] = requests
    embed = json.loads(request.content)["embeds"][0]
    assert embed["title"] == "intel-feeds test post: ransomware (made-up victim)"
    assert embed["author"]["name"] == "ransomware.live"  # the source from sources.yaml
    assert "icon_url" in embed["author"]
    assert [f["name"] for f in embed["fields"]] == ["Group", "Country", "Sector", "Website"]


def test_state_defaults_to_state_json_in_the_working_folder(tmp_path):
    assert main(["--config", str(REPO / "sources.yaml")]) == 0
    assert (tmp_path / "state.json").exists()


def test_state_path_from_the_environment_or_env_file(tmp_path):
    (tmp_path / ".env").write_text("INTEL_FEEDS_STATE=data/from-env.json\n")
    (tmp_path / "data").mkdir()
    assert main(["--config", str(REPO / "sources.yaml")]) == 0
    assert (tmp_path / "data" / "from-env.json").exists()
    assert not (tmp_path / "state.json").exists()


def test_state_option_beats_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("INTEL_FEEDS_STATE", str(tmp_path / "env.json"))
    assert main(["--config", str(REPO / "sources.yaml"), "--state", str(tmp_path / "flag.json")]) == 0
    assert (tmp_path / "flag.json").exists()
    assert not (tmp_path / "env.json").exists()


def test_version_comes_from_the_package_source(capsys):
    from intel_feeds import __version__

    assert __version__ != "0.0.0"
    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out.strip() == f"intel_feeds {__version__}"
