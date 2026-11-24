from intel_feeds.envfile import load_env_file

SECRET = "https://webhook.invalid/api/webhooks/0/sentinel-token"


def write(tmp_path, text):
    path = tmp_path / ".env"
    path.write_text(text)
    return path


def test_missing_file_is_not_an_error(tmp_path):
    env = {}
    assert load_env_file(tmp_path / ".env", env) == ([], [])
    assert env == {}


def test_reads_names_values_quotes_comments_and_export(tmp_path):
    path = write(
        tmp_path,
        "# comment\n"
        "\n"
        f"WEBHOOK_NEWS={SECRET}\n"
        f"WEBHOOK_VULNS='{SECRET}/v'\n"
        f'export WEBHOOK_ADVISORIES="{SECRET}/a"  # trailing comment\n'
        f"WEBHOOK_RESEARCH = {SECRET}/r   # optional\n",
    )
    env = {}
    names, warnings = load_env_file(path, env)
    assert warnings == []
    assert names == [
        "WEBHOOK_NEWS",
        "WEBHOOK_VULNS",
        "WEBHOOK_ADVISORIES",
        "WEBHOOK_RESEARCH",
    ]
    assert env == {
        "WEBHOOK_NEWS": SECRET,
        "WEBHOOK_VULNS": f"{SECRET}/v",
        "WEBHOOK_ADVISORIES": f"{SECRET}/a",
        "WEBHOOK_RESEARCH": f"{SECRET}/r",
    }


def test_empty_values_are_not_set(tmp_path):
    path = write(tmp_path, "WEBHOOK_NEWS=\nWEBHOOK_OPS=   # optional\n")
    env = {}
    assert load_env_file(path, env) == ([], [])
    assert env == {}


def test_environment_wins_over_the_file(tmp_path):
    path = write(tmp_path, "WEBHOOK_NEWS=from-file\nWEBHOOK_VULNS=from-file\n")
    env = {"WEBHOOK_NEWS": "from-shell", "WEBHOOK_VULNS": "  "}
    names, _ = load_env_file(path, env)
    assert env["WEBHOOK_NEWS"] == "from-shell"
    # A blank value in the environment counts as unset.
    assert env["WEBHOOK_VULNS"] == "from-file"
    assert names == ["WEBHOOK_VULNS"]


def test_bad_lines_warn_by_line_number_without_showing_the_text(tmp_path):
    path = write(
        tmp_path,
        f"{SECRET}\n"  # URL pasted without a name
        f'WEBHOOK_NEWS="{SECRET}\n'  # unclosed quote
        f"1BAD={SECRET}\n",  # invalid name
    )
    env = {}
    names, warnings = load_env_file(path, env)
    assert names == [] and env == {}
    assert warnings == [
        f"{path}:1: not a NAME=value line; ignored",
        f"{path}:2: WEBHOOK_NEWS has an unclosed quote; ignored",
        f"{path}:3: not a NAME=value line; ignored",
    ]
    assert not any("sentinel" in w for w in warnings)
