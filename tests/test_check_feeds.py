"""Offline tests for scripts/check_feeds.py, using the saved fixtures."""

import importlib.util
import json
import sys
from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures"

spec = importlib.util.spec_from_file_location("check_feeds", REPO / "scripts" / "check_feeds.py")
check_feeds = importlib.util.module_from_spec(spec)
sys.modules["check_feeds"] = check_feeds
spec.loader.exec_module(check_feeds)

RSS = (FIXTURES / "rss20_the_record.xml").read_bytes()
KEV = (FIXTURES / "kev.json").read_bytes()
NVD = (FIXTURES / "nvd.json").read_bytes()
HTML = b"<!doctype html><html><head><title>Blog</title></head><body>hi</body></html>"


def write_config(tmp_path, *entries):
    lines = ["sources:"]
    for name, url, kind, category in entries:
        lines += [f"  - name: {name}", f"    url: {url}", f"    type: {kind}", f"    category: {category}"]
    path = tmp_path / "sources.yaml"
    path.write_text("\n".join(lines) + "\n")
    return path


@pytest.fixture
def serve(monkeypatch):
    """Serve canned responses by host; returns the list of requests seen."""
    routes, seen = {}, []

    def handler(request):
        seen.append(request)
        status, body, headers = routes[request.url.host]
        return httpx.Response(status, content=body, headers=headers)

    monkeypatch.setattr(
        check_feeds, "make_client",
        lambda: httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True),
    )

    def add(host, body, status=200, headers=None):
        routes[host] = (status, body, headers or {})

    add.requests = seen
    return add


def test_every_fixture_type_is_reported_ok(tmp_path, serve, capsys):
    serve("rss.example", RSS, headers={"Content-Type": "text/html", "ETag": '"x"'})
    serve("kev.example", KEV, headers={"Last-Modified": "Tue, 17 Nov 2026 12:00:00 GMT"})
    serve("nvd.example", NVD)
    config = write_config(
        tmp_path,
        ("Feed", "https://rss.example/feed", "rss", "news"),
        ("KEV", "https://kev.example/kev.json", "kev", "vulns"),
        ("NVD", "https://nvd.example/cves", "nvd", "vulns"),
    )
    assert check_feeds.main(["--config", str(config)]) == 0
    out = capsys.readouterr().out
    assert "3 of 3 sources returned items" in out
    feed_line = next(line for line in out.splitlines() if line.startswith("Feed"))
    assert "rss20" in feed_line and "  5  " in feed_line  # sniffed despite text/html
    kev_line = next(line for line in out.splitlines() if line.startswith("KEV"))
    assert "json (kev)" in kev_line and "  5  " in kev_line


def test_nvd_request_asks_for_a_small_recent_window(tmp_path, serve, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key")
    serve("nvd.example", NVD)
    config = write_config(tmp_path, ("NVD", "https://nvd.example/cves", "nvd", "vulns"))
    check_feeds.main(["--config", str(config)])
    request = serve.requests[0]
    assert request.url.params["resultsPerPage"] == "5"
    assert {"pubStartDate", "pubEndDate"} <= set(request.url.params)
    assert request.headers["apiKey"] == "test-key"


@pytest.mark.parametrize(
    ("status", "body", "problem"),
    [
        (403, b"Access Denied", "HTTP 403 Forbidden"),
        (200, HTML, "not an RSS or Atom feed"),
        (200, b'{"a": 1}', "JSON body for an rss source"),
        (200, b'<rss version="2.0"><channel><title>t</title></channel></rss>', "no items"),
    ],
)
def test_broken_sources_fail_with_a_reason(tmp_path, serve, capsys, status, body, problem):
    serve("rss.example", body, status=status)
    config = write_config(tmp_path, ("Feed", "https://rss.example/feed", "rss", "news"))
    assert check_feeds.main(["--config", str(config)]) == 1
    out = capsys.readouterr().out
    assert problem in out
    assert "0 of 1 sources returned items" in out


def test_network_error_names_the_type_not_the_url(tmp_path, monkeypatch, capsys):
    def handler(request):
        raise httpx.ConnectError(f"cannot reach {request.url}")

    monkeypatch.setattr(
        check_feeds, "make_client",
        lambda: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    config = write_config(tmp_path, ("Feed", "https://secret.example/feed", "rss", "news"))
    assert check_feeds.main(["--config", str(config)]) == 1
    out = capsys.readouterr().out
    assert "network error: ConnectError" in out
    assert "secret.example" not in out


def test_source_filter_and_unknown_name(tmp_path, serve, capsys):
    serve("rss.example", RSS)
    config = write_config(
        tmp_path,
        ("Feed", "https://rss.example/feed", "rss", "news"),
        ("Other", "https://other.example/feed", "rss", "news"),
    )
    assert check_feeds.main(["--config", str(config), "--source", "feed"]) == 0
    assert [r.url.host for r in serve.requests] == ["rss.example"]
    assert check_feeds.main(["--config", str(config), "--source", "Nope"]) == 2
    assert "No source named: nope" in capsys.readouterr().err


def test_save_fixtures_keeps_the_smallest_feed_and_trims_kev(tmp_path, serve):
    big_kev = json.loads(KEV)
    big_kev["vulnerabilities"] = big_kev["vulnerabilities"] * 4
    serve("a.example", RSS)
    serve("b.example", RSS + b"<!-- padding -->" * 100)
    serve("kev.example", json.dumps(big_kev).encode())
    config = write_config(
        tmp_path,
        ("Small Feed", "https://a.example/feed", "rss", "news"),
        ("Big Feed", "https://b.example/feed", "rss", "news"),
        ("KEV", "https://kev.example/kev.json", "kev", "vulns"),
    )
    out_dir = tmp_path / "fixtures"
    assert check_feeds.main(["--config", str(config), "--save-fixtures", str(out_dir)]) == 0
    assert sorted(p.name for p in out_dir.iterdir()) == ["kev.json", "rss20_small_feed.xml"]
    kev = json.loads((out_dir / "kev.json").read_text())
    assert kev["count"] == len(kev["vulnerabilities"]) == 5


def test_committed_config_is_what_the_checker_reads():
    # Guards the checker against config changes: it must load the real file.
    sources = check_feeds.load_sources(REPO / "sources.yaml")
    assert {s.type for s in sources} == {"rss", "kev", "nvd", "ransomware"}
