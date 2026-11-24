import json
import logging
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from conftest import fetch_client

from intel_feeds import __version__, fetch
from intel_feeds.__main__ import main
from intel_feeds.config import Source
from intel_feeds.state import State, load_state

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures"
NOW = datetime(2026, 11, 18, 10, 0, 0, tzinfo=UTC)
REAL_MAKE_CLIENT = fetch.make_client  # conftest replaces it during each test

RSS = Source("SecurityWeek", "https://feeds.example.com/sw.xml", "rss", "news")
KEV = Source("CISA KEV", "https://feeds.example.com/kev.json", "kev", "vulns")
NVD = Source("NVD CVE API", "https://nvd.example.com/rest/json/cves/2.0", "nvd", "vulns")


def state_with(*sources: Source, **fetch_info) -> State:
    state = State()
    state.add_sources([s.name for s in sources], NOW - timedelta(days=1))
    for name, (etag, last_modified, cursor) in fetch_info.items():
        state.set_fetch_info(name, etag, last_modified, cursor=cursor)
    return state


def run_fetch(handler, sources, state=None, env=None):
    state = state if state is not None else state_with(*sources)
    with fetch_client(handler) as client:
        return fetch.fetch_all(client, sources, state, NOW, env or {})


# --- conditional requests -----------------------------------------------


def test_first_fetch_sends_no_validators_and_returns_the_new_ones():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200,
            content=b"<rss/>",
            headers={"ETag": '"v1"', "Last-Modified": "Wed, 18 Nov 2026 09:00:00 GMT"},
        )

    [result] = run_fetch(handler, [RSS])
    assert "if-none-match" not in seen[0].headers
    assert "if-modified-since" not in seen[0].headers
    assert result.status == fetch.OK
    assert result.body == b"<rss/>"
    assert result.etag == '"v1"'
    assert result.last_modified == "Wed, 18 Nov 2026 09:00:00 GMT"


def test_saved_validators_are_sent_and_304_means_not_modified():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(304)

    state = state_with(
        RSS, SecurityWeek=('"v1"', "Wed, 18 Nov 2026 09:00:00 GMT", None)
    )
    [result] = run_fetch(handler, [RSS], state)
    assert seen[0].headers["if-none-match"] == '"v1"'
    assert seen[0].headers["if-modified-since"] == "Wed, 18 Nov 2026 09:00:00 GMT"
    assert result.status == fetch.NOT_MODIFIED
    assert result.body == b""


def test_only_the_validator_the_server_gave_is_sent():
    seen = []
    state = state_with(RSS, SecurityWeek=(None, "Wed, 18 Nov 2026 09:00:00 GMT", None))
    run_fetch(lambda r: seen.append(r) or httpx.Response(304), [RSS], state)
    assert "if-none-match" not in seen[0].headers
    assert "if-modified-since" in seen[0].headers


def sent_user_agent() -> str:
    seen = []
    with REAL_MAKE_CLIENT(httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200))) as client:
        fetch.fetch_source(client, RSS, None, NOW, {})
    return seen[0].headers["user-agent"]


def test_user_agent_names_the_job_and_nothing_else_by_default():
    assert sent_user_agent() == f"intel-feeds/{__version__}"


def test_user_agent_adds_the_operators_contact(monkeypatch):
    monkeypatch.setenv(fetch.CONTACT_ENV, "  https://example.org/bot  ")
    assert sent_user_agent() == f"intel-feeds/{__version__} (+https://example.org/bot)"


@pytest.mark.parametrize("contact", ["ops@example.org\r\nX-Evil: 1", "x" * 201, "caf\u00e9@example.org"])
def test_a_bad_contact_is_left_out_without_repeating_it(monkeypatch, caplog, contact):
    monkeypatch.setenv(fetch.CONTACT_ENV, contact)
    assert sent_user_agent() == f"intel-feeds/{__version__}"
    assert "INTEL_FEEDS_CONTACT is ignored" in caplog.text
    assert contact not in caplog.text


def test_redirects_are_followed():
    def handler(request):
        if request.url.path == "/sw.xml":
            return httpx.Response(301, headers={"Location": "https://feeds.example.com/new.xml"})
        return httpx.Response(200, content=b"moved")

    [result] = run_fetch(handler, [RSS])
    assert result.body == b"moved"


# --- failures never stop the run ----------------------------------------


@pytest.mark.parametrize(
    "response, message",
    [
        (lambda r: httpx.Response(503), "HTTP 503 Service Unavailable"),
        (lambda r: httpx.Response(403), "HTTP 403 Forbidden"),
        (lambda r: (_ for _ in ()).throw(httpx.ConnectError("boom")), "network error: ConnectError"),
        (lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("slow")), "network error: ReadTimeout"),
    ],
)
def test_a_failing_source_is_skipped_and_the_others_still_fetch(response, message, caplog):
    def handler(request):
        if request.url.path == "/sw.xml":
            return response(request)
        return httpx.Response(200, content=b"{}")

    results = run_fetch(handler, [RSS, KEV])
    assert [r.status for r in results] == [fetch.FAILED, fetch.OK]
    assert results[0].error == message
    assert 'fetch "SecurityWeek": failed, skipped this run: ' + message in caplog.text


def test_failure_messages_never_include_the_url(caplog):
    def handler(request):
        raise httpx.ConnectError(f"cannot reach {request.url}")

    [result] = run_fetch(handler, [RSS])
    assert "example.com" not in result.error
    assert "example.com" not in caplog.text


def test_an_unexpected_error_in_one_source_skips_only_that_source(monkeypatch):
    real = fetch._fetch_feed

    def buggy(client, source, saved):
        if source is RSS:
            raise ZeroDivisionError("bug")
        return real(client, source, saved)

    monkeypatch.setattr(fetch, "_fetch_feed", buggy)
    results = run_fetch(lambda r: httpx.Response(200), [RSS, KEV])
    assert [r.status for r in results] == [fetch.FAILED, fetch.OK]
    assert results[0].error == "unexpected error: ZeroDivisionError"


def test_a_download_past_the_deadline_fails(monkeypatch):
    ticks = iter([0.0, 0.0, fetch.DEADLINE + 1, fetch.DEADLINE + 1])
    monkeypatch.setattr(fetch, "_clock", lambda: next(ticks))
    [result] = run_fetch(lambda r: httpx.Response(200, content=b"x"), [RSS])
    assert result.status == fetch.FAILED
    assert result.error == "took longer than 20 s"


def test_an_oversized_body_fails(monkeypatch):
    monkeypatch.setattr(fetch, "MAX_BYTES", 10)
    [result] = run_fetch(lambda r: httpx.Response(200, content=b"x" * 11), [RSS])
    assert result.status == fetch.FAILED
    assert result.error.startswith("response larger than")


# --- concurrency --------------------------------------------------------


def test_sources_are_fetched_at_the_same_time_and_results_keep_their_order():
    sources = [Source(f"Feed {i}", f"https://feeds.example.com/{i}.xml", "rss", "news") for i in range(4)]
    barrier = threading.Barrier(len(sources), timeout=5)

    def handler(request):
        barrier.wait()  # only passes if all 4 requests are in flight together
        return httpx.Response(200, content=request.url.path.encode())

    results = run_fetch(handler, sources)
    assert [r.body for r in results] == [b"/0.xml", b"/1.xml", b"/2.xml", b"/3.xml"]


def test_no_sources_means_no_requests():
    assert run_fetch(lambda r: pytest.fail("no request expected"), []) == []


# --- NVD ----------------------------------------------------------------


def nvd_page(cves: list[str], total: int, start: int = 0) -> dict:
    return {
        "resultsPerPage": len(cves),
        "startIndex": start,
        "totalResults": total,
        "vulnerabilities": [{"cve": {"id": cve}} for cve in cves],
    }


def test_nvd_first_fetch_asks_for_the_last_day_and_sets_the_cursor():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=nvd_page(["CVE-2026-1"], 1))

    [result] = run_fetch(handler, [NVD])
    params = seen[0].url.params
    assert params["pubStartDate"] == "2026-11-17T10:00:00.000"
    assert params["pubEndDate"] == "2026-11-18T10:00:00.000"
    assert params["resultsPerPage"] == "2000"
    assert "apikey" not in seen[0].headers
    assert "if-none-match" not in seen[0].headers
    assert result.status == fetch.OK
    assert result.cursor == "2026-11-18T10:00:00Z"
    assert json.loads(result.body)["vulnerabilities"] == [{"cve": {"id": "CVE-2026-1"}}]


def test_nvd_window_starts_at_the_cursor_minus_the_overlap():
    seen = []
    state = state_with(NVD, **{"NVD CVE API": (None, None, "2026-11-18T09:30:00Z")})
    run_fetch(lambda r: seen.append(r) or httpx.Response(200, json=nvd_page([], 0)), [NVD], state)
    assert seen[0].url.params["pubStartDate"] == "2026-11-18T07:30:00.000"


def test_nvd_window_is_capped_after_a_long_gap(caplog):
    start, end = fetch.nvd_window("2026-11-01T00:00:00Z", NOW)
    assert end - start == fetch.NVD_MAX_WINDOW
    assert "skipping CVEs published before 2026-11-16T10:00:00Z" in caplog.text


def test_nvd_cursor_in_the_future_never_makes_an_empty_window():
    start, end = fetch.nvd_window("2026-11-19T00:00:00Z", NOW)
    assert start <= end


def test_nvd_api_key_is_sent_only_when_set():
    seen = []
    handler = lambda r: seen.append(r) or httpx.Response(200, json=nvd_page([], 0))  # noqa: E731
    run_fetch(handler, [NVD], env={"NVD_API_KEY": "k123"})
    run_fetch(handler, [NVD], env={"NVD_API_KEY": ""})
    assert seen[0].headers["apikey"] == "k123"
    assert "apikey" not in seen[1].headers


def test_nvd_pages_are_merged_into_one_response(monkeypatch):
    monkeypatch.setattr(fetch, "NVD_PAGE_SIZE", 2)
    pages = {"0": ["CVE-1", "CVE-2"], "2": ["CVE-3", "CVE-4"], "4": ["CVE-5"]}
    seen = []

    def handler(request):
        start = request.url.params["startIndex"]
        seen.append(start)
        return httpx.Response(200, json=nvd_page(pages[start], 5, int(start)))

    [result] = run_fetch(handler, [NVD])
    assert seen == ["0", "2", "4"]
    body = json.loads(result.body)
    assert body["totalResults"] == 5
    assert [v["cve"]["id"] for v in body["vulnerabilities"]] == ["CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"]


def test_nvd_too_many_pages_fails_without_a_cursor(monkeypatch):
    monkeypatch.setattr(fetch, "NVD_PAGE_SIZE", 1)
    monkeypatch.setattr(fetch, "NVD_MAX_PAGES", 2)
    [result] = run_fetch(lambda r: httpx.Response(200, json=nvd_page(["CVE-1"], 9)), [NVD])
    assert result.status == fetch.FAILED
    assert result.error == "NVD window has 9 CVEs, more than 2 pages"
    assert result.cursor is None


@pytest.mark.parametrize("body", [b"not json", b"{}", b'{"totalResults": 1}'])
def test_nvd_malformed_response_fails(body):
    [result] = run_fetch(lambda r: httpx.Response(200, content=body), [NVD])
    assert result.status == fetch.FAILED
    assert result.error.startswith("unexpected NVD response")


def test_nvd_failed_second_page_fails_the_source(monkeypatch):
    monkeypatch.setattr(fetch, "NVD_PAGE_SIZE", 1)

    def handler(request):
        if request.url.params["startIndex"] == "0":
            return httpx.Response(200, json=nvd_page(["CVE-1"], 2))
        return httpx.Response(503)

    [result] = run_fetch(handler, [NVD])
    assert result.status == fetch.FAILED


# --- NVD error reasons ----------------------------------------------

KEY = "a1b2c3d4-0000-4bad-key0-secretsecret"


def test_nvd_error_names_the_reason_from_the_message_header(caplog):
    handler = lambda r: httpx.Response(404, headers={"message": "Invalid apiKey."})  # noqa: E731
    [result] = run_fetch(handler, [NVD], env={"NVD_API_KEY": KEY})
    assert result.status == fetch.FAILED
    assert result.error == "HTTP 404 Not Found: Invalid apiKey."
    assert (
        'fetch "NVD CVE API": failed, skipped this run: HTTP 404 Not Found: Invalid apiKey.'
        in caplog.text
    )


def test_nvd_error_without_a_message_header_is_just_the_status():
    [result] = run_fetch(lambda r: httpx.Response(403), [NVD])
    assert result.error == "HTTP 403 Forbidden"


def test_nvd_error_with_an_empty_message_header_is_just_the_status():
    [result] = run_fetch(lambda r: httpx.Response(503, headers={"message": "  "}), [NVD])
    assert result.error == "HTTP 503 Service Unavailable"


def test_nvd_error_never_holds_the_key_or_the_url(caplog):
    def handler(request):
        echo = f"Invalid apiKey {request.headers['apiKey']} for {request.url} ({request.url.query.decode()})"
        return httpx.Response(404, headers={"message": echo})

    [result] = run_fetch(handler, [NVD], env={"NVD_API_KEY": KEY})
    assert result.error.startswith("HTTP 404 Not Found: Invalid apiKey [redacted] for [redacted]")
    for text in (result.error, caplog.text):
        assert KEY not in text
        assert "example.com" not in text
        assert "pubStartDate" not in text


def test_nvd_reason_is_one_line_and_clipped():
    reason = "first line\r\n\tsecond\x00line " + "x" * 500
    [result] = run_fetch(lambda r: httpx.Response(400, headers={"message": reason}), [NVD])
    prefix = "HTTP 400 Bad Request: "
    assert result.error.startswith(prefix + "first line second line xxx")
    tail = result.error[len(prefix):]
    assert len(tail) == fetch.REASON_MAX
    assert tail.endswith("…")
    assert result.error.isprintable()


def test_other_sources_ignore_a_message_header():
    [result] = run_fetch(lambda r: httpx.Response(404, headers={"message": "ignored"}), [RSS])
    assert result.error == "HTTP 404 Not Found"


def test_the_saved_nvd_fixture_comes_back_unchanged_in_content():
    fixture = json.loads((FIXTURES / "nvd.json").read_text())
    fixture["totalResults"] = len(fixture["vulnerabilities"])  # one page, not a day
    [result] = run_fetch(lambda r: httpx.Response(200, json=fixture), [NVD])
    assert json.loads(result.body)["vulnerabilities"] == fixture["vulnerabilities"]


# --- remember -----------------------------------------------------------


def test_remember_saves_validators_and_cursor_only_for_a_full_response():
    state = state_with(RSS, NVD, SecurityWeek=('"old"', None, None))
    fetch.remember(state, fetch.FetchResult(RSS, fetch.NOT_MODIFIED))
    fetch.remember(state, fetch.FetchResult(RSS, fetch.FAILED, error="x"))
    assert state.sources["SecurityWeek"].etag == '"old"'

    fetch.remember(state, fetch.FetchResult(RSS, fetch.OK, etag='"new"', last_modified="lm"))
    fetch.remember(state, fetch.FetchResult(NVD, fetch.OK, cursor="2026-11-18T10:00:00Z"))
    assert state.sources["SecurityWeek"].etag == '"new"'
    assert state.sources["SecurityWeek"].last_modified == "lm"
    assert state.sources["NVD CVE API"].cursor == "2026-11-18T10:00:00Z"


def test_remember_clears_a_validator_the_server_stopped_sending():
    state = state_with(RSS, SecurityWeek=('"old"', "lm", None))
    fetch.remember(state, fetch.FetchResult(RSS, fetch.OK, etag=None, last_modified="lm2"))
    assert state.sources["SecurityWeek"].etag is None


# --- the run ------------------------------------------------------------


def test_a_run_fetches_every_enabled_source_and_saves_validators_for_finished_ones(
    tmp_path, monkeypatch, caplog
):
    config = tmp_path / "sources.yaml"
    config.write_text(
        "sources:\n"
        "  - name: Up\n    url: https://feeds.example.com/up.xml\n    type: rss\n    category: news\n"
        "  - name: Down\n    url: https://feeds.example.com/down.xml\n    type: rss\n    category: news\n"
        "  - name: Paused\n    url: https://feeds.example.com/paused.xml\n    type: rss\n    category: news\n"
        "    enabled: false\n"
    )
    paths = []

    def handler(request):
        paths.append(request.url.path)
        if request.url.path == "/down.xml":
            return httpx.Response(500)
        return httpx.Response(200, content=b"<rss/>", headers={"ETag": '"v1"'})

    monkeypatch.setattr(fetch, "make_client", lambda transport=None: fetch_client(handler))
    caplog.set_level(logging.INFO)
    assert main(["--config", str(config)]) == 0
    assert sorted(paths) == ["/down.xml", "/up.xml"]
    assert "fetch: 1 fetched, 0 not modified, 1 failed" in caplog.text
    saved = load_state(tmp_path / "state.json")
    assert saved.sources["Up"].etag == '"v1"'  # nothing new to post: finished
    assert saved.sources["Down"].etag is None


def test_a_run_where_every_source_fails_still_exits_zero(caplog):
    # conftest's default fetch client answers 503 to everything.
    caplog.set_level(logging.INFO)
    assert main(["--config", str(REPO / "sources.yaml")]) == 0
    assert "fetch: 0 fetched, 0 not modified, 20 failed" in caplog.text


def test_nvd_pages_get_the_longer_nvd_timeout(monkeypatch):
    timeouts = []

    def handler(request):
        timeouts.append(request.extensions["timeout"])
        return httpx.Response(200, json=nvd_page([], 0))

    run_fetch(handler, [NVD])
    run_fetch(lambda r: timeouts.append(r.extensions["timeout"]) or httpx.Response(200), [RSS])
    assert timeouts[0]["read"] == fetch.NVD_TIMEOUT
    assert timeouts[1]["read"] != fetch.NVD_TIMEOUT


def test_nvd_deadline_is_the_nvd_timeout(monkeypatch):
    ticks = iter([0.0, 0.0, fetch.NVD_TIMEOUT + 1, fetch.NVD_TIMEOUT + 1])
    monkeypatch.setattr(fetch, "_clock", lambda: next(ticks))
    [result] = run_fetch(lambda r: httpx.Response(200, json=nvd_page([], 0)), [NVD])
    assert result.error == "took longer than 25 s"
