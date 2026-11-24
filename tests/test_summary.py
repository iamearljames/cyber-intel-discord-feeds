import logging

import pytest

from intel_feeds import summary
from intel_feeds.summary import Summary


def sample() -> Summary:
    tally = Summary(["SecurityWeek", "CISA KEV", "Broken", "Bad XML"])
    tally.fetched("SecurityWeek", "ok", 0.8)
    tally.parsed("SecurityWeek", 50, 0.1)
    tally.fetched("CISA KEV", "not_modified", 0.3)
    tally.fetched("Broken", "failed", 10.0)
    tally.fetched("Bad XML", "ok", 0.2)
    tally.parse_failed("Bad XML", 0.05)
    tally.new({"SecurityWeek": 6})
    tally.filtered({"SecurityWeek": 1})
    tally.filtered({"SecurityWeek": 1})  # guard, then the CVE filter
    tally.posted({"SecurityWeek": 3})
    tally.failed_posts({"SecurityWeek": 1})
    return tally


def test_rows_keep_config_order_and_count_each_stage():
    rows = sample().rows
    assert list(rows) == ["SecurityWeek", "CISA KEV", "Broken", "Bad XML"]
    sw = rows["SecurityWeek"]
    assert (sw.fetch, sw.items, sw.new, sw.filtered, sw.posted, sw.left, sw.errors) == (
        "ok", 50, 6, 2, 3, 1, 1
    )
    assert sw.seconds == pytest.approx(0.9)
    assert rows["CISA KEV"].fetch == "not modified"
    assert (rows["Broken"].fetch, rows["Broken"].errors) == ("failed", 1)
    assert (rows["Bad XML"].fetch, rows["Bad XML"].errors) == ("parse failed", 1)
    assert rows["Bad XML"].seconds == pytest.approx(0.25)


def test_left_is_new_minus_filtered_and_posted():
    tally = Summary(["A"])
    tally.new({"A": 12})
    tally.filtered({"A": 2})
    tally.posted({"A": 10})
    assert tally.rows["A"].left == 0


def test_total_adds_up_every_source():
    assert sample().total() == {
        "items": 50, "new": 6, "filtered": 2, "posted": 3, "left": 1, "errors": 3
    }


def test_a_source_not_listed_up_front_still_gets_a_row():
    tally = Summary([])
    tally.posted({"Late": 1})
    assert tally.rows["Late"].posted == 1


def test_table_is_aligned_with_a_header_and_a_total():
    lines = sample().table()
    assert lines[0].split() == [
        "source", "fetch", "items", "new", "filtered", "posted", "left", "errors", "seconds"
    ]
    assert lines[1].split() == ["SecurityWeek", "ok", "50", "6", "2", "3", "1", "1", "0.9"]
    assert lines[2].split() == ["CISA", "KEV", "not", "modified", "0", "0", "0", "0", "0", "0", "0.3"]
    assert lines[-1].split() == ["total", "50", "6", "2", "3", "1", "3"]
    # Every count column ends at the same place on every line.
    header_end = lines[0].index("errors") + len("errors")
    assert all(line[header_end - 1] != " " for line in lines[1:])


def test_log_has_the_table_and_the_run_time(caplog):
    caplog.set_level(logging.INFO)
    sample().log(14.25)
    assert "summary: source" in caplog.text
    assert "summary: SecurityWeek" in caplog.text
    assert "run: finished in 14.2 s; 6 new, 2 filtered, 3 posted, 1 left, 3 errors" in caplog.text
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.parametrize("seconds, warns", [(59.9, False), (60.0, False), (60.1, True)])
def test_a_run_over_the_budget_warns(seconds, warns, caplog):
    sample().log(seconds)
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    if warns:
        assert warnings == [
            f"run: took {seconds:.1f} s, over the 60 s budget"
        ]
    else:
        assert warnings == []
