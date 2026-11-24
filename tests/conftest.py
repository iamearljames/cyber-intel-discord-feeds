import os

import httpx
import pytest

from intel_feeds import __main__ as cli
from intel_feeds import cvefilter, enrich, fetch, webhook

WEBHOOK_VARS = (
    "WEBHOOK_NEWS",
    "WEBHOOK_VULNS",
    "WEBHOOK_ADVISORIES",
    "WEBHOOK_RESEARCH",
    "WEBHOOK_RANSOM",
    "WEBHOOK_OPS",
    "RANSOMWARE_LIVE_API",
)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Keep the real .env, real webhooks and real sleeps out of every test.

    Runs each test in an empty folder (so ``main`` finds no ``.env``), clears
    the webhook variables, the ransomware.live key, the contact and the
    state path, restores the environment afterwards (the ``.env``
    loader writes to ``os.environ`` directly), and fails any webhook request
    a test has not mocked. Feed fetches a test has not mocked get a 503 from
    a fake transport, so a normal run works offline and every source fails.
    """
    saved = dict(os.environ)
    for var in (*WEBHOOK_VARS, fetch.NVD_KEY_ENV, fetch.CONTACT_ENV, cli.STATE_ENV):
        os.environ.pop(var, None)
    monkeypatch.chdir(tmp_path)

    def no_network(request):
        pytest.fail("unexpected real HTTP request in a test")

    monkeypatch.setattr(
        webhook,
        "make_client",
        lambda transport=None: httpx.Client(transport=httpx.MockTransport(no_network)),
    )
    monkeypatch.setattr(
        fetch,
        "make_client",
        lambda transport=None: fetch_client(lambda request: httpx.Response(503)),
    )
    monkeypatch.setattr(webhook, "_sleep", lambda seconds: None)
    monkeypatch.setattr(webhook, "_jitter", lambda: 0.0)
    monkeypatch.setattr(cvefilter, "_sleep", lambda seconds: None)
    monkeypatch.setattr(enrich, "_sleep", lambda seconds: None)
    yield
    os.environ.clear()
    os.environ.update(saved)


def fetch_client(handler) -> httpx.Client:
    """A fetch client like the real one, answering through ``handler``."""
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
        headers={"User-Agent": fetch.USER_AGENT},
    )
