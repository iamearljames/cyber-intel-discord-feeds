"""Post embeds to Discord webhooks.

Webhook URLs are secrets: anyone holding one can post to the channel. This
module never logs or raises a URL. Every message names the environment
variable the URL came from (for example ``WEBHOOK_NEWS``) instead, and
httpx's own loggers, which log each request URL at INFO and DEBUG, are kept
at WARNING.
"""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Mapping
from datetime import UTC, datetime

import httpx

from intel_feeds import __version__
from intel_feeds.config import WEBHOOK_ENV

log = logging.getLogger(__name__)

# httpx logs "HTTP Request: POST <full URL>" at INFO; httpcore logs at DEBUG.
for _name in ("httpx", "httpcore"):
    logging.getLogger(_name).setLevel(logging.WARNING)

OPS_ENV = "WEBHOOK_OPS"  # the optional ops channel: source health alerts and --test-post

COLORS = {
    "news": 0x3498DB,  # blue
    "vulns": 0xE74C3C,  # red
    "advisories": 0xE67E22,  # orange
    "research": 0x9B59B6,  # purple
    "ransomware": 0x8B1A1A,  # dark red / maroon
    "ops": 0x95A5A6,  # grey
}

# Discord allows 256 / 4096 / 2048 characters; keep posts short and the
# whole embed far below Discord's 6,000-character total.
TITLE_LIMIT = 256
EXCERPT_LIMIT = 300
AUTHOR_LIMIT = 256  # Discord's limit on the author name

MAX_ATTEMPTS = 4  # the first try plus 3 retries
MAX_WAIT = 30.0  # seconds; longer waits do not fit a one-minute run
BACKOFF_BASE = 1.0  # seconds: 1, 2, 4
TIMEOUT = 10.0
USER_AGENT = f"intel-feeds/{__version__}"

# Looked up at call time so tests can replace them.
_sleep = time.sleep
_jitter = random.random


class WebhookError(Exception):
    """A post failed. The message names the variable, never the URL."""


def make_client(transport: httpx.BaseTransport | None = None) -> httpx.Client:
    return httpx.Client(
        timeout=TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        transport=transport,
    )


def build_embed(
    *,
    title: str,
    category: str,
    source: str,
    url: str = "",
    published: datetime | None = None,
    excerpt: str = "",
    source_url: str | None = None,
    source_icon: str | None = None,
) -> dict:
    """Build one embed: source, title linking to ``url``, excerpt, time, color.

    The source name is the embed's author line, at the top, with
    ``source_icon`` beside it and linking to ``source_url`` when given
   . The published time shows at the bottom. A naive ``published``
    time is taken as UTC.
    """
    author: dict = {"name": _clip(source.strip() or "(unknown source)", AUTHOR_LIMIT)}
    if source_url:
        author["url"] = source_url
    if source_icon:
        author["icon_url"] = source_icon
    embed: dict = {
        "author": author,
        "title": _clip(title.strip() or "(untitled)", TITLE_LIMIT),
        "color": COLORS[category],
    }
    if url:
        embed["url"] = url
    if excerpt.strip():
        embed["description"] = _clip(excerpt.strip(), EXCERPT_LIMIT)
    if published is not None:
        if published.tzinfo is None:
            published = published.replace(tzinfo=UTC)
        embed["timestamp"] = published.astimezone(UTC).isoformat()
    return embed


def post_embed(
    client: httpx.Client,
    url: str,
    embed: dict,
    *,
    label: str,
    allowed_mentions: dict | None = None,
    content: str = "",
) -> None:
    """Post one embed, retrying 429s, 5xx responses and network errors.

    ``label`` names the URL's variable in logs and errors. Mentions are
    disabled unless ``allowed_mentions`` says otherwise, so a feed title
    containing ``@everyone`` cannot ping anyone.
    """
    if not url.startswith("https://"):
        raise WebhookError(f"{label} is not an https URL; check the value")

    payload: dict = {
        "embeds": [embed],
        "allowed_mentions": allowed_mentions or {"parse": []},
    }
    if content:
        payload["content"] = content

    for attempt in range(1, MAX_ATTEMPTS + 1):
        last = attempt == MAX_ATTEMPTS
        try:
            response = client.post(url, params={"wait": "true"}, json=payload)
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            # str(exc) can include the host or URL; report only the type.
            reason = type(exc).__name__
            if isinstance(exc, (httpx.InvalidURL, httpx.UnsupportedProtocol)):
                raise WebhookError(f"{label} is not a valid URL ({reason})") from None
            if last:
                raise WebhookError(
                    f"{label}: network error ({reason}) after {attempt} attempts"
                ) from None
            _retry(label, f"network error ({reason})", _backoff(attempt))
            continue

        status = response.status_code
        if status < 300:
            _pace(response)
            return
        if status == 429:
            wait = _retry_after(response)
            if wait > MAX_WAIT:
                raise WebhookError(
                    f"{label}: rate limited by Discord for {wait:.0f}s, "
                    f"longer than the {MAX_WAIT:.0f}s limit; try again later"
                )
            if last:
                raise WebhookError(
                    f"{label}: still rate limited after {attempt} attempts"
                )
            _retry(label, "rate limited (HTTP 429)", wait)
            continue
        if status >= 500:
            if last:
                raise WebhookError(
                    f"{label}: Discord returned HTTP {status} after {attempt} attempts"
                )
            _retry(label, f"Discord returned HTTP {status}", _backoff(attempt))
            continue
        if status in (401, 403, 404):
            raise WebhookError(
                f"{label}: Discord rejected the webhook (HTTP {status}); it was "
                f"deleted or the URL is wrong. Recreate it and update {label}"
            )
        raise WebhookError(
            f"{label}: Discord refused the post (HTTP {status}){_discord_message(response)}"
        )


def send_test_posts(
    client: httpx.Client,
    env: Mapping[str, str],
    webhooks: Mapping[str, str] = WEBHOOK_ENV,
    samples: Mapping[str, dict] | None = None,
) -> list[tuple[str, str]]:
    """Post one sample embed to every webhook that is set.

    ``webhooks`` maps each category to its variable (``settings.webhooks``);
    the ops channel's :data:`OPS_ENV` comes last. ``samples`` gives a
    category its own sample embed instead of the plain one (the ransomware
    channel's made-up victim).

    Returns ``(variable, outcome)`` pairs in a fixed order, where outcome is
    ``"posted"``, ``"skipped (not set)"`` or ``"failed: <reason>"``.
    """
    results = []
    now = datetime.now(UTC)
    for category, variable in {**webhooks, "ops": OPS_ENV}.items():
        url = env.get(variable, "").strip()
        if not url:
            results.append((variable, "skipped (not set)"))
            continue
        embed = (samples or {}).get(category) or build_embed(
            title=f"intel-feeds test post: {category}",
            category=category,
            source=f"intel-feeds {__version__} · --test-post",
            published=now,
            excerpt=(
                f"If you can read this, the {variable} webhook works and "
                f"posts to this channel. This is a one-off test; nothing "
                f"else posts here until the feeds are connected."
            ),
        )
        try:
            post_embed(client, url, embed, label=variable)
        except WebhookError as exc:
            results.append((variable, f"failed: {exc}"))
        else:
            results.append((variable, "posted"))
    return results


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _backoff(attempt: int) -> float:
    return BACKOFF_BASE * 2 ** (attempt - 1) + _jitter() * 0.5


def _retry(label: str, reason: str, wait: float) -> None:
    log.warning("%s: %s; retrying in %.1fs", label, reason, wait)
    _sleep(wait)


def _retry_after(response: httpx.Response) -> float:
    """Seconds to wait from Discord's JSON ``retry_after`` or the header."""
    value: object = None
    try:
        body = response.json()
        if isinstance(body, dict):
            value = body.get("retry_after")
    except ValueError:
        pass
    if value is None:
        value = response.headers.get("Retry-After")
    try:
        return max(0.0, float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return BACKOFF_BASE


def _pace(response: httpx.Response) -> None:
    """Wait out the bucket when Discord says no requests remain."""
    if response.headers.get("X-RateLimit-Remaining") != "0":
        return
    try:
        wait = float(response.headers.get("X-RateLimit-Reset-After", ""))
    except ValueError:
        return
    if wait > 0:
        log.debug("rate limit bucket empty; waiting %.1fs", wait)
        _sleep(min(wait, MAX_WAIT))


def _discord_message(response: httpx.Response) -> str:
    """Discord's error message and code, if the body has them."""
    try:
        body = response.json()
    except ValueError:
        return ""
    if not isinstance(body, dict) or "message" not in body:
        return ""
    code = f" (code {body['code']})" if "code" in body else ""
    return f": {_clip(str(body['message']), 200)}{code}"
