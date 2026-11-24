"""Route new items to their category's webhook and post them.

Each category posts through one webhook, named by
``settings.webhooks`` in sources.yaml (by default ``news`` → ``WEBHOOK_NEWS`` and so
on). Within a channel, items go out oldest first, across all its sources.

- An item is recorded in state only after its post succeeds.
- A failed post (after the retries in ``webhook.post_embed``) stops that
  channel for the run. The failed item and the ones after it stay
  unrecorded, so the next run fetches them again and posts them in order.
- A category whose webhook is not set keeps its items unposted and
  unrecorded; they post once the webhook is set.
- A new KEV catalog entry (ID ``kev:…``) mentions ``@everyone``
 . Only that post allows the mention; every other post allows
  none, so feed text can never ping anyone. Other items with a KEV badge
  (an MSRC entry whose CVE is in KEV) do not ping.
- Each channel posts at most ``posts_per_channel`` items a run.
  The rest (the newest) are its overflow: unrecorded, so the next run
  fetches them again and they go out ahead of anything newer, oldest first.
- **Watchlist groups**: when a channel's items include
  ``group_min`` or more NVD CVEs let through by the product watchlist for
  the same product, they become one post (a summary embed), placed at the
  oldest one's time. It counts as one post toward the cap, and all its
  CVEs are recorded when it posts, or none when it fails or overflows.
  CVEs at ``cvss_min`` and KEV entries are not marked as watchlist posts,
  so they still post one by one.

A source whose new items are not all recorded (a failed post, overflow or
no webhook) is "incomplete": the caller must not save its validators
(``fetch.remember``), or the next fetch would be a 304 and the unrecorded
items would never come back.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from intel_feeds import dedup, webhook
from intel_feeds.config import CATEGORIES, DEFAULTS, Source
from intel_feeds.dedup import NewItem, Split
from intel_feeds.embeds import group_embed, item_embed
from intel_feeds.items import Item
from intel_feeds.state import State

log = logging.getLogger(__name__)

_NO_TIME = datetime.max.replace(tzinfo=UTC)  # undated items go out last



@dataclass
class Route:
    category: str
    variable: str  # the environment variable holding the webhook URL
    items: list[NewItem]  # oldest first, at most the cap when routed
    overflow: list[NewItem] = field(default_factory=list)  # over the cap, oldest first
    cap: int = DEFAULTS.posts_per_channel


@dataclass
class Plan:
    routes: list[Route] = field(default_factory=list)  # webhook set
    unrouted: list[Route] = field(default_factory=list)  # webhook not set

    def count(self) -> int:
        """Items this run posts (routed and within the cap)."""
        return sum(len(r.items) for r in self.routes)

    def overflow(self) -> int:
        """Routed items over the cap, left for the next run."""
        return sum(len(r.overflow) for r in self.routes)


@dataclass
class Report:
    posted: int = 0
    failed: int = 0  # the failed post plus the ones left after it
    unrouted: int = 0
    overflow: int = 0  # over the per-channel cap, left for the next run
    pinged: int = 0  # KEV posts that mentioned @everyone
    grouped: int = 0  # watchlist CVEs posted inside group posts
    incomplete: set[str] = field(default_factory=set)  # source names
    posted_by: Counter[str] = field(default_factory=Counter)  # by source name
    failed_by: Counter[str] = field(default_factory=Counter)  # by source name


def plan(
    splits: Mapping[str, Split],
    env: Mapping[str, str],
    *,
    cap: int = DEFAULTS.posts_per_channel,
    caps: Mapping[str, int] | None = None,
    webhooks: Mapping[str, str] = DEFAULTS.webhooks,
    group_min: int = 0,
) -> Plan:
    """Group each source's new items by category, oldest first.

    Feeds list newest first, so each source's items are reversed before the
    sort; items with the same time keep their feed's order, oldest first.
    With ``group_min`` (``watchlist.group_min``; 0 turns it off), a
    product's watchlist CVEs become one group post when there are that
    many or more.
    A routed channel (``webhooks`` names its variable, and ``env`` sets it)
    keeps its oldest ``cap`` posts (``posts_per_channel``; ``caps``
    overrides it per category, ``channel_caps``) and puts the rest in its
    overflow; an unrouted one keeps them all.
    """
    by_category: dict[str, list[NewItem]] = {c: [] for c in CATEGORIES}
    for split in splits.values():
        for new in reversed(split.new):
            by_category[new.item.category].append(new)
    result = Plan()
    for category, news in by_category.items():
        if not news:
            continue
        news.sort(key=_published)
        if group_min:
            news = group(news, group_min)
        variable = webhooks[category]
        limit = (caps or {}).get(category, cap)
        if env.get(variable, "").strip():
            result.routes.append(Route(category, variable, news[:limit], news[limit:], limit))
        else:
            result.unrouted.append(Route(category, variable, news))
    return result


def post(
    client: httpx.Client,
    routing: Plan,
    state: State,
    now: datetime,
    env: Mapping[str, str],
    *,
    sources: Mapping[str, Source] | None = None,
) -> Report:
    """Post every routed item, record each success, and report the rest.

    New KEV entries mention ``@everyone``.
    ``sources`` (by name) gives each post its source's icon and site link.
    """
    sources = sources or {}
    report = Report()
    for route in routing.unrouted:
        report.unrouted += sum(new.size for new in route.items)
        report.incomplete.update(new.item.source for new in route.items)
    log_unrouted(routing)
    for route in routing.routes:
        url = env[route.variable].strip()
        report.overflow += sum(new.size for new in route.overflow)
        report.incomplete.update(new.item.source for new in route.overflow)
        posted = pinged = 0
        for index, new in enumerate(route.items):
            ping = _ping(new)
            source = sources.get(new.item.source)
            if new.members:
                embed = group_embed(new.item.watched or "", [m.item for m in new.members], source)
            else:
                embed = item_embed(new.item, source)
            try:
                webhook.post_embed(client, url, embed, label=route.variable, **ping)
            except webhook.WebhookError as exc:
                left = route.items[index:]
                report.failed += sum(n.size for n in left)
                for n in left:
                    report.failed_by[n.item.source] += n.size
                report.incomplete.update(n.item.source for n in left)
                log.warning(
                    "post %s: %d posted, then failed: %s; %d items left for the next run",
                    route.variable,
                    posted,
                    exc,
                    len(left),
                )
                break
            for member in new.recorded():
                dedup.record(state, member, now, posted=True)
            posted += 1
            report.posted_by[new.item.source] += new.size
            if new.members:
                report.grouped += new.size
                log.info(
                    'post %s: one post for %d "%s" watchlist CVEs',
                    route.variable,
                    new.size,
                    new.item.watched,
                )
            pinged += bool(ping)
            log.debug('post %s: "%s" %s', route.variable, new.item.source, new.id)
        else:
            log.info("post %s: %d posted%s", route.variable, posted, _over(route))
        if pinged:
            log.info("post %s: %d KEV entries pinged @everyone", route.variable, pinged)
        report.posted += posted
        report.pinged += pinged
    return report


def log_plan(routing: Plan) -> None:
    """Log what a run would post, without posting (posting switched off)."""
    for route in routing.routes:
        log.info(
            "route: would post %d items to %s%s", len(route.items), route.variable, _over(route)
        )
    log_unrouted(routing)


def log_unrouted(routing: Plan) -> None:
    for route in routing.unrouted:
        log.warning(
            'route: %s is not set; %d "%s" items kept for a later run',
            route.variable,
            len(route.items),
            route.category,
        )


def group(news: list[NewItem], group_min: int) -> list[NewItem]:
    """Fold each product's watchlist CVEs into one post when there are enough.

    ``news`` is oldest first; so is the result. A group takes the place of
    its oldest CVE; products with fewer than ``group_min`` stay as they are.
    """
    by_product: dict[tuple[str, str], list[NewItem]] = {}
    for new in news:
        if new.item.watched and not new.members:
            by_product.setdefault((new.item.source, new.item.watched), []).append(new)
    groups = {
        id(members[0]): _group_post(members)
        for members in by_product.values()
        if len(members) >= group_min
    }
    folded = {id(m) for members in by_product.values() if len(members) >= group_min for m in members}
    result = []
    for new in news:
        if id(new) in groups:
            result.append(groups[id(new)])
        elif id(new) not in folded:
            result.append(new)
    return result


def _group_post(members: list[NewItem]) -> NewItem:
    first = members[0].item
    product = first.watched or ""
    top = max(members, key=lambda m: (m.item.cvss or 0.0, m.item.published or _NO_TIME))
    item = Item(
        title=f"{product}: {len(members)} CVEs",
        url=top.item.url,
        source=first.source,
        category=first.category,
        published=first.published,
        watched=product,
    )
    return NewItem(
        item=item,
        id=f"group:{product}:{members[0].id}",
        url=None,
        members=tuple(members),
    )


def _ping(new: NewItem) -> dict:
    """post_embed's mention arguments: @everyone for a KEV entry, else none."""
    if not new.id.startswith("kev:"):
        return {}
    return {"content": "@everyone", "allowed_mentions": {"parse": ["everyone"]}}


def _over(route: Route) -> str:
    if not route.overflow:
        return ""
    return (
        f", {len(route.overflow)} over the cap of {route.cap} "
        "left for the next run"
    )


def _published(new: NewItem) -> datetime:
    return new.item.published or _NO_TIME
