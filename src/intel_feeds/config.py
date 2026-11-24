"""Load and validate ``sources.yaml``: the sources and the optional settings.

Validation collects every problem in the file before failing, so one run
shows the full list. Each message names the file, the line and the source
(or setting), for example::

    sources.yaml:57: source "SecurityWeek": unknown category "new" (allowed: news, vulns, advisories, research)
    sources.yaml:12: settings: 'cvss_min' must be a number from 0 to 10, found "high" (text)

The ``settings:`` section and every key in it are optional; :class:`Settings`
holds the defaults.
"""

from __future__ import annotations

import difflib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

import yaml

TYPES = ("rss", "kev", "nvd", "ransomware")
CATEGORIES = ("news", "vulns", "advisories", "research", "ransomware")
REQUIRED_FIELDS = ("name", "url", "type", "category")
OPTIONAL_FIELDS = ("enabled", "revisions", "cve_filter", "site", "icon", "notes")
ALL_FIELDS = REQUIRED_FIELDS + OPTIONAL_FIELDS
TOP_LEVEL_KEYS = ("sources", "settings")

# Default environment variable holding each category's
# webhook URL; ``settings.webhooks`` can name others.
WEBHOOK_ENV = {category: f"WEBHOOK_{category.upper()}" for category in CATEGORIES}
WEBHOOK_ENV["ransomware"] = "WEBHOOK_RANSOM"  # shorter than WEBHOOK_RANSOMWARE

# The ransomware.live PRO API key, sent by ransomware sources.
RANSOMWARE_KEY_ENV = "RANSOMWARE_LIVE_API"

# Each ransomware source must post to the ransomware channel, and only
# ransomware sources may.
TYPE_CATEGORY = {"ransomware": "ransomware"}

# Per-channel caps that differ from posts_per_channel: leak sites
# list victims in dumps of 50 or more, one post each, so the ransomware
# channel posts more per run.
CHANNEL_CAPS = {"ransomware": 25}

_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]*")

# The flood guard holds back a pruned item that a feed lists again only if
# it counts as stale, so keep_days must stay well above max_age_days.
KEEP_TO_MAX_AGE = 4


@dataclass(frozen=True)
class Watchlist:
    """``settings.watchlist``: products whose NVD CVEs post below ``cvss_min``.

    An NVD CVE whose title or description names one of ``products``
    (case-insensitive, whole words) posts when it scores ``min_cvss`` or
    more. With no products it changes nothing. When one run lets through
    ``group_min`` or more CVEs naming the same product, they post as one
    summary instead of one post each.
    """

    min_cvss: float = 7.0
    products: tuple[str, ...] = ()
    group_min: int = 3


WATCHLIST_KEYS = ("min_cvss", "products", "group_min")
GROUP_MIN_RANGE = (2, 100)


@dataclass(frozen=True)
class Settings:
    """The ``settings:`` section; each default is used when its key is absent."""

    # CVE filter: NVD CVEs and cve_filter entries post at this CVSS
    # score or higher (9.0 let through about 100 a day).
    cvss_min: float = 9.8
    # NVD lookups per run for cve_filter sources, with an NVD API key.
    # Without a key NVD allows far fewer, so the run uses at most
    # cvefilter.NO_KEY_LOOKUPS.
    cve_lookups_per_run: int = 20
    # Posts per channel per run; the rest wait for the next run. 4 full
    # channels make 40 posts, which must fit the one-minute run.
    posts_per_channel: int = 10
    # Flood guard: the newest items a new source posts on its first
    # run, and the age past which a new item is held back.
    new_source_posts: int = 3
    max_age_days: int = 7
    # State pruning: items no feed lists go after this many days.
    keep_days: int = 90
    # Product watchlist: NVD CVEs naming these products post from a
    # lower score. Empty by default; sources.yaml ships the agreed list.
    watchlist: Watchlist = Watchlist()
    # Category -> environment variable holding that channel's webhook URL.
    webhooks: Mapping[str, str] = field(default_factory=lambda: dict(WEBHOOK_ENV))
    # Category -> posts per run for channels that differ from
    # posts_per_channel.
    channel_caps: Mapping[str, int] = field(default_factory=lambda: dict(CHANNEL_CAPS))

    def cap_for(self, category: str) -> int:
        """Posts per run for ``category``'s channel."""
        return self.channel_caps.get(category, self.posts_per_channel)

    @property
    def max_age(self) -> timedelta:
        return timedelta(days=self.max_age_days)

    @property
    def keep_for(self) -> timedelta:
        return timedelta(days=self.keep_days)


DEFAULTS = Settings()
SETTINGS_KEYS = (
    "cvss_min",
    "cve_lookups_per_run",
    "posts_per_channel",
    "new_source_posts",
    "max_age_days",
    "keep_days",
    "watchlist",
    "webhooks",
    "channel_caps",
)


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    type: str
    category: str
    enabled: bool = True
    notes: str = ""
    revisions: bool = False  # each new published time of a GUID is a new item
    cve_filter: bool = False  # post only entries whose CVE is in KEV or scores high
    site: str | None = None  # the page the source name links to on each post
    icon: str | None = None  # image shown beside the source name


@dataclass(frozen=True)
class Config:
    sources: list[Source]
    settings: Settings = DEFAULTS


class ConfigError(Exception):
    """The config has one or more problems; ``errors`` lists them all."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("\n".join(errors))


def load_sources(path: str | os.PathLike[str]) -> list[Source]:
    """Read and validate the config; return only its sources."""
    return load_config(path).sources


def load_config(path: str | os.PathLike[str]) -> Config:
    """Read and validate the config; raise ConfigError listing every problem."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError([f"{path}: file not found"]) from None
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError([f"{path}: cannot read file: {exc}"]) from None
    return parse_config(text, label=path.name)


def parse_sources(text: str, label: str = "sources.yaml") -> list[Source]:
    """Validate config text; return only its sources."""
    return parse_config(text, label).sources


def parse_config(text: str, label: str = "sources.yaml") -> Config:
    """Validate config text; ``label`` prefixes every message."""
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError([_yaml_error(label, exc)]) from None

    if root is None:
        raise ConfigError([f"{label}: file is empty; it needs a top-level 'sources:' list"])
    if not isinstance(data, Mapping):
        raise ConfigError(
            [f"{label}:{_line(root)}: expected a top-level 'sources:' list, found {_kind(data)}"]
        )

    errors: list[str] = []
    top_keys = [k.value for k, _ in root.value]
    for key_node, _ in root.value:
        key = key_node.value
        if top_keys.count(key) > 1:
            errors.append(f"{label}:{_line(key_node)}: top-level key {key!r} appears more than once")
            raise ConfigError(errors)
        if key not in TOP_LEVEL_KEYS:
            errors.append(
                f"{label}:{_line(key_node)}: unknown top-level key {key!r}"
                f"{_suggest(key, TOP_LEVEL_KEYS)} (allowed: {', '.join(TOP_LEVEL_KEYS)})"
            )

    settings = DEFAULTS
    if "settings" in data:
        settings_node = next(v for k, v in root.value if k.value == "settings")
        settings = _check_settings(data["settings"], settings_node, label, errors)

    if "sources" not in data:
        errors.append(f"{label}: missing the top-level 'sources:' list")
        raise ConfigError(errors)
    entries = data["sources"]
    entries_node = next(v for k, v in root.value if k.value == "sources")
    if not isinstance(entries, list):
        errors.append(
            f"{label}:{_line(entries_node)}: 'sources' must be a list of entries "
            f"starting with '- name:', found {_kind(entries)}"
        )
        raise ConfigError(errors)
    if not entries:
        errors.append(f"{label}:{_line(entries_node)}: 'sources' is empty; add at least one source")

    sources: list[Source] = []
    seen_names: dict[str, int] = {}
    for index, (entry, node) in enumerate(zip(entries, entries_node.value), start=1):
        line = _line(node)
        source, entry_errors = _check_entry(entry, node, index)
        prefix = f"{label}:{line}: {_who(entry, index)}"
        errors.extend(f"{prefix}: {problem}" for problem in entry_errors)

        if source is not None:
            folded = source.name.casefold()
            if folded in seen_names:
                errors.append(
                    f"{prefix}: duplicate name (also used on line {seen_names[folded]}); "
                    "names must be unique"
                )
            else:
                seen_names[folded] = line
            if not entry_errors:
                sources.append(source)

    if errors:
        raise ConfigError(errors)
    return Config(sources, settings)


def webhook_warnings(
    sources: list[Source],
    env: Mapping[str, str] | None = None,
    settings: Settings = DEFAULTS,
) -> list[str]:
    """Name each category that has enabled sources but no webhook set.

    Only checks that the variable is non-empty; never returns its value.
    """
    env = os.environ if env is None else env
    warnings = []
    for category in CATEGORIES:
        count = sum(1 for s in sources if s.enabled and s.category == category)
        variable = settings.webhooks[category]
        if count and not env.get(variable, "").strip():
            plural = "source" if count == 1 else "sources"
            warnings.append(
                f'no webhook for category "{category}": '
                f"{variable} is not set, "
                f"so {count} enabled {plural} will not post"
            )
    return warnings


def key_warnings(sources: list[Source], env: Mapping[str, str] | None = None) -> list[str]:
    """Name the API key variable when an enabled source needs it and it is unset.

    Only checks that the variable is non-empty; never returns its value.
    """
    env = os.environ if env is None else env
    count = sum(1 for s in sources if s.enabled and s.type == "ransomware")
    if not count or env.get(RANSOMWARE_KEY_ENV, "").strip():
        return []
    plural = "source" if count == 1 else "sources"
    return [
        f"no ransomware.live API key: {RANSOMWARE_KEY_ENV} is not set, "
        f"so {count} enabled ransomware {plural} will fail to fetch"
    ]


def _check_settings(
    data: object, node: yaml.Node, label: str, errors: list[str]
) -> Settings:
    """Validate the settings section into ``errors``; return what is usable."""
    if data is None:
        return DEFAULTS
    if not isinstance(data, Mapping):
        errors.append(
            f"{label}:{_line(node)}: 'settings' must be a set of fields like "
            f"'cvss_min: 9.8', found {_kind(data)}"
        )
        return DEFAULTS

    values: dict[str, object] = {}
    keys = [k.value for k, _ in node.value]
    for key_node, value_node in node.value:
        key = key_node.value
        where = f"{label}:{_line(key_node)}: settings"
        if keys.count(key) > 1:
            errors.append(f"{where}: {key!r} appears more than once")
            continue
        if key not in SETTINGS_KEYS:
            errors.append(
                f"{where}: unknown setting {key!r}{_suggest(str(key), SETTINGS_KEYS)} "
                f"(allowed: {', '.join(SETTINGS_KEYS)})"
            )
            continue
        value = data[key]
        if key == "webhooks":
            webhooks = _check_webhooks(value, value_node, f"{label}:{_line(value_node)}: settings")
            if isinstance(webhooks, list):
                errors.extend(webhooks)
            else:
                values[key] = webhooks
            continue
        if key == "channel_caps":
            caps = _check_channel_caps(value, f"{label}:{_line(value_node)}: settings")
            if isinstance(caps, list):
                errors.extend(caps)
            else:
                values[key] = caps
            continue
        if key == "watchlist":
            watchlist = _check_watchlist(value, f"{label}:{_line(value_node)}: settings")
            if isinstance(watchlist, list):
                errors.extend(watchlist)
            else:
                values[key] = watchlist
            continue
        problem, checked = _check_setting(key, value)
        if problem:
            errors.append(f"{where}: {problem}")
        else:
            values[key] = checked

    settings = Settings(**values)
    if "max_age_days" in values or "keep_days" in values:
        floor = KEEP_TO_MAX_AGE * settings.max_age_days
        if settings.keep_days < floor:
            errors.append(
                f"{label}:{_line(node)}: settings: 'keep_days' ({settings.keep_days}) must be "
                f"at least {KEEP_TO_MAX_AGE} times 'max_age_days' ({settings.max_age_days}), "
                f"so at least {floor}: a pruned item that a feed lists again must be "
                "old enough for the flood guard to hold it back"
            )
    return settings


def _check_setting(key: str, value: object) -> tuple[str, object]:
    """Return (problem, value); an empty problem means the value is valid."""
    if key == "cvss_min":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 10:
            return f"'cvss_min' must be a number from 0 to 10, found {_show(value)}", None
        return "", float(value)
    low, high = {
        # Upper bounds keep a run inside its one-minute budget: lookups are
        # 0.7 s apart, and 5 channels of 25 posts are 125 posts.
        "cve_lookups_per_run": (0, 40),
        "posts_per_channel": (1, 25),
        "new_source_posts": (0, 25),
        "max_age_days": (1, None),
        "keep_days": (1, None),
    }[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < low or (
        high is not None and value > high
    ):
        span = f"from {low} to {high}" if high is not None else f"of {low} or more"
        return f"{key!r} must be a whole number {span}, found {_show(value)}", None
    return "", value


def _check_watchlist(value: object, where: str) -> Watchlist | list[str]:
    """The watchlist, or its problems."""
    if value is None:
        return Watchlist()
    if not isinstance(value, Mapping):
        return [
            f"{where}: 'watchlist' must be a set of fields like 'min_cvss: 7.0' "
            f"and 'products:', found {_kind(value)}"
        ]
    problems = []
    for key in value:
        if key not in WATCHLIST_KEYS:
            problems.append(
                f"{where}: watchlist: unknown field {_show(key)}"
                f"{_suggest(str(key), WATCHLIST_KEYS)} (allowed: {', '.join(WATCHLIST_KEYS)})"
            )
    min_cvss = value.get("min_cvss", Watchlist.min_cvss)
    if isinstance(min_cvss, bool) or not isinstance(min_cvss, (int, float)) or not 0 <= min_cvss <= 10:
        problems.append(
            f"{where}: watchlist: 'min_cvss' must be a number from 0 to 10, found {_show(min_cvss)}"
        )
    group_min = value.get("group_min", Watchlist.group_min)
    low, high = GROUP_MIN_RANGE
    if isinstance(group_min, bool) or not isinstance(group_min, int) or not low <= group_min <= high:
        problems.append(
            f"{where}: watchlist: 'group_min' must be a whole number from {low} to {high}, "
            f"found {_show(group_min)}"
        )
    products = value.get("products") or []
    if not isinstance(products, list):
        problems.append(
            f"{where}: watchlist: 'products' must be a list of product names "
            f"(one '- name' a line), found {_kind(products)}"
        )
        products = []
    names, folded = [], set()
    for index, product in enumerate(products, start=1):
        name = " ".join(product.split()) if isinstance(product, str) else ""
        if not re.search(r"\w", name):
            problems.append(
                f"{where}: watchlist: product {index} must be a name, found {_show(product)}"
            )
        elif name.casefold() in folded:
            problems.append(f"{where}: watchlist: product {_show(name)} appears more than once")
        else:
            names.append(name)
            folded.add(name.casefold())
    if problems:
        return problems
    return Watchlist(float(min_cvss), tuple(names), group_min)


def _check_channel_caps(value: object, where: str) -> dict[str, int] | list[str]:
    """The category -> cap mapping with defaults filled in, or its problems."""
    if not isinstance(value, Mapping):
        return [
            f"{where}: 'channel_caps' must be a set of fields like 'ransomware: 25', "
            f"found {_kind(value)}"
        ]
    problems = []
    caps = dict(CHANNEL_CAPS)
    low, high = 1, 25
    for category, cap in value.items():
        if category not in CATEGORIES:
            problems.append(
                f"{where}: channel_caps: unknown category {_show(category)}"
                f"{_suggest(str(category), CATEGORIES)} (allowed: {', '.join(CATEGORIES)})"
            )
        elif isinstance(cap, bool) or not isinstance(cap, int) or not low <= cap <= high:
            problems.append(
                f"{where}: channel_caps: {category!r} must be a whole number "
                f"from {low} to {high}, found {_show(cap)}"
            )
        else:
            caps[category] = cap
    return problems or caps


def _check_webhooks(value: object, node: yaml.Node, where: str) -> dict[str, str] | list[str]:
    """The category -> variable mapping with defaults filled in, or its problems."""
    if not isinstance(value, Mapping):
        return [
            f"{where}: 'webhooks' must be a set of fields like 'news: WEBHOOK_NEWS', "
            f"found {_kind(value)}"
        ]
    problems = []
    keys = [k.value for k, _ in node.value]
    for category in sorted({k for k in keys if keys.count(k) > 1}, key=str):
        problems.append(f"{where}: webhooks: {category!r} appears more than once")
    mapping = dict(WEBHOOK_ENV)
    for category, variable in value.items():
        if category not in CATEGORIES:
            problems.append(
                f"{where}: webhooks: unknown category {_show(category)}"
                f"{_suggest(str(category), CATEGORIES)} (allowed: {', '.join(CATEGORIES)})"
            )
        elif not isinstance(variable, str) or not _ENV_NAME.fullmatch(variable):
            # Never echo the value: it may be a pasted webhook URL.
            found = (
                "what looks like a URL; the URL goes in that variable, not here"
                if isinstance(variable, str) and "://" in variable
                else f"{_kind(variable)} that is not a variable name"
            )
            problems.append(
                f"{where}: webhooks: {category!r} must name an environment variable in "
                f"capitals, like WEBHOOK_{category.upper()}; found {found}"
            )
        else:
            mapping[category] = variable
    return problems or mapping


def _check_entry(
    entry: object, node: yaml.Node, index: int
) -> tuple[Source | None, list[str]]:
    """Return the Source (when the name is usable) and the entry's problems."""
    if not isinstance(entry, Mapping):
        return None, [
            f"expected fields like 'name:' and 'url:', found {_kind(entry)}; "
            "check the indentation against the template"
        ]

    problems: list[str] = []
    keys = [k.value for k, _ in node.value]
    for key in sorted({k for k in keys if keys.count(k) > 1}, key=str):
        problems.append(f"field {key!r} appears more than once")
    for key in entry:
        if key not in ALL_FIELDS:
            problems.append(
                f"unknown field {key!r}{_suggest(str(key), ALL_FIELDS)} "
                f"(allowed: {', '.join(ALL_FIELDS)})"
            )
    for required in REQUIRED_FIELDS:
        if required not in entry or entry[required] is None:
            problems.append(f"missing required field {required!r}")

    name = entry.get("name")
    if name is not None and (not isinstance(name, str) or not name.strip()):
        problems.append("'name' must be non-empty text")
        name = None

    url = entry.get("url")
    if url is not None:
        problems.extend(_check_url(url))
    links = {}
    for key in ("site", "icon"):
        value = entry.get(key)
        if value is None or value == "":
            links[key] = None
            continue
        found = _check_url(value, key)
        problems.extend(found)
        links[key] = None if found else value.strip()

    for key, allowed in (("type", TYPES), ("category", CATEGORIES)):
        value = entry.get(key)
        if value is not None and value not in allowed:
            problems.append(
                f"unknown {key} {_show(value)}{_suggest(str(value), allowed)} "
                f"(allowed: {', '.join(allowed)})"
            )

    kind, category = entry.get("type"), entry.get("category")
    if kind in TYPES and category in CATEGORIES:
        if kind in TYPE_CATEGORY and category != TYPE_CATEGORY[kind]:
            problems.append(f"type {kind} must use category {TYPE_CATEGORY[kind]!r}")
        elif kind not in TYPE_CATEGORY and category in TYPE_CATEGORY.values():
            problems.append(f"category {category!r} is only for type {category}")

    enabled = entry.get("enabled", True)
    if not isinstance(enabled, bool):
        problems.append(f"'enabled' must be true or false, found {_show(enabled)}")

    revisions = entry.get("revisions", False)
    if not isinstance(revisions, bool):
        problems.append(f"'revisions' must be true or false, found {_show(revisions)}")
    elif revisions and entry.get("type") in ("kev", "nvd", "ransomware"):
        problems.append("'revisions' applies only to type rss")

    cve_filter = entry.get("cve_filter", False)
    if not isinstance(cve_filter, bool):
        problems.append(f"'cve_filter' must be true or false, found {_show(cve_filter)}")
    elif cve_filter and entry.get("type") in ("kev", "nvd"):
        problems.append(
            "'cve_filter' applies only to type rss (kev always posts; nvd is always filtered)"
        )
    elif cve_filter and entry.get("type") == "ransomware":
        problems.append("'cve_filter' applies only to type rss")

    notes = entry.get("notes", "")
    if notes is None:
        notes = ""
    elif not isinstance(notes, str):
        problems.append(f"'notes' must be text, found {_kind(notes)}")

    if not isinstance(name, str):
        return None, problems
    return (
        Source(
            name=name,
            url=url if isinstance(url, str) else "",
            type=str(entry.get("type")),
            category=str(entry.get("category")),
            enabled=enabled is True,
            notes=notes if isinstance(notes, str) else "",
            revisions=revisions is True,
            cve_filter=cve_filter is True,
            site=links["site"],
            icon=links["icon"],
        ),
        problems,
    )


def _check_url(url: object, field: str = "url") -> list[str]:
    if not isinstance(url, str):
        return [f"{field!r} must be text, found {_kind(url)}"]
    if any(ch.isspace() for ch in url.strip()):
        return [f"{field!r} contains spaces (found \"{url}\")"]
    parts = urlsplit(url.strip())
    if parts.scheme != "https":
        return [f"{field!r} must start with https:// (found \"{url}\")"]
    if not parts.hostname or "." not in parts.hostname:
        return [f"{field!r} has no valid host name (found \"{url}\")"]
    return []


def _who(entry: object, index: int) -> str:
    name = entry.get("name") if isinstance(entry, Mapping) else None
    if isinstance(name, str) and name.strip():
        return f'source "{name.strip()}"'
    return f"entry {index} (no name)"


def _suggest(value: str, allowed: tuple[str, ...]) -> str:
    match = difflib.get_close_matches(value.lower(), allowed, n=1, cutoff=0.6)
    return f"; did you mean {match[0]!r}?" if match else ""


def _show(value: object) -> str:
    return f'"{value}"' if isinstance(value, str) else f"{value!r} ({_kind(value)})"


def _kind(value: object) -> str:
    if value is None:
        return "nothing"
    if isinstance(value, bool):
        return "true/false"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "text"
    if isinstance(value, list):
        return "a list"
    if isinstance(value, Mapping):
        return "a set of fields"
    return type(value).__name__


def _line(node: yaml.Node) -> int:
    return node.start_mark.line + 1


def _yaml_error(label: str, exc: yaml.YAMLError) -> str:
    mark = getattr(exc, "problem_mark", None)
    where = f"{label}:{mark.line + 1}" if mark is not None else label
    problem = getattr(exc, "problem", None) or str(exc)
    hint = ""
    if "mapping values are not allowed" in problem:
        hint = "; a value containing ': ' needs quotes or the '>-' block style used in notes"
    elif "found character '\\t'" in problem:
        hint = "; use spaces, not tabs, for indentation"
    return f"{where}: YAML syntax error: {problem}{hint}"
