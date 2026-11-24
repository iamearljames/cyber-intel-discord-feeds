"""Load a local ``.env`` file into the environment.

Values already set in the environment win, so a variable exported in the
shell or passed in by Docker (``env_file`` in ``compose.yaml``) is never
replaced by the file.

Supported lines: ``NAME=value``, ``export NAME=value``, values in single or
double quotes, blank lines, ``#`` comments and unquoted trailing
`` # comments``. Warnings name the file and line, never the line's text,
because a malformed line may hold a webhook URL.
"""

from __future__ import annotations

import os
import re
from collections.abc import MutableMapping
from pathlib import Path

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Unquoted: "#" starts a comment at the start of the value or after a space.
_TRAILING_COMMENT = re.compile(r"(^|\s+)#.*$")


def load_env_file(
    path: str | os.PathLike[str],
    env: MutableMapping[str, str] | None = None,
) -> tuple[list[str], list[str]]:
    """Set variables from ``path`` that are not already set in ``env``.

    Returns ``(names_set, warnings)``. A missing file is not an error: it
    returns two empty lists.
    """
    env = os.environ if env is None else env
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], []
    except (OSError, UnicodeDecodeError) as exc:
        return [], [f"{path}: cannot read file ({type(exc).__name__}); ignored"]

    names_set: list[str] = []
    warnings: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, sep, value = line.partition("=")
        name = name.strip()
        if not sep or not _NAME.fullmatch(name):
            warnings.append(f"{path}:{lineno}: not a NAME=value line; ignored")
            continue
        value = _parse_value(value.strip())
        if value is None:
            warnings.append(f"{path}:{lineno}: {name} has an unclosed quote; ignored")
            continue
        if not value or env.get(name, "").strip():
            continue
        env[name] = value
        names_set.append(name)
    return names_set, warnings


def _parse_value(value: str) -> str | None:
    """Strip quotes or a trailing comment; None if a quote is never closed."""
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        return None if end == -1 else value[1:end]
    return _TRAILING_COMMENT.sub("", value)
