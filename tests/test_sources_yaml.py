"""The committed sources.yaml and its copy-paste template pass validation."""

from __future__ import annotations

import re
from pathlib import Path

from intel_feeds.config import load_sources, parse_sources

SOURCES = Path(__file__).resolve().parents[1] / "sources.yaml"


def template_text() -> str:
    """Uncomment the copy-paste template at the top of the file."""
    lines = []
    in_block = False
    for line in SOURCES.read_text(encoding="utf-8").splitlines():
        if line.startswith("#   - name:"):
            in_block = True
        elif in_block and not re.match(r"#     \w+:", line):
            break
        if in_block:
            lines.append(line.removeprefix("# "))
    assert lines, "template block not found at the top of sources.yaml"
    return "sources:\n" + "\n".join(lines) + "\n"


def test_committed_sources_file_is_valid():
    assert len(load_sources(SOURCES)) >= 1


def test_kev_and_nvd_appear_once():
    types = [s.type for s in load_sources(SOURCES)]
    assert types.count("kev") == 1
    assert types.count("nvd") == 1


def test_template_uncomments_to_a_valid_rss_entry():
    [entry] = parse_sources(template_text())
    assert entry.type == "rss"


def test_template_needs_only_the_four_required_fields():
    four = [l for l in template_text().splitlines() if not re.match(r"\s+(enabled|notes):", l)]
    [entry] = parse_sources("\n".join(four) + "\n")
    assert entry.enabled is True and entry.notes == ""
