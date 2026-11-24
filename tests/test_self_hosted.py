"""The public bot must not point at one repository or assume git-kept state.

Anyone can run their own copy, so the code, scripts and the shipped config
name no GitHub repository, and nothing expects state on a git branch or the
job to run in GitHub Actions. State is a file at a path (``--state``).
"""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CHECKED = sorted(
    [*REPO.glob("src/**/*.py"), *REPO.glob("scripts/*.py"), REPO / "sources.yaml", REPO / ".env.example"]
)
FORBIDDEN = {
    "a GitHub repository URL": re.compile(r"github\.com[/:][\w.-]+/[\w.-]+", re.IGNORECASE),
    "state on a git branch": re.compile(r"state[`'\"]*\s+branch|\borphan\b|\blease\b", re.IGNORECASE),
    "the Actions job summary": re.compile(r"GITHUB_STEP_SUMMARY"),
    "GitHub secrets": re.compile(r"GitHub secret|repository secret", re.IGNORECASE),
}


@pytest.mark.parametrize("path", CHECKED, ids=lambda p: str(p.relative_to(REPO)))
def test_no_repository_or_git_state_assumptions(path):
    text = path.read_text(encoding="utf-8")
    found = [
        f"{what}: line {text.count(chr(10), 0, m.start()) + 1}: {m.group(0)!r}"
        for what, pattern in FORBIDDEN.items()
        for m in pattern.finditer(text)
    ]
    assert found == []


def test_the_check_covers_the_package():
    assert REPO / "src" / "intel_feeds" / "fetch.py" in CHECKED
