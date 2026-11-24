"""The lock files pin every dependency in pyproject.toml, with hashes.

requirements.lock (runtime) is what the Run workflow installs;
requirements-dev.lock (runtime plus the dev extra) is what the Test workflow
installs. A dependency added to or bumped in pyproject.toml without
regenerating both would be missing or stale in CI. Regenerate with the
commands in the "Dependencies" section of docs/how-it-works.md.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements.lock"
DEV_LOCK = ROOT / "requirements-dev.lock"
PYPROJECT = ROOT / "pyproject.toml"

PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)", re.MULTILINE)
SPEC = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*~=\s*([0-9][0-9.]*)$")


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def pins(lock: Path) -> dict[str, str]:
    return {normalize(n): v for n, v in PIN.findall(lock.read_text(encoding="utf-8"))}


def release(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def compatible(pinned: str, spec: str) -> bool:
    """True if `pinned` satisfies `~=spec` (PEP 440 compatible release)."""
    have, want = release(pinned), release(spec)
    return have >= want and have[: len(want) - 1] == want[:-1]


def direct_dependencies(*, dev: bool = False) -> list[str]:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    extra = project["optional-dependencies"]["dev"] if dev else []
    return project["dependencies"] + extra


def test_compatible_release_check():
    assert compatible("0.28.1", "0.28.1")
    assert compatible("0.28.9", "0.28.1")
    assert not compatible("0.29.0", "0.28.1")
    assert not compatible("0.28.0", "0.28.1")
    assert compatible("9.4", "9.2")
    assert not compatible("10.0", "9.2")


@pytest.mark.parametrize(("lock", "dev"), [(LOCK, False), (DEV_LOCK, True)], ids=["runtime", "dev"])
def test_every_dependency_is_pinned_compatibly(lock, dev):
    locked = pins(lock)
    for requirement in direct_dependencies(dev=dev):
        match = SPEC.match(requirement.strip())
        assert match, f"expected NAME~=VERSION in pyproject.toml, got {requirement!r}"
        name, spec = normalize(match[1]), match[2]
        assert name in locked, f"{name} is in pyproject.toml but not in {lock.name}"
        assert compatible(locked[name], spec), (
            f"{lock.name} pins {name}=={locked[name]}, outside ~={spec}"
        )


def test_tests_run_on_the_versions_the_job_runs():
    # Every runtime pin must be identical in the dev lock, so CI tests exactly
    # what the Run workflow installs.
    runtime, dev = pins(LOCK), pins(DEV_LOCK)
    differ = {n: (v, dev.get(n)) for n, v in runtime.items() if dev.get(n) != v}
    assert not differ, f"runtime pins differ between the locks (runtime, dev): {differ}"


@pytest.mark.parametrize("lock", [LOCK, DEV_LOCK], ids=["runtime", "dev"])
def test_every_pin_has_a_hash(lock):
    # CI installs with --require-hashes, which fails on any pin without one.
    blocks = re.split(r"\n(?=[A-Za-z0-9])", lock.read_text(encoding="utf-8"))
    for block in blocks:
        if PIN.match(block):
            assert "--hash=sha256:" in block, f"no hash for {block.splitlines()[0]} in {lock.name}"
