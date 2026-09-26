from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
PACKAGE_LINE = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+)==(?P<version>\S+)")


def _locked_packages(path: Path) -> dict[str, tuple[str, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    packages: dict[str, tuple[str, str]] = {}
    index = 0
    while index < len(lines):
        match = PACKAGE_LINE.match(lines[index])
        if not match:
            index += 1
            continue
        hashes: list[str] = []
        index += 1
        while index < len(lines) and lines[index].startswith("    --hash=sha256:"):
            hashes.append(lines[index])
            index += 1
        assert hashes, f"{path} has no hash for {match['name']}"
        packages[match["name"].lower().replace("_", "-")] = (match["version"], "\n".join(hashes))
    return packages


def test_runtime_and_ci_locks_pin_the_security_floor_with_hashes():
    for filename in ("requirements-runtime.txt", "requirements-ci.txt"):
        packages = _locked_packages(ROOT / filename)
        assert packages["anyio"][0] == "4.14.2"
        assert len(packages) >= 70
