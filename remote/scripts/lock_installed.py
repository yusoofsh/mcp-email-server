"""Record the tested dependency closure for Linux/Python 3.13.

Run in a clean environment installed with .[test] after deliberate dependency
upgrades, then review the resulting pins. Does not copy unrelated site packages.
"""

from importlib.metadata import distribution
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def closure(extras):
    todo = [("email-mcp-remote", set(extras))]
    visited = {}
    result = {}
    env = default_environment()
    while todo:
        name, wanted = todo.pop()
        name = canonicalize_name(name)
        if name in visited and wanted <= visited[name]:
            continue
        requested = wanted | visited.get(name, set())
        visited[name] = requested
        dist = distribution(name)
        if name != "email-mcp-remote":
            result[name] = dist.version
        for text in dist.requires or []:
            req = Requirement(text)
            if req.marker and not any(
                req.marker.evaluate({**env, "extra": extra}) for extra in requested | {""}
            ):
                continue
            todo.append((req.name, set(req.extras)))
    return result


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    for filename, extras in [("requirements-runtime.txt", set()), ("requirements-ci.txt", {"test"})]:
        packages = closure(extras)
        (root / filename).write_text(
            "# Tested Linux / CPython 3.13 dependency closure. Regenerate: scripts/lock_installed.py\n"
            + "\n".join(f"{name}=={version}" for name, version in sorted(packages.items()))
            + "\n"
        )
        print(filename, len(packages), "pinned packages")
