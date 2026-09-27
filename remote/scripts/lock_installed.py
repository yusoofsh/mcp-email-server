"""Record the tested dependency closure for Linux/Python 3.13.

Run in a clean environment installed with .[test] after deliberate dependency
upgrades, then review the resulting pins. Does not copy unrelated site packages.
"""

import shutil
import subprocess
import tempfile
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
    uv = shutil.which("uv")
    if uv is None:
        raise SystemExit("uv is required to regenerate hash-verified remote requirements")
    for filename, extras in [("requirements-runtime.txt", set()), ("requirements-ci.txt", {"test"})]:
        packages = closure(extras)
        with tempfile.TemporaryDirectory(prefix="mcp-email-lock-") as directory:
            requirements_in = Path(directory) / "requirements.in"
            requirements_out = Path(directory) / "requirements.txt"
            requirements_in.write_text(
                "\n".join(f"{name}=={version}" for name, version in sorted(packages.items())) + "\n"
            )
            subprocess.run(
                [
                    uv,
                    "pip",
                    "compile",
                    str(requirements_in),
                    "--python-version",
                    "3.13",
                    "--python-platform",
                    "x86_64-unknown-linux-gnu",
                    "--generate-hashes",
                    "--no-annotate",
                    "--no-header",
                    "--output-file",
                    str(requirements_out),
                ],
                check=True,
            )
            install_target = "Docker" if filename == "requirements-runtime.txt" else "CI"
            (root / filename).write_text(
                "# Tested Linux / CPython 3.13 dependency closure. Regenerate with\n"
                "# `uv pip compile --generate-hashes` after deliberate dependency upgrades.\n"
                f"# {install_target} installs this file with `--require-hashes`.\n"
                + requirements_out.read_text()
            )
        print(filename, len(packages), "pinned packages")
