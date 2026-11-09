"""Promote verified, digest-addressed candidates to latest and, on request, to a release version.

Must run inside the shared GitHub Actions publication concurrency group.
There is deliberately no image build here and no commit-derived mutable tag.
`latest` is the only floating tag. A release version tag is immutable: it is
created once from the promoted digest and never moved.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path

REPOSITORY = "yusoofsh/mcp-email-server"
IMAGE = "ghcr.io/" + REPOSITORY
VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?")
DIGEST_LINE = re.compile(r"^Digest:\s*(sha256:[0-9a-f]{64})\s*$", re.MULTILINE)


def candidates(directory: Path, source: str) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("Invalid source SHA")
    found = {}
    for path in sorted(directory.glob("*.json")):
        item = json.loads(path.read_text())
        arch = item.get("arch")
        if (
            item.get("source") != source
            or item.get("verified") is not True
            or item.get("checks") != "compose-oauth-http-restart-revocation"
            or arch not in {"amd64", "arm64"}
            or arch in found
            or not re.fullmatch(re.escape(IMAGE) + r"@sha256:[0-9a-f]{64}", item.get("image", ""))
        ):
            raise ValueError("Invalid or mixed candidate evidence")
        found[arch] = item["image"]
    if set(found) != {"amd64", "arm64"}:
        raise ValueError("Both native architecture smoke reports are required")
    return [found[arch] for arch in ("amd64", "arm64")]


def main_head(token: str) -> str:
    request = urllib.request.Request(
        "https://api.github.com/repos/" + REPOSITORY + "/git/ref/heads/main",
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)["object"]["sha"]


def execute(command: list[str]) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=120).stdout


def digest_of(tag: str) -> str | None:
    try:
        description = execute(["docker", "buildx", "imagetools", "inspect", IMAGE + ":" + tag])
    except subprocess.CalledProcessError as error:
        if "not found" in (error.stderr or "").lower():
            return None
        raise
    match = DIGEST_LINE.search(description)
    if not match:
        raise RuntimeError("Published manifest digest missing")
    return match.group(1)


def tag_version(version: str, digest: str) -> None:
    existing = digest_of(version)
    if existing is not None and existing != digest:
        raise RuntimeError("Version tag " + version + " already points at a different image")
    if existing is None:
        execute(
            ["docker", "buildx", "imagetools", "create", "--tag", IMAGE + ":" + version, IMAGE + "@" + digest]
        )
    if digest_of(version) != digest:
        raise RuntimeError("Version tag " + version + " does not match the promoted digest")


def promote(directory: Path, source: str, token: str, version: str | None = None) -> str | None:
    if version is not None and not VERSION.fullmatch(version):
        raise ValueError("Invalid release version")
    refs = candidates(directory, source)
    # This check occurs while holding the single publisher lock, immediately before promotion.
    if main_head(token) != source:
        print("SKIP: this is not the current main commit; latest was not modified")
        return None
    execute(["docker", "buildx", "imagetools", "create", "--tag", IMAGE + ":latest", *refs])
    raw = json.loads(execute(["docker", "buildx", "imagetools", "inspect", "--raw", IMAGE + ":latest"]))
    platforms = {
        (item.get("platform", {}).get("os"), item.get("platform", {}).get("architecture"))
        for item in raw.get("manifests", [])
        if item.get("platform", {}).get("os") != "unknown"
    }
    if platforms != {("linux", "amd64"), ("linux", "arm64")}:
        raise RuntimeError("Published manifest has unexpected platforms")
    description = execute(["docker", "buildx", "imagetools", "inspect", IMAGE + ":latest"])
    match = DIGEST_LINE.search(description)
    if not match:
        raise RuntimeError("Published manifest digest missing")
    if version is not None:
        tag_version(version, match.group(1))
    return match.group(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--version", help="Also tag the promoted image, for example 1.9.1-ys.1")
    args = parser.parse_args()
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise SystemExit("Publication is allowed only from the canonical main branch")
    result = promote(args.evidence, args.source_sha, os.environ["GH_TOKEN"], args.version)
    tags = "`:latest`" + (f" and `:{args.version}`" if args.version else "")
    summary = (
        f"Published `{IMAGE}` as {tags}\n\nExact artifact: `{IMAGE}@{result}`\n"
        if result
        else "Stale run skipped; latest unchanged.\n"
    )
    print(summary)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
        output.write(summary)


if __name__ == "__main__":
    main()
