"""Publication safety: only current main and exactly the two tested digests."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/promote_image.py"
SPEC = importlib.util.spec_from_file_location("promote_image", SCRIPT)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
SHA = "a" * 40


def evidence(root, arch="amd64", **changes):
    row = {
        "source": SHA,
        "image": release.IMAGE + "@sha256:" + ("b" if arch == "amd64" else "c") * 64,
        "arch": arch,
        "verified": True,
        "checks": "compose-oauth-http-restart-revocation",
        **changes,
    }
    (root / (arch + ".json")).write_text(json.dumps(row))


def test_missing_platform_blocks_promotion(tmp_path):
    evidence(tmp_path)
    with pytest.raises(ValueError):
        release.candidates(tmp_path, SHA)


@pytest.mark.parametrize(
    "changes",
    [
        {"source": "d" * 40},
        {"verified": False},
        {"checks": "build-only"},
        {"image": "attacker/image@sha256:" + "a" * 64},
        {"image": release.IMAGE + ":latest"},
    ],
)
def test_untrusted_or_untested_candidates_rejected(tmp_path, changes):
    evidence(tmp_path, **changes)
    evidence(tmp_path, "arm64")
    with pytest.raises(ValueError):
        release.candidates(tmp_path, SHA)


def test_stale_main_never_touches_latest(tmp_path, monkeypatch):
    evidence(tmp_path)
    evidence(tmp_path, "arm64")
    monkeypatch.setattr(release, "main_head", lambda token: "d" * 40)
    calls = []
    monkeypatch.setattr(release, "execute", lambda args: calls.append(args))
    assert release.promote(tmp_path, SHA, "test-token") is None
    assert calls == []


def test_only_latest_is_promoted_without_rebuilding(tmp_path, monkeypatch):
    evidence(tmp_path)
    evidence(tmp_path, "arm64")
    monkeypatch.setattr(release, "main_head", lambda token: SHA)
    calls = []

    def execute(args):
        calls.append(args)
        if "--raw" in args:
            return json.dumps(
                {
                    "manifests": [
                        {"platform": {"os": "linux", "architecture": arch}} for arch in ("amd64", "arm64")
                    ]
                }
            )
        if "inspect" in args:
            return "Digest: sha256:" + "f" * 64 + "\n"
        return ""

    monkeypatch.setattr(release, "execute", execute)
    assert release.promote(tmp_path, SHA, "test-token") == "sha256:" + "f" * 64
    assert calls[0] == [
        "docker",
        "buildx",
        "imagetools",
        "create",
        "--tag",
        release.IMAGE + ":latest",
        release.IMAGE + "@sha256:" + "b" * 64,
        release.IMAGE + "@sha256:" + "c" * 64,
    ]
    assert all("build" not in command for command in calls)


DIGEST = "sha256:" + "f" * 64
OTHER = "sha256:" + "e" * 64


def promote_with_version(tmp_path, monkeypatch, existing, version="1.9.1-ys.1"):
    evidence(tmp_path)
    evidence(tmp_path, "arm64")
    monkeypatch.setattr(release, "main_head", lambda token: SHA)
    calls = []
    tags = {"latest": DIGEST}
    if existing is not None:
        tags[version] = existing

    def execute(args):
        calls.append(args)
        if "create" in args:
            tags[args[args.index("--tag") + 1].rsplit(":", 1)[1]] = DIGEST
            return ""
        if "--raw" in args:
            return json.dumps(
                {
                    "manifests": [
                        {"platform": {"os": "linux", "architecture": arch}} for arch in ("amd64", "arm64")
                    ]
                }
            )
        tag = args[-1].rsplit(":", 1)[1]
        if tag not in tags:
            raise release.subprocess.CalledProcessError(
                1, args, stderr="ERROR: ghcr.io/x:" + tag + ": not found"
            )
        return "Digest: " + tags[tag] + "\n"

    monkeypatch.setattr(release, "execute", execute)
    return calls


def test_version_tag_is_created_from_the_promoted_digest(tmp_path, monkeypatch):
    calls = promote_with_version(tmp_path, monkeypatch, None)
    assert release.promote(tmp_path, SHA, "test-token", "1.9.1-ys.1") == DIGEST
    created = [args for args in calls if "create" in args]
    assert created[-1] == [
        "docker",
        "buildx",
        "imagetools",
        "create",
        "--tag",
        release.IMAGE + ":1.9.1-ys.1",
        release.IMAGE + "@" + DIGEST,
    ]
    assert all("build" not in command for command in calls)


def test_version_tag_is_never_moved(tmp_path, monkeypatch):
    calls = promote_with_version(tmp_path, monkeypatch, OTHER)
    with pytest.raises(RuntimeError, match="different image"):
        release.promote(tmp_path, SHA, "test-token", "1.9.1-ys.1")
    assert not any(args[-2:] == ["--tag", release.IMAGE + ":1.9.1-ys.1"] for args in calls)
    assert [args for args in calls if "create" in args and release.IMAGE + ":1.9.1-ys.1" in args] == []


def test_rerun_with_the_same_digest_creates_nothing(tmp_path, monkeypatch):
    calls = promote_with_version(tmp_path, monkeypatch, DIGEST)
    assert release.promote(tmp_path, SHA, "test-token", "1.9.1-ys.1") == DIGEST
    assert [args for args in calls if "create" in args and release.IMAGE + ":1.9.1-ys.1" in args] == []


@pytest.mark.parametrize("version", ["latest", "1.9", "v1.9.1", "1.9.1/../x", "1.9.1-", " 1.9.1", "1.9.1\n"])
def test_malformed_version_is_rejected_before_any_registry_call(tmp_path, monkeypatch, version):
    calls = promote_with_version(tmp_path, monkeypatch, None, version="1.0.0")
    with pytest.raises(ValueError, match="Invalid release version"):
        release.promote(tmp_path, SHA, "test-token", version)
    assert calls == []
