#!/usr/bin/env python3
"""Verify that every public version matches the optional release tag."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, Optional

STABLE_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
PYPROJECT_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
PYTHON_VERSION = re.compile(r'^__version__\s*=\s*"([^"]+)"\s*$', re.MULTILINE)


class VersionError(ValueError):
    """Raised when release version metadata is incomplete or inconsistent."""


def _match_version(path: Path, pattern: "re.Pattern[str]", label: str) -> str:
    match = pattern.search(path.read_text(encoding="utf-8"))
    if match is None:
        raise VersionError(f"could not find {label} in {path}")
    return match.group(1)


def read_versions(root: Path) -> Dict[str, str]:
    """Read every version value that is included in a public release."""

    package = json.loads((root / "js/package.json").read_text(encoding="utf-8"))
    npm_version = package.get("version")
    if not isinstance(npm_version, str):
        raise VersionError("js/package.json does not contain a string version")

    package_lock = json.loads(
        (root / "js/package-lock.json").read_text(encoding="utf-8")
    )
    lock_version = package_lock.get("version")
    lock_root_version = package_lock.get("packages", {}).get("", {}).get("version")
    if not isinstance(lock_version, str) or not isinstance(lock_root_version, str):
        raise VersionError("js/package-lock.json does not contain root versions")

    return {
        "js/package.json": npm_version,
        "js/package-lock.json": lock_version,
        "js/package-lock.json packages root": lock_root_version,
        "python/pyproject.toml": _match_version(
            root / "python/pyproject.toml", PYPROJECT_VERSION, "project version"
        ),
        "python/src/tool_call_guard/__init__.py": _match_version(
            root / "python/src/tool_call_guard/__init__.py",
            PYTHON_VERSION,
            "__version__",
        ),
    }


def validate_versions(root: Path, tag: Optional[str] = None) -> str:
    """Return the shared release version or raise ``VersionError``."""

    versions = read_versions(root)
    unique = set(versions.values())
    if len(unique) != 1:
        details = ", ".join(f"{path}={version}" for path, version in versions.items())
        raise VersionError(f"release versions do not match: {details}")

    version = unique.pop()
    if STABLE_VERSION.fullmatch(version) is None:
        raise VersionError(f"release version must be X.Y.Z, got {version!r}")

    heading = f"## [{version}]"
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if heading not in changelog:
        raise VersionError(f"CHANGELOG.md does not contain {heading}")

    if tag is not None:
        expected_tag = f"v{version}"
        if tag != expected_tag:
            raise VersionError(
                f"release tag {tag!r} does not match package version {version!r}; "
                f"expected {expected_tag!r}"
            )

    return version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the parent of scripts/)",
    )
    parser.add_argument("--tag", help="release tag to compare, for example v0.2.0")
    args = parser.parse_args()

    try:
        version = validate_versions(args.root.resolve(), args.tag)
    except (OSError, ValueError) as error:
        print(f"release version check failed: {error}", file=sys.stderr)
        return 1

    suffix = f" and tag {args.tag}" if args.tag else ""
    print(f"release version {version} is consistent{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
