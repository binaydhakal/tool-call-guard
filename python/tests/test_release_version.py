import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/check_release_version.py"


def write_repository(
    root, *, npm="0.2.0", lock=None, pyproject="0.2.0", module="0.2.0"
):
    lock_version = lock or npm
    (root / "js").mkdir()
    (root / "python/src/tool_call_guard").mkdir(parents=True)
    (root / "js/package.json").write_text(
        json.dumps({"name": "example", "version": npm}), encoding="utf-8"
    )
    (root / "js/package-lock.json").write_text(
        json.dumps(
            {
                "name": "example",
                "version": lock_version,
                "lockfileVersion": 3,
                "packages": {"": {"name": "example", "version": lock_version}},
            }
        ),
        encoding="utf-8",
    )
    (root / "python/pyproject.toml").write_text(
        f'[project]\nname = "example"\nversion = "{pyproject}"\n', encoding="utf-8"
    )
    (root / "python/src/tool_call_guard/__init__.py").write_text(
        f'__version__ = "{module}"\n', encoding="utf-8"
    )
    (root / "CHANGELOG.md").write_text(
        f"# Changelog\n\n## [{npm}] - 2026-08-15\n", encoding="utf-8"
    )


def run_check(root, *args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def test_accepts_consistent_versions(tmp_path):
    write_repository(tmp_path)

    result = run_check(tmp_path)

    assert result.returncode == 0
    assert "release version 0.2.0 is consistent" in result.stdout


def test_accepts_matching_release_tag(tmp_path):
    write_repository(tmp_path)

    result = run_check(tmp_path, "--tag", "v0.2.0")

    assert result.returncode == 0
    assert "tag v0.2.0" in result.stdout


def test_rejects_mismatched_package_versions(tmp_path):
    write_repository(tmp_path, module="0.1.0")

    result = run_check(tmp_path)

    assert result.returncode == 1
    assert "release versions do not match" in result.stderr
    assert "python/src/tool_call_guard/__init__.py=0.1.0" in result.stderr


def test_rejects_stale_package_lock_version(tmp_path):
    write_repository(tmp_path, lock="0.1.0")

    result = run_check(tmp_path)

    assert result.returncode == 1
    assert "js/package-lock.json=0.1.0" in result.stderr


def test_rejects_tag_that_does_not_match_version(tmp_path):
    write_repository(tmp_path)

    result = run_check(tmp_path, "--tag", "v0.3.0")

    assert result.returncode == 1
    assert "expected 'v0.2.0'" in result.stderr
