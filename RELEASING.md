# Releasing tool-call-guard

The release-candidate workflow builds npm and PyPI distributions from one commit, verifies them, and stores them as an immutable GitHub Actions artifact. It has read-only repository permissions and cannot publish to either registry.

## Release checklist

1. Update the version in `js/package.json`, `python/pyproject.toml`, and `python/src/tool_call_guard/__init__.py`.
2. Add the matching section to `CHANGELOG.md`.
3. Run `python scripts/check_release_version.py` and the full JavaScript and Python test suites.
4. Merge the version change into `main` and confirm CI plus the release-candidate workflow are green.
5. Create a GitHub release targeting `main` with a stable tag matching the package version, such as `v0.2.0`.
6. Confirm the tag-triggered release-candidate workflow passes, then download its `release-distributions-*` artifact.
7. Inspect the archive and publish those exact files with the registry owner accounts:

   ```sh
   npm publish release-dist/npm/yanib-tool-call-guard-*.tgz --access public
   python -m twine upload release-dist/python/*
   ```

8. Confirm the npm package, PyPI files, and GitHub release all show the same version.

The workflow rejects mismatched tags or versions before building. It tests both runtimes, builds the npm archive plus Python wheel and source distribution, checks Python metadata, and uploads the verified artifacts without registry credentials.

Registry versions are immutable. If a publish fails, diagnose the registry response and reuse the same verified artifact. Never rebuild a release from a different commit under the same version.

## Future trusted publishing

npm and PyPI both support short-lived OpenID Connect credentials from GitHub Actions. Enabling that would let a protected workflow publish without stored registry tokens, but it also grants persistent package-publishing authority to a repository workflow. Add it only as a separately reviewed change after the npm and PyPI trusted-publisher identities, GitHub environments, and approval rules are explicitly agreed.
