# Changelog

All notable changes to this project are documented here.

## [0.2.0] - 2026-08-14

### Added

- OpenAI Agents SDK function-tool input guardrail adapters for JavaScript and Python.
- Anthropic Claude Agent SDK `PreToolUse` hook adapters for JavaScript and Python.
- Compatibility tests against the current released provider SDKs.
- Optional npm peer dependencies and Python extras for provider integrations.

### Security

- Provider calls fail closed when OpenAI supplies malformed JSON arguments.
- Default provider-facing denial messages do not expose internal policy reasons.
- Anthropic allow decisions preserve the SDK's native permission checks.
- Dry-run mode observes provider calls without bypassing native permission flows.
