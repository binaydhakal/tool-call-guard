# tool-call-guard

**Deny-by-default policy gate for AI agent tool calls — one policy model, enforced in JavaScript and Python.**

[![CI](https://github.com/binaydhakal/tool-call-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/binaydhakal/tool-call-guard/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@yanib/tool-call-guard?label=npm)](https://www.npmjs.com/package/@yanib/tool-call-guard)
[![PyPI](https://img.shields.io/pypi/v/tool-call-guard?label=pypi)](https://pypi.org/project/tool-call-guard/)
[![license](https://img.shields.io/badge/license-MIT-b8973d)](./LICENSE)

Prompt injection becomes materially dangerous the moment a model can call tools: untrusted input — a web page, an email, a ticket — can steer an agent into tool calls with the operator's authority. OWASP catalogued over 500 tool-misuse incidents in 2026 alone, and every post-mortem recommends the same defenses: least-privilege allowlists, argument validation, rate caps, human approval for high-risk actions.

This repository is those defenses as a deterministic library. No AI inside — a policy engine you can read in one sitting, test exhaustively, and wrap around any framework's tools.

## One policy, two runtimes

The policy is a JSON-friendly document, identical in both languages. Write it once, review it once, enforce it in your Node gateway *and* your Python agents:

```jsonc
{
  "defaultAction": "deny",
  "tools": {
    "search_*":   {},                                        // allowlisted group
    "send_email": { "maxCallsPerMinute": 5 },                // rate-capped
    "deploy":     { "action": "approve" },                   // human-in-the-loop
    "shell_exec": { "action": "deny" }                       // never
  }
}
```

Audit events share one schema across both implementations (JSONL sinks included), so a single dashboard watches your whole fleet.

| | JavaScript / TypeScript | Python |
|---|---|---|
| Package | [`@yanib/tool-call-guard` on npm](https://www.npmjs.com/package/@yanib/tool-call-guard) | [`tool-call-guard` on PyPI](https://pypi.org/project/tool-call-guard/) |
| Source | [`js/`](./js) | [`python/`](./python) |
| Validation | zod-style `safeParse` or predicates | pydantic-style `model_validate` or callables |
| Wrappers | `wrap`, `wrapTools` (AI SDK `{ execute }` shape) | `wrap`, `@guard.protect`, `wrap_tools` |
| OpenAI Agents | `createOpenAIToolInputGuardrail` | `create_tool_input_guardrail` |
| Claude Agent SDK | `createAnthropicHookMatcher` | `create_hook_matcher` |
| Async | async `check`, async approvers | `check` / `acheck`, sync or async approvers |

## Provider-native adapters

Version 0.2 adds optional adapters for the OpenAI Agents SDK and Anthropic Claude Agent SDK in both runtimes. They translate provider tool-call events into the same deny-by-default policy decisions and audit records used by the framework-agnostic core.

- **OpenAI Agents:** attach the adapter to a function tool's input guardrails. A denial can return safe model-visible content or trip the run immediately.
- **Claude Agent SDK:** register the adapter as a `PreToolUse` hook. Denied calls return a structured SDK denial; allowed calls still pass through Claude's native permission system.
- **Safe rollout:** dry-run mode records what the policy would block while allowing the provider SDK to continue normally.

The core packages remain dependency-free. Install only the SDK adapter you use; see the [JavaScript](./js#provider-adapters) and [Python](./python#provider-adapters) examples.

## Design decisions worth knowing

- **Deny-by-default.** An empty policy blocks everything. Security posture should be opt-in, not opt-out.
- **Validation before quota.** Malformed calls never consume budget — an attacker can't starve a tool by spamming garbage.
- **Wildcard rules share one budget.** `"fs_*": { "maxCalls": 10 }` is ten calls across the whole group, not ten per tool.
- **No approver means deny.** An `approve` rule without a configured approver fails closed.
- **Dry-run is a first-class mode.** Ship the guard in `dry-run`, watch the audit trail for what *would* have been blocked, then flip to `enforce`. Approvers are never invoked during a rehearsal — no paging a human for practice.
- **Injectable clocks.** Rate windows are tested with fake time, deterministically — and you can replay production timelines the same way.

## Scope, honestly

This is runtime *enforcement* — the layer OWASP's recommendations describe. It is complementary to MCP *scanners* (which detect malicious tool definitions before you install them) and to model-level guardrails (which filter prompts and outputs). Defense in depth wants all three; this repo is the middle layer, deliberately small enough to audit.

## Releases

npm and PyPI release candidates are built from the same commit, tested, checked, and stored as immutable GitHub Actions artifacts before publication. See the [release guide](./RELEASING.md) for the versioning and verification procedure.

## License

MIT © [Binaya Dhakal](https://www.dhakalbinaya.com.np)
