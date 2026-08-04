# tool-call-guard (Python)

[![PyPI](https://img.shields.io/pypi/v/tool-call-guard)](https://pypi.org/project/tool-call-guard/)
[![license](https://img.shields.io/pypi/l/tool-call-guard)](../LICENSE)

**Deny-by-default policy gate for AI agent tool calls.** The Python half of [tool-call-guard](https://github.com/binaydhakal/tool-call-guard) — same JSON policy model and audit schema as the [npm package](https://www.npmjs.com/package/tool-call-guard), so one security review covers both stacks.

```python
from tool_call_guard import Guard, ToolCallDenied

guard = Guard(
    {
        "defaultAction": "deny",              # anything unlisted is blocked
        "tools": {
            "search_*": {},                   # allowlist a group
            "send_email": {
                "validate": lambda a: a["to"].endswith("@mycompany.com")
                or "external recipients need approval",
                "maxCallsPerMinute": 5,
            },
            "deploy": {"action": "approve"},  # human-in-the-loop
            "shell_exec": {"action": "deny"},
        },
    },
    approve=lambda req: ask_operator(req),    # sync here; async via acheck()
)

@guard.protect("send_email")
def send_email(args):
    ...

send_email({"to": "attacker@evil.com"})       # raises ToolCallDenied
```

## Install

```sh
pip install tool-call-guard
```

Zero dependencies, fully typed, Python 3.9+. Validators accept plain callables (return `True`/`False`/reason-string, or raise) or pydantic-style model classes (anything with `model_validate`).

## What the policy gives you

- **Deny-by-default** — unlisted tools are blocked; the allowlist is the policy.
- **Wildcard rules** — `"fs_*"` budgets and gates a whole group; exact names beat patterns.
- **Argument validation** — runs before quota, so malformed calls never consume budget.
- **Quotas** — `maxCalls` per guard lifetime, `maxCallsPerMinute` sliding window (injectable clock).
- **Approval hooks** — `action: "approve"` calls your approver; no approver configured means deny, not allow.
- **Dry-run mode** — everything proceeds, but the audit trail records what enforcement *would* have done. Observe a policy in production before turning it on. Approvers are never invoked during a rehearsal.
- **Audit trail** — in-memory ring buffer plus optional sinks; `jsonl_audit(path)` writes one JSON line per decision, same schema as the JS package.

## API sketch

```python
guard = Guard(policy, mode="enforce"|"dry-run", approve=..., on_audit=...,
              audit_args=True, max_audit_events=1000, now=time.time)

guard.check(tool, args)   -> Decision      # sync; sync approvers only
await guard.acheck(tool, args)             # async; sync or async approvers
guard.wrap(name, fn)                       # sync fn -> sync wrapper, async -> async
@guard.protect(name)                       # decorator form
guard.wrap_tools({name: fn, ...})
guard.audit_log                            # ring buffer, newest last
guard.reset()
```

`Decision`: `allowed`, `action`, `reason`, `tool`, `rule`, and in dry-run `would_allow` + `dry_run`. Denied wrapped calls raise `ToolCallDenied` (with `.decision`).

Policy keys are camelCase (portable JSON, shared with the JS package); snake_case aliases (`max_calls`, …) are accepted in Python.

See the [repository root](https://github.com/binaydhakal/tool-call-guard) for the full policy reference and the threat model this addresses.

## License

MIT © [Binaya Dhakal](https://www.dhakalbinaya.com.np)
