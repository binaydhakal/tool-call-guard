# @yanib/tool-call-guard

[![npm](https://img.shields.io/npm/v/@yanib/tool-call-guard)](https://www.npmjs.com/package/@yanib/tool-call-guard)
[![license](https://img.shields.io/npm/l/@yanib/tool-call-guard)](./LICENSE)

**Deny-by-default policy gate for AI agent tool calls.** The JS/TS half of [tool-call-guard](https://github.com/binaydhakal/tool-call-guard) — same JSON policy model and audit schema as the [PyPI package](https://pypi.org/project/tool-call-guard/), so one security review covers both stacks.

```ts
import { createGuard, ToolCallDeniedError } from "@yanib/tool-call-guard";
import { z } from "zod";

const guard = createGuard(
  {
    defaultAction: "deny",              // anything unlisted is blocked
    tools: {
      "search_*": {},                   // allowlist a group
      send_email: {
        validate: z.object({ to: z.string().endsWith("@mycompany.com") }),
        maxCallsPerMinute: 5,
      },
      deploy: { action: "approve" },    // human-in-the-loop
      shell_exec: { action: "deny" },
    },
  },
  { approve: async (req) => askOperator(req) }
);

// Wrap an AI SDK-style tools record — denied calls throw ToolCallDeniedError:
const tools = guard.wrapTools({
  send_email: { description: "...", execute: sendEmail },
  deploy: { description: "...", execute: deploy },
});
```

## Install

```sh
npm i @yanib/tool-call-guard
```

Zero dependencies, ESM + CJS, Node ≥18 (core also runs in edge/workers — the JSONL sink lives in a separate `@yanib/tool-call-guard/jsonl` entry so `node:fs` never touches the main bundle). Validators accept zod-style schemas (anything with `safeParse`) or plain predicates returning `true`/`false`/reason-string.

## What the policy gives you

- **Deny-by-default** — unlisted tools are blocked; the allowlist is the policy.
- **Wildcard rules** — `"fs_*"` budgets and gates a whole group; exact names beat patterns.
- **Argument validation** — runs before quota, so malformed calls never consume budget.
- **Quotas** — `maxCalls` per guard lifetime, `maxCallsPerMinute` sliding window (injectable clock).
- **Approval hooks** — `action: "approve"` calls your (possibly async) approver; no approver configured means deny, not allow.
- **Dry-run mode** — everything proceeds, but the audit trail records what enforcement *would* have done. Observe a policy in production before turning it on. Approvers are never invoked during a rehearsal.
- **Audit trail** — in-memory ring buffer plus optional sinks; `jsonlAudit(path)` writes one JSON line per decision, same schema as the Python package.

## API sketch

```ts
const guard = createGuard(policy, {
  mode: "enforce" | "dry-run",
  approve?: (req) => boolean | Promise<boolean>,
  onAudit?: (event) => void,
  auditArgs?: boolean,       // default true
  maxAuditEvents?: number,   // default 1000
  now?: () => number,        // injectable ms clock
});

await guard.check(tool, args);   // → Decision (never invokes the tool)
guard.wrap(name, fn);            // denied calls throw ToolCallDeniedError
guard.wrapTools(record);         // { name: { execute } } or { name: fn }
guard.auditLog;                  // ring buffer, newest last
guard.reset();
```

`Decision`: `allowed`, `action`, `reason`, `tool`, `rule`, and in dry-run `wouldAllow` + `dryRun`.

See the [repository root](https://github.com/binaydhakal/tool-call-guard) for the full policy reference and the threat model this addresses.

## License

MIT © [Binaya Dhakal](https://www.dhakalbinaya.com.np)
