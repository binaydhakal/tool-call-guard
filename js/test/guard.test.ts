import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { z } from "zod";
import {
  createGuard,
  ToolCallDeniedError,
  type AuditEvent,
  type Policy,
} from "../src/index.js";
import { jsonlAudit } from "../src/jsonl.js";

function fakeClock(start = 1_000_000) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

describe("deny-by-default", () => {
  it("denies unknown tools when no rule matches", async () => {
    const guard = createGuard({ tools: { search: {} } });
    const decision = await guard.check("delete_everything", {});
    expect(decision.allowed).toBe(false);
    expect(decision.action).toBe("deny");
    expect(decision.reason).toContain("denied by default");
  });

  it("allowlists tools that have a rule", async () => {
    const guard = createGuard({ tools: { search: {} } });
    const decision = await guard.check("search", { q: "hi" });
    expect(decision.allowed).toBe(true);
    expect(decision.rule).toBe("search");
  });

  it("defaultAction allow flips the open/closed posture", async () => {
    const guard = createGuard({ defaultAction: "allow", tools: {} });
    expect((await guard.check("anything")).allowed).toBe(true);
  });
});

describe("rules and patterns", () => {
  it("explicit deny rules block even in allow-by-default policies", async () => {
    const guard = createGuard({
      defaultAction: "allow",
      tools: { shell_exec: { action: "deny" } },
    });
    const decision = await guard.check("shell_exec", { cmd: "rm -rf /" });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('denied by rule "shell_exec"');
  });

  it("wildcard patterns match groups of tools", async () => {
    const guard = createGuard({ tools: { "fs_*": {} } });
    expect((await guard.check("fs_read", {})).allowed).toBe(true);
    expect((await guard.check("fs_write", {})).allowed).toBe(true);
    expect((await guard.check("net_fetch", {})).allowed).toBe(false);
  });

  it("exact rules beat wildcard rules", async () => {
    const guard = createGuard({
      tools: { "fs_*": {}, fs_delete: { action: "deny" } },
    });
    expect((await guard.check("fs_read")).allowed).toBe(true);
    const denied = await guard.check("fs_delete");
    expect(denied.allowed).toBe(false);
    expect(denied.rule).toBe("fs_delete");
  });

  it("more-literal patterns beat less-literal ones", async () => {
    const guard = createGuard({
      tools: { "*": {}, "db_*": { action: "deny" } },
    });
    expect((await guard.check("anything")).allowed).toBe(true);
    expect((await guard.check("db_drop")).allowed).toBe(false);
  });
});

describe("argument validation", () => {
  it("predicate validators reject with a string reason", async () => {
    const guard = createGuard({
      tools: {
        pay: { validate: (args: any) => args.amount <= 100 || "amount over limit" },
      },
    });
    expect((await guard.check("pay", { amount: 50 })).allowed).toBe(true);
    const denied = await guard.check("pay", { amount: 5000 });
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toContain("amount over limit");
  });

  it("zod schemas validate via safeParse", async () => {
    const guard = createGuard({
      tools: { search: { validate: z.object({ q: z.string().max(100) }) } },
    });
    expect((await guard.check("search", { q: "ok" })).allowed).toBe(true);
    expect((await guard.check("search", { q: 42 })).allowed).toBe(false);
  });

  it("a throwing validator denies with the error message", async () => {
    const guard = createGuard({
      tools: {
        x: {
          validate: () => {
            throw new Error("boom");
          },
        },
      },
    });
    const denied = await guard.check("x", {});
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toContain("boom");
  });

  it("invalid args do not consume the call budget", async () => {
    const guard = createGuard({
      tools: { pay: { maxCalls: 1, validate: (a: any) => a.ok === true } },
    });
    await guard.check("pay", { ok: false });
    await guard.check("pay", { ok: false });
    expect((await guard.check("pay", { ok: true })).allowed).toBe(true);
  });
});

describe("quotas", () => {
  it("maxCalls caps total allowed calls", async () => {
    const guard = createGuard({ tools: { search: { maxCalls: 2 } } });
    expect((await guard.check("search")).allowed).toBe(true);
    expect((await guard.check("search")).allowed).toBe(true);
    const third = await guard.check("search");
    expect(third.allowed).toBe(false);
    expect(third.reason).toContain("maxCalls: 2");
  });

  it("maxCallsPerMinute is a sliding window on the injectable clock", async () => {
    const clock = fakeClock();
    const guard = createGuard(
      { tools: { fetch: { maxCallsPerMinute: 2 } } },
      { now: clock.now }
    );
    expect((await guard.check("fetch")).allowed).toBe(true);
    clock.advance(1_000);
    expect((await guard.check("fetch")).allowed).toBe(true);
    clock.advance(1_000);
    const third = await guard.check("fetch");
    expect(third.allowed).toBe(false);
    expect(third.reason).toContain("2/min");
    clock.advance(59_500); // first call slides out of the 60s window
    expect((await guard.check("fetch")).allowed).toBe(true);
  });

  it("wildcard rules share one budget across their whole group", async () => {
    const guard = createGuard({ tools: { "fs_*": { maxCalls: 2 } } });
    expect((await guard.check("fs_read")).allowed).toBe(true);
    expect((await guard.check("fs_write")).allowed).toBe(true);
    expect((await guard.check("fs_list")).allowed).toBe(false);
  });

  it("reset clears quotas and the audit log", async () => {
    const guard = createGuard({ tools: { search: { maxCalls: 1 } } });
    await guard.check("search");
    expect((await guard.check("search")).allowed).toBe(false);
    guard.reset();
    expect(guard.auditLog).toHaveLength(0);
    expect((await guard.check("search")).allowed).toBe(true);
  });
});

describe("approval", () => {
  it("invokes the approver and honors its verdict", async () => {
    const requests: any[] = [];
    const guard = createGuard(
      { tools: { deploy: { action: "approve" } } },
      {
        approve: async (req) => {
          requests.push(req);
          return (req.args as { env?: string }).env !== "prod";
        },
      }
    );
    expect((await guard.check("deploy", { env: "staging" })).allowed).toBe(true);
    const denied = await guard.check("deploy", { env: "prod" });
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toBe("approval declined");
    expect(requests).toHaveLength(2);
    expect(requests[0]).toMatchObject({ tool: "deploy", rule: "deploy" });
  });

  it("approve rules deny safely when no approver is configured", async () => {
    const guard = createGuard({ tools: { deploy: { action: "approve" } } });
    const denied = await guard.check("deploy", {});
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toContain("no approver is configured");
  });
});

describe("wrap and wrapTools", () => {
  it("wrap blocks denied calls without invoking the tool", async () => {
    let invoked = 0;
    const guard = createGuard({ tools: {} });
    const wrapped = guard.wrap("nuke", async (_args: unknown) => {
      invoked += 1;
      return "done";
    });
    await expect(wrapped({})).rejects.toThrow(ToolCallDeniedError);
    await expect(wrapped({})).rejects.toThrow(/denied by default/);
    expect(invoked).toBe(0);
  });

  it("wrap passes allowed calls through with args and extra params", async () => {
    const guard = createGuard({ tools: { echo: {} } });
    const wrapped = guard.wrap("echo", (args: { msg: string }, suffix: string) => args.msg + suffix);
    await expect(wrapped({ msg: "hi" }, "!")).resolves.toBe("hi!");
  });

  it("wrapTools guards the AI SDK { execute } record shape", async () => {
    const guard = createGuard({ tools: { search: {} } });
    const tools = guard.wrapTools({
      search: { description: "find things", execute: async (a: any) => `found ${a.q}` },
      shell: { description: "danger", execute: async (_a: unknown) => "ran" },
    });
    expect(tools.search.description).toBe("find things");
    await expect(tools.search.execute({ q: "x" })).resolves.toBe("found x");
    await expect(tools.shell.execute({})).rejects.toThrow(ToolCallDeniedError);
  });

  it("wrapTools guards plain-function records and passes through schema-only tools", async () => {
    const guard = createGuard({ tools: { add: {} } });
    const tools = guard.wrapTools({
      add: (a: any) => a.x + a.y,
      schemaOnly: { description: "no executor" },
    });
    await expect(tools.add({ x: 2, y: 3 })).resolves.toBe(5);
    expect(tools.schemaOnly).toEqual({ description: "no executor" });
  });
});

describe("audit trail", () => {
  it("records every decision with action, reason, and args", async () => {
    const guard = createGuard({ tools: { search: {} } });
    await guard.check("search", { q: "hi" });
    await guard.check("unknown", { x: 1 });
    expect(guard.auditLog).toHaveLength(2);
    expect(guard.auditLog[0]).toMatchObject({
      tool: "search",
      allowed: true,
      mode: "enforce",
      args: { q: "hi" },
    });
    expect(guard.auditLog[1]).toMatchObject({ tool: "unknown", allowed: false });
  });

  it("auditArgs: false omits args from events", async () => {
    const guard = createGuard({ tools: { search: {} } }, { auditArgs: false });
    await guard.check("search", { secret: "hunter2" });
    expect("args" in guard.auditLog[0]).toBe(false);
  });

  it("the ring buffer drops oldest events past maxAuditEvents", async () => {
    const guard = createGuard({ tools: { t: {} } }, { maxAuditEvents: 2 });
    await guard.check("t", { n: 1 });
    await guard.check("t", { n: 2 });
    await guard.check("t", { n: 3 });
    expect(guard.auditLog).toHaveLength(2);
    expect(guard.auditLog[0].args).toEqual({ n: 2 });
  });

  it("forwards events to onAudit sinks", async () => {
    const events: AuditEvent[] = [];
    const guard = createGuard({ tools: {} }, { onAudit: (e) => events.push(e) });
    await guard.check("x");
    expect(events).toHaveLength(1);
    expect(events[0].allowed).toBe(false);
  });
});

describe("jsonl sink", () => {
  const dir = mkdtempSync(join(tmpdir(), "tcg-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("appends one JSON line per event, creating parent dirs", async () => {
    const file = join(dir, "nested", "audit.jsonl");
    const guard = createGuard({ tools: { search: {} } }, { onAudit: jsonlAudit(file) });
    await guard.check("search", { q: "a" });
    await guard.check("blocked", {});
    const lines = readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatchObject({ tool: "search", allowed: true });
    expect(lines[1]).toMatchObject({ tool: "blocked", allowed: false });
  });
});

describe("dry-run mode", () => {
  it("allows everything but audits what enforcement would have done", async () => {
    const guard = createGuard(
      { tools: { search: {} } },
      { mode: "dry-run" }
    );
    const denied = await guard.check("dangerous", {});
    expect(denied.allowed).toBe(true);
    expect(denied.dryRun).toBe(true);
    expect(denied.wouldAllow).toBe(false);
    const allowed = await guard.check("search", {});
    expect(allowed.wouldAllow).toBe(true);
    expect(guard.auditLog[0]).toMatchObject({ mode: "dry-run", wouldAllow: false });
  });

  it("does not invoke approvers during a rehearsal", async () => {
    let paged = 0;
    const guard = createGuard(
      { tools: { deploy: { action: "approve" } } },
      {
        mode: "dry-run",
        approve: async () => {
          paged += 1;
          return true;
        },
      }
    );
    const decision = await guard.check("deploy", {});
    expect(decision.allowed).toBe(true);
    expect(decision.wouldAllow).toBe(false); // approval wasn't granted, just not enforced
    expect(paged).toBe(0);
  });

  it("wrapped tools run in dry-run even when the policy would deny", async () => {
    const guard = createGuard({ tools: {} }, { mode: "dry-run" });
    const wrapped = guard.wrap("anything", async () => "ran");
    await expect(wrapped({})).resolves.toBe("ran");
  });
});

describe("policy reuse", () => {
  it("the same JSON policy document drives multiple guards", async () => {
    const policy: Policy = {
      defaultAction: "deny",
      tools: {
        "read_*": {},
        write_file: { action: "approve" },
        shell: { action: "deny" },
      },
    };
    const a = createGuard(policy, { approve: async () => true });
    const b = createGuard(policy);
    expect((await a.check("read_doc")).allowed).toBe(true);
    expect((await a.check("write_file")).allowed).toBe(true);
    expect((await b.check("write_file")).allowed).toBe(false); // no approver on b
    expect((await b.check("shell")).allowed).toBe(false);
  });
});
