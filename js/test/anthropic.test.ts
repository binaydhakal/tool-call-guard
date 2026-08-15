import type {
  HookCallback,
  Options,
  PreToolUseHookInput,
} from "@anthropic-ai/claude-agent-sdk";
import { describe, expect, it } from "vitest";
import {
  createAnthropicHookMatcher,
  createAnthropicPreToolUseHook,
} from "../src/anthropic.js";
import { createGuard } from "../src/index.js";

function preToolUse(name: string, input: unknown): PreToolUseHookInput {
  return {
    session_id: "session-1",
    transcript_path: "/tmp/transcript.jsonl",
    cwd: "/tmp/project",
    hook_event_name: "PreToolUse",
    tool_name: name,
    tool_input: input,
    tool_use_id: "tool-1",
  };
}

async function invoke(hook: HookCallback, input: PreToolUseHookInput) {
  return hook(input, input.tool_use_id, {
    signal: new AbortController().signal,
  });
}

describe("Anthropic Claude Agent SDK adapter", () => {
  it("builds a matcher accepted by real SDK options", () => {
    const matcher = createAnthropicHookMatcher(
      createGuard({ tools: { "mcp__docs__*": {} } }),
      { matcher: "mcp__docs__.*", timeout: 3 }
    );
    const options: Options = { hooks: { PreToolUse: [matcher] } };

    expect(options.hooks?.PreToolUse?.[0]).toMatchObject({
      matcher: "mcp__docs__.*",
      timeout: 3,
    });
    expect(matcher.hooks).toHaveLength(1);
  });

  it("defers allowed calls to the SDK's native permission system", async () => {
    const guard = createGuard({ tools: { Read: {} } });
    const hook = createAnthropicPreToolUseHook(guard);

    const output = await invoke(hook, preToolUse("Read", { file_path: "README.md" }));

    expect(output).toEqual({});
    expect(guard.auditLog[0]).toMatchObject({
      tool: "Read",
      args: { file_path: "README.md" },
      allowed: true,
    });
  });

  it("returns an SDK denial when human approval is declined", async () => {
    const approvals: unknown[] = [];
    const guard = createGuard(
      { tools: { Write: { action: "approve" } } },
      {
        approve: async (request) => {
          approvals.push(request);
          return false;
        },
      }
    );
    const hook = createAnthropicPreToolUseHook(guard);

    const output = await invoke(
      hook,
      preToolUse("Write", { file_path: "release.json" })
    );

    expect(approvals).toHaveLength(1);
    expect(output).toMatchObject({
      hookSpecificOutput: {
        permissionDecision: "deny",
        permissionDecisionReason: "Tool call blocked by policy.",
      },
    });
  });

  it("returns a structured PreToolUse denial", async () => {
    const guard = createGuard({ tools: { Bash: { action: "deny" } } });
    const hook = createAnthropicPreToolUseHook(guard);

    const output = await invoke(hook, preToolUse("Bash", { command: "whoami" }));

    expect(output).toEqual({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: "Tool call blocked by policy.",
      },
    });
  });

  it("supports custom denial messages", async () => {
    const hook = createAnthropicPreToolUseHook(createGuard({ tools: {} }), {
      message: (decision) => `Blocked ${decision.tool}`,
    });

    const output = await invoke(hook, preToolUse("Write", { file_path: ".env" }));

    expect(output).toMatchObject({
      hookSpecificOutput: {
        permissionDecision: "deny",
        permissionDecisionReason: "Blocked Write",
      },
    });
  });

  it("keeps dry-run observational and preserves native permissions", async () => {
    const guard = createGuard({ tools: {} }, { mode: "dry-run" });
    const hook = createAnthropicPreToolUseHook(guard);

    const output = await invoke(hook, preToolUse("Bash", { command: "date" }));

    expect(output).toEqual({});
    expect(guard.auditLog[0]).toMatchObject({
      mode: "dry-run",
      wouldAllow: false,
    });
  });

  it("ignores non-PreToolUse events defensively", async () => {
    const guard = createGuard({ tools: {} });
    const hook = createAnthropicPreToolUseHook(guard);
    const output = await hook(
      {
        session_id: "session-1",
        transcript_path: "/tmp/transcript.jsonl",
        cwd: "/tmp/project",
        hook_event_name: "Stop",
        stop_hook_active: false,
      },
      undefined,
      { signal: new AbortController().signal }
    );

    expect(output).toEqual({});
    expect(guard.auditLog).toHaveLength(0);
  });
});
