import { tool, type ToolInputGuardrailData } from "@openai/agents";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { createGuard } from "../src/index.js";
import { createOpenAIToolInputGuardrail } from "../src/openai.js";

function callData(name: string, args: string): ToolInputGuardrailData {
  return {
    toolCall: { name, arguments: args },
  } as unknown as ToolInputGuardrailData;
}

describe("OpenAI Agents SDK adapter", () => {
  it("produces a guardrail accepted by a real function tool", () => {
    const policyGuardrail = createOpenAIToolInputGuardrail(
      createGuard({ tools: { search: {} } })
    );
    const search = tool({
      name: "search",
      description: "Search documents.",
      parameters: z.object({ query: z.string() }),
      inputGuardrails: [policyGuardrail],
      execute: ({ query }) => query,
    });

    expect(search.inputGuardrails).toEqual([policyGuardrail]);
    expect(policyGuardrail).toMatchObject({
      type: "tool_input",
      name: "tool_call_guard",
    });
  });

  it("allows policy-approved calls and records the parsed arguments", async () => {
    const guard = createGuard({ tools: { search: {} } });
    const policyGuardrail = createOpenAIToolInputGuardrail(guard);

    const output = await policyGuardrail.run(
      callData("search", JSON.stringify({ query: "security" }))
    );

    expect(output.behavior).toEqual({ type: "allow" });
    expect(guard.auditLog[0]).toMatchObject({
      tool: "search",
      args: { query: "security" },
      allowed: true,
    });
  });

  it("runs human approval before allowing an approve rule", async () => {
    const approvals: unknown[] = [];
    const guard = createGuard(
      { tools: { deploy: { action: "approve" } } },
      {
        approve: async (request) => {
          approvals.push(request);
          return true;
        },
      }
    );
    const policyGuardrail = createOpenAIToolInputGuardrail(guard);

    const output = await policyGuardrail.run(
      callData("deploy", JSON.stringify({ environment: "staging" }))
    );

    expect(output.behavior).toEqual({ type: "allow" });
    expect(approvals).toEqual([
      {
        tool: "deploy",
        args: { environment: "staging" },
        rule: "deploy",
      },
    ]);
    expect(output.outputInfo).toMatchObject({
      decision: { allowed: true, action: "approve", reason: "approved" },
    });
  });

  it("rejects denied calls with a model-visible policy reason", async () => {
    const guard = createGuard({ tools: { shell: { action: "deny" } } });
    const policyGuardrail = createOpenAIToolInputGuardrail(guard);

    const output = await policyGuardrail.run(
      callData("shell", JSON.stringify({ command: "whoami" }))
    );

    expect(output.behavior).toEqual({
      type: "rejectContent",
      message: "Tool call blocked by policy.",
    });
    expect(output.outputInfo).toMatchObject({
      decision: { allowed: false, tool: "shell", rule: "shell" },
    });
  });

  it("supports tripwires", async () => {
    const policyGuardrail = createOpenAIToolInputGuardrail(
      createGuard({ tools: {} }),
      { deniedBehavior: "throwException" }
    );

    const output = await policyGuardrail.run(callData("unknown", "{}"));
    expect(output.behavior).toEqual({ type: "throwException" });
  });

  it("supports curated model-visible denial messages", async () => {
    const policyGuardrail = createOpenAIToolInputGuardrail(
      createGuard({ tools: {} }),
      { message: (decision) => `Blocked ${decision.tool}` }
    );

    const output = await policyGuardrail.run(callData("unknown", "{}"));
    expect(output.behavior).toEqual({
      type: "rejectContent",
      message: "Blocked unknown",
    });
  });

  it("rejects unknown denied behavior at runtime", () => {
    expect(() =>
      createOpenAIToolInputGuardrail(createGuard({ tools: {} }), {
        deniedBehavior: "silentlyIgnore" as never,
      })
    ).toThrow(/deniedBehavior/);
  });

  it("fails closed on malformed JSON without exposing the raw arguments", async () => {
    const guard = createGuard({ defaultAction: "allow" });
    const policyGuardrail = createOpenAIToolInputGuardrail(guard);

    const output = await policyGuardrail.run(callData("search", "{secret"));

    expect(output.behavior).toEqual({
      type: "rejectContent",
      message: "Tool call blocked because its arguments were not valid JSON.",
    });
    expect(output.outputInfo).toEqual({
      adapterError: "invalid_tool_arguments",
      tool: "search",
    });
    expect(JSON.stringify(output)).not.toContain("{secret");
    expect(guard.auditLog).toHaveLength(0);
  });

  it("preserves dry-run observation without blocking the SDK", async () => {
    const guard = createGuard({ tools: {} }, { mode: "dry-run" });
    const policyGuardrail = createOpenAIToolInputGuardrail(guard);

    const output = await policyGuardrail.run(callData("shell", "{}"));

    expect(output.behavior).toEqual({ type: "allow" });
    expect(output.outputInfo).toMatchObject({
      decision: { allowed: true, dryRun: true, wouldAllow: false },
    });
    expect(guard.auditLog[0]).toMatchObject({
      mode: "dry-run",
      wouldAllow: false,
    });
  });
});
