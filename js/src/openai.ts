import type {
  ToolGuardrailFunctionOutput,
  ToolInputGuardrailDefinition,
} from "@openai/agents";
import type { Decision, Guard } from "./index.js";

export type OpenAIDeniedBehavior = "rejectContent" | "throwException";

export interface OpenAIToolInputGuardrailOptions {
  /** Name shown in OpenAI Agents SDK traces. */
  name?: string;
  /** Reject the call with model-visible content, or halt the run with a tripwire. */
  deniedBehavior?: OpenAIDeniedBehavior;
  /** Model-visible rejection message. Defaults to generic text; ignored for tripwires. */
  message?: string | ((decision: Decision) => string);
}

function denialMessage(
  decision: Decision,
  message: OpenAIToolInputGuardrailOptions["message"]
): string {
  if (typeof message === "function") return message(decision);
  return message ?? "Tool call blocked by policy.";
}

function invalidArgumentsOutput(
  behavior: OpenAIDeniedBehavior,
  tool: string
): ToolGuardrailFunctionOutput {
  const outputInfo = {
    adapterError: "invalid_tool_arguments",
    tool,
  };
  return behavior === "throwException"
    ? { behavior: { type: "throwException" }, outputInfo }
    : {
        behavior: {
          type: "rejectContent",
          message: "Tool call blocked because its arguments were not valid JSON.",
        },
        outputInfo,
      };
}

/**
 * Create an OpenAI Agents SDK input guardrail backed by a tool-call-guard policy.
 *
 * Attach the returned definition to a function tool's `inputGuardrails` array.
 * Allowed calls continue through any remaining SDK guardrails and native approval
 * checks. Denied calls never reach the tool executor.
 */
export function createOpenAIToolInputGuardrail<TContext = unknown>(
  guard: Pick<Guard, "check">,
  options: OpenAIToolInputGuardrailOptions = {}
): ToolInputGuardrailDefinition<TContext> {
  const deniedBehavior = options.deniedBehavior ?? "rejectContent";
  if (
    deniedBehavior !== "rejectContent" &&
    deniedBehavior !== "throwException"
  ) {
    throw new TypeError(
      'deniedBehavior must be "rejectContent" or "throwException"'
    );
  }

  return {
    type: "tool_input",
    name: options.name ?? "tool_call_guard",
    run: async ({ toolCall }) => {
      let args: unknown;
      try {
        args = JSON.parse(toolCall.arguments || "{}");
      } catch {
        return invalidArgumentsOutput(deniedBehavior, toolCall.name);
      }

      const decision = await guard.check(toolCall.name, args);
      const outputInfo = { decision };
      if (decision.allowed) {
        return { behavior: { type: "allow" }, outputInfo };
      }
      if (deniedBehavior === "throwException") {
        return { behavior: { type: "throwException" }, outputInfo };
      }
      return {
        behavior: {
          type: "rejectContent",
          message: denialMessage(decision, options.message),
        },
        outputInfo,
      };
    },
  };
}
