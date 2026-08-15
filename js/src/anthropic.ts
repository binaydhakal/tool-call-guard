import type {
  HookCallback,
  HookCallbackMatcher,
  HookJSONOutput,
} from "@anthropic-ai/claude-agent-sdk";
import type { Decision, Guard } from "./index.js";

export interface AnthropicPreToolUseHookOptions {
  /** Reason returned to the SDK. Defaults to generic text. */
  message?: string | ((decision: Decision) => string);
}

export interface AnthropicHookMatcherOptions extends AnthropicPreToolUseHookOptions {
  /** Optional SDK matcher regex. Omit it to inspect every tool call. */
  matcher?: string;
  /** Timeout in seconds for the hook matcher. */
  timeout?: number;
}

function denialMessage(
  decision: Decision,
  message: AnthropicPreToolUseHookOptions["message"]
): string {
  if (typeof message === "function") return message(decision);
  return message ?? "Tool call blocked by policy.";
}

/**
 * Create a Claude Agent SDK `PreToolUse` callback backed by a guard policy.
 *
 * Allowed calls return no permission decision so the SDK's normal permission
 * system still applies. Denied calls return the SDK's structured deny result.
 */
export function createAnthropicPreToolUseHook(
  guard: Pick<Guard, "check">,
  options: AnthropicPreToolUseHookOptions = {}
): HookCallback {
  return async (input): Promise<HookJSONOutput> => {
    if (input.hook_event_name !== "PreToolUse") return {};

    const decision = await guard.check(input.tool_name, input.tool_input);
    if (decision.allowed) {
      return {};
    }

    return {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: denialMessage(decision, options.message),
      },
    };
  };
}

/** Build a ready-to-register `hooks.PreToolUse` matcher. */
export function createAnthropicHookMatcher(
  guard: Pick<Guard, "check">,
  options: AnthropicHookMatcherOptions = {}
): HookCallbackMatcher {
  const { matcher, timeout, ...hookOptions } = options;
  return {
    ...(matcher === undefined ? {} : { matcher }),
    ...(timeout === undefined ? {} : { timeout }),
    hooks: [createAnthropicPreToolUseHook(guard, hookOptions)],
  };
}
