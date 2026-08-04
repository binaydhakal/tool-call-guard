/**
 * tool-call-guard — deny-by-default policy gate for AI agent tool calls.
 *
 * Prompt injection becomes materially dangerous the moment a model can call
 * tools: untrusted input can steer an agent into tool calls with the
 * operator's authority. This library is the enforcement layer the incident
 * reports keep recommending — least-privilege allowlists, argument
 * validation, rate caps, human approval for high-risk actions — as one
 * deterministic policy engine that wraps any framework's tools.
 *
 * The policy model is deliberately JSON-friendly and identical across the
 * JS and Python implementations, so one security review covers both stacks.
 */

export type RuleAction = "allow" | "deny" | "approve";

/**
 * Argument validator: a predicate returning `true` (pass), `false`, or a
 * string reason (fail) — or a zod-style schema exposing `safeParse`.
 * A thrown error also counts as a failure, with its message as the reason.
 */
export type Validator =
  | ((args: unknown) => boolean | string)
  | { safeParse: (args: unknown) => { success: boolean; error?: { message?: string } } };

export interface ToolRule {
  /** What matching calls do. Default "allow" (the rule's existence allowlists it). */
  action?: RuleAction;
  /** Validate call arguments before anything else consumes quota. */
  validate?: Validator;
  /** Total allowed calls per guard lifetime (shared across a wildcard rule). */
  maxCalls?: number;
  /** Allowed calls per sliding 60s window (shared across a wildcard rule). */
  maxCallsPerMinute?: number;
}

export interface Policy {
  /** What happens when no rule matches. Default "deny" — the safe default. */
  defaultAction?: "allow" | "deny";
  /**
   * Rules keyed by tool name or `*` wildcard pattern (e.g. `"fs_*"`, `"*"`).
   * Exact names beat patterns; longer (more literal) patterns beat shorter.
   */
  tools?: Record<string, ToolRule>;
}

export interface ApprovalRequest {
  tool: string;
  args: unknown;
  /** The policy key that matched. */
  rule: string;
}

export interface Decision {
  /** Whether the call may proceed. Always true in dry-run mode. */
  allowed: boolean;
  action: RuleAction;
  reason: string;
  tool: string;
  /** The policy key that matched, if any. */
  rule?: string;
  /** Present in dry-run mode: what enforcement WOULD have decided. */
  wouldAllow?: boolean;
  dryRun?: boolean;
}

export interface AuditEvent {
  /** ISO timestamp (from the injectable clock). */
  time: string;
  tool: string;
  rule?: string;
  action: RuleAction;
  allowed: boolean;
  reason: string;
  mode: "enforce" | "dry-run";
  /** Included unless auditArgs: false. */
  args?: unknown;
  wouldAllow?: boolean;
}

export interface GuardOptions {
  /**
   * "enforce" (default) blocks denied calls. "dry-run" allows everything but
   * audits what enforcement WOULD have done — observe a policy in production
   * before turning it on.
   */
  mode?: "enforce" | "dry-run";
  /** Human-in-the-loop hook for `action: "approve"` rules. May be async. */
  approve?: (request: ApprovalRequest) => boolean | Promise<boolean>;
  /** Receives every audit event (e.g. the jsonl sink from "tool-call-guard/jsonl"). */
  onAudit?: (event: AuditEvent) => void;
  /** Include call args in audit events. Default true. */
  auditArgs?: boolean;
  /** In-memory audit ring buffer size. Default 1000. */
  maxAuditEvents?: number;
  /** Injectable ms clock (tests, deterministic replay). Default Date.now. */
  now?: () => number;
}

/** Thrown by wrapped tools when the policy denies a call. */
export class ToolCallDeniedError extends Error {
  readonly decision: Decision;
  constructor(decision: Decision) {
    super(`Tool call denied: ${decision.tool} — ${decision.reason}`);
    this.name = "ToolCallDeniedError";
    this.decision = decision;
  }
}

const WINDOW_MS = 60_000;

function patternToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`);
}

/** Match a tool name against policy keys: exact first, then most-literal pattern. */
function matchRule(
  tools: Record<string, ToolRule>,
  name: string
): { key: string; rule: ToolRule } | undefined {
  if (Object.prototype.hasOwnProperty.call(tools, name) && !name.includes("*")) {
    return { key: name, rule: tools[name] };
  }
  let best: { key: string; rule: ToolRule; literal: number } | undefined;
  for (const key of Object.keys(tools)) {
    if (!key.includes("*")) continue;
    if (!patternToRegex(key).test(name)) continue;
    const literal = key.replace(/\*/g, "").length;
    if (!best || literal > best.literal) best = { key, rule: tools[key], literal };
  }
  return best && { key: best.key, rule: best.rule };
}

function runValidator(validate: Validator, args: unknown): true | string {
  try {
    if (typeof validate === "function") {
      const result = validate(args);
      if (result === true) return true;
      if (result === false) return "argument validation failed";
      return `argument validation failed: ${result}`;
    }
    const parsed = validate.safeParse(args);
    if (parsed.success) return true;
    const detail = parsed.error?.message ? `: ${parsed.error.message}` : "";
    return `argument validation failed${detail}`;
  } catch (err) {
    return `argument validation failed: ${err instanceof Error ? err.message : String(err)}`;
  }
}

export interface Guard {
  /** Evaluate the policy for one call. Does not invoke the tool. */
  check(tool: string, args?: unknown): Promise<Decision>;
  /** Wrap a tool function: denied calls throw ToolCallDeniedError, allowed pass through. */
  wrap<A, R>(tool: string, fn: (args: A, ...rest: any[]) => R): (args: A, ...rest: any[]) => Promise<Awaited<R>>;
  /**
   * Wrap a `{ name: { execute } }` tools record (the AI SDK shape) or a
   * `{ name: fn }` record. Returns the same shape with guarded executors.
   */
  wrapTools<T extends Record<string, any>>(tools: T): T;
  /** In-memory audit trail (ring buffer, newest last). */
  readonly auditLog: readonly AuditEvent[];
  /** Clear counters, rate windows, and the audit log. */
  reset(): void;
}

export function createGuard(policy: Policy, options: GuardOptions = {}): Guard {
  const tools = policy.tools ?? {};
  const defaultAction = policy.defaultAction ?? "deny";
  const mode = options.mode ?? "enforce";
  const auditArgs = options.auditArgs ?? true;
  const maxAudit = options.maxAuditEvents ?? 1000;
  const now = options.now ?? Date.now;

  let totalCalls = new Map<string, number>();
  let windows = new Map<string, number[]>();
  const auditLog: AuditEvent[] = [];

  function record(event: AuditEvent): void {
    auditLog.push(event);
    if (auditLog.length > maxAudit) auditLog.shift();
    options.onAudit?.(event);
  }

  /** The enforcement decision, before dry-run softening. Mutates quota on allow. */
  async function decide(tool: string, args: unknown, invokeApprover: boolean): Promise<Decision> {
    const match = matchRule(tools, tool);
    if (!match) {
      return defaultAction === "allow"
        ? { allowed: true, action: "allow", reason: "no rule matched; default allow", tool }
        : { allowed: false, action: "deny", reason: "no rule matched; denied by default", tool };
    }
    const { key, rule } = match;
    const action = rule.action ?? "allow";
    if (action === "deny") {
      return { allowed: false, action, reason: `denied by rule "${key}"`, tool, rule: key };
    }

    // Validation runs before quota so malformed calls never consume it.
    if (rule.validate) {
      const result = runValidator(rule.validate, args);
      if (result !== true) {
        return { allowed: false, action, reason: result, tool, rule: key };
      }
    }

    // Quota — shared per rule key, so a wildcard rule budgets its whole group.
    if (rule.maxCalls != null && (totalCalls.get(key) ?? 0) >= rule.maxCalls) {
      return {
        allowed: false,
        action,
        reason: `call budget exhausted (maxCalls: ${rule.maxCalls})`,
        tool,
        rule: key,
      };
    }
    if (rule.maxCallsPerMinute != null) {
      const cutoff = now() - WINDOW_MS;
      const window = (windows.get(key) ?? []).filter((t) => t > cutoff);
      windows.set(key, window);
      if (window.length >= rule.maxCallsPerMinute) {
        return {
          allowed: false,
          action,
          reason: `rate limit exceeded (${rule.maxCallsPerMinute}/min)`,
          tool,
          rule: key,
        };
      }
    }

    // Human-in-the-loop for high-risk actions.
    if (action === "approve") {
      if (!invokeApprover) {
        return {
          allowed: false,
          action,
          reason: "approval required (not requested in dry-run)",
          tool,
          rule: key,
        };
      }
      if (!options.approve) {
        return {
          allowed: false,
          action,
          reason: "approval required but no approver is configured",
          tool,
          rule: key,
        };
      }
      const approved = await options.approve({ tool, args, rule: key });
      if (!approved) {
        return { allowed: false, action, reason: "approval declined", tool, rule: key };
      }
    }

    // Allowed — consume quota.
    totalCalls.set(key, (totalCalls.get(key) ?? 0) + 1);
    if (rule.maxCallsPerMinute != null) {
      windows.get(key)!.push(now());
    }
    const reason = action === "approve" ? "approved" : `allowed by rule "${key}"`;
    return { allowed: true, action, reason, tool, rule: key };
  }

  async function check(tool: string, args?: unknown): Promise<Decision> {
    // Dry-run computes the real decision (approvers are NOT invoked — don't
    // page a human for a rehearsal) but lets the call proceed.
    const enforced = await decide(tool, args, mode === "enforce");
    const decision: Decision =
      mode === "dry-run"
        ? { ...enforced, allowed: true, wouldAllow: enforced.allowed, dryRun: true }
        : enforced;

    record({
      time: new Date(now()).toISOString(),
      tool,
      rule: decision.rule,
      action: decision.action,
      allowed: decision.allowed,
      reason: decision.reason,
      mode,
      ...(auditArgs ? { args } : {}),
      ...(mode === "dry-run" ? { wouldAllow: enforced.allowed } : {}),
    });
    return decision;
  }

  function wrap<A, R>(tool: string, fn: (args: A, ...rest: any[]) => R) {
    return async (args: A, ...rest: any[]): Promise<Awaited<R>> => {
      const decision = await check(tool, args);
      if (!decision.allowed) throw new ToolCallDeniedError(decision);
      return await fn(args, ...rest);
    };
  }

  function wrapTools<T extends Record<string, any>>(toolsRecord: T): T {
    const out: Record<string, any> = {};
    for (const [name, value] of Object.entries(toolsRecord)) {
      if (typeof value === "function") {
        out[name] = wrap(name, value);
      } else if (value && typeof value.execute === "function") {
        out[name] = { ...value, execute: wrap(name, value.execute.bind(value)) };
      } else {
        out[name] = value; // schema-only tools (no executor) pass through
      }
    }
    return out as T;
  }

  return {
    check,
    wrap,
    wrapTools,
    get auditLog() {
      return auditLog;
    },
    reset() {
      totalCalls = new Map();
      windows = new Map();
      auditLog.length = 0;
    },
  };
}
