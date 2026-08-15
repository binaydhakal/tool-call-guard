"""tool-call-guard -- deny-by-default policy gate for AI agent tool calls.

Prompt injection becomes materially dangerous the moment a model can call
tools: untrusted input can steer an agent into tool calls with the operator's
authority. This library is the enforcement layer the incident reports keep
recommending -- least-privilege allowlists, argument validation, rate caps,
human approval for high-risk actions -- as one deterministic policy engine
that wraps any framework's tools.

The policy document is JSON-friendly and identical across the JS and Python
implementations (canonical keys are camelCase, e.g. ``maxCalls``; snake_case
aliases are accepted in Python), so one security review covers both stacks.
Audit events share the same schema in both languages.
"""

from __future__ import annotations

import functools
import inspect
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

__version__ = "0.2.0"

_WINDOW_SECONDS = 60.0

Policy = Dict[str, Any]
AuditEvent = Dict[str, Any]


@dataclass
class Decision:
    """The outcome of evaluating one tool call against the policy."""

    allowed: bool
    action: str  # "allow" | "deny" | "approve"
    reason: str
    tool: str
    rule: Optional[str] = None
    #: Present in dry-run mode: what enforcement WOULD have decided.
    would_allow: Optional[bool] = None
    dry_run: bool = False


class ToolCallDenied(Exception):
    """Raised by wrapped tools when the policy denies a call."""

    def __init__(self, decision: Decision):
        super().__init__(f"Tool call denied: {decision.tool} -- {decision.reason}")
        self.decision = decision


def _rule_get(rule: Dict[str, Any], camel: str, snake: str) -> Any:
    """Read a rule option by its canonical camelCase key or snake_case alias."""
    if camel in rule:
        return rule[camel]
    return rule.get(snake)


def _pattern_to_regex(pattern: str) -> "re.Pattern[str]":
    escaped = re.escape(pattern).replace(r"\*", ".*")
    return re.compile(f"^{escaped}$")


def _match_rule(tools: Dict[str, Any], name: str) -> Optional[tuple]:
    """Exact names beat patterns; longer (more literal) patterns beat shorter."""
    if name in tools and "*" not in name:
        return name, tools[name]
    best = None
    for key, rule in tools.items():
        if "*" not in key:
            continue
        if not _pattern_to_regex(key).match(name):
            continue
        literal = len(key.replace("*", ""))
        if best is None or literal > best[2]:
            best = (key, rule, literal)
    return (best[0], best[1]) if best else None


def _run_validator(validate: Any, args: Any) -> Any:
    """True on pass; a string reason on failure."""
    try:
        # Pydantic-style model classes are ALSO callable (calling one constructs
        # it), so the model_validate check must come first.
        model_validate = getattr(validate, "model_validate", None)
        if callable(model_validate):
            model_validate(args)
            return True
        if callable(validate):
            result = validate(args)
            if result is True or result is None:
                return True
            if result is False:
                return "argument validation failed"
            return f"argument validation failed: {result}"
        return f"argument validation failed: unsupported validator {type(validate).__name__}"
    except Exception as err:  # noqa: BLE001 -- validator errors become deny reasons
        return f"argument validation failed: {err}"


class Guard:
    """A policy-enforcing gate. Create one per agent session (quotas are per guard)."""

    def __init__(
        self,
        policy: Policy,
        *,
        mode: str = "enforce",
        approve: Optional[Callable[[Dict[str, Any]], Any]] = None,
        on_audit: Optional[Callable[[AuditEvent], None]] = None,
        audit_args: bool = True,
        max_audit_events: int = 1000,
        now: Optional[Callable[[], float]] = None,
    ):
        if mode not in ("enforce", "dry-run"):
            raise ValueError(f'mode must be "enforce" or "dry-run", got {mode!r}')
        self._tools: Dict[str, Any] = policy.get("tools") or {}
        self._default_action = (
            policy.get("defaultAction") or policy.get("default_action") or "deny"
        )
        self._mode = mode
        self._approve = approve
        self._on_audit = on_audit
        self._audit_args = audit_args
        self._max_audit = max_audit_events
        self._now = now or time.time
        self._total_calls: Dict[str, int] = {}
        self._windows: Dict[str, List[float]] = {}
        #: In-memory audit trail (ring buffer, newest last). Same schema as JS.
        self.audit_log: List[AuditEvent] = []

    # ------------------------------------------------------------------ core

    def _decide(self, tool: str, args: Any, invoke_approver: bool) -> Decision:
        """Enforcement decision up to (not including) async approval."""
        match = _match_rule(self._tools, tool)
        if match is None:
            if self._default_action == "allow":
                return Decision(True, "allow", "no rule matched; default allow", tool)
            return Decision(False, "deny", "no rule matched; denied by default", tool)
        key, rule = match
        action = rule.get("action") or "allow"
        if action == "deny":
            return Decision(False, action, f'denied by rule "{key}"', tool, key)

        # Validation runs before quota so malformed calls never consume it.
        validate = rule.get("validate")
        if validate is not None:
            result = _run_validator(validate, args)
            if result is not True:
                return Decision(False, action, result, tool, key)

        # Quota -- shared per rule key, so a wildcard rule budgets its group.
        max_calls = _rule_get(rule, "maxCalls", "max_calls")
        if max_calls is not None and self._total_calls.get(key, 0) >= max_calls:
            return Decision(
                False, action, f"call budget exhausted (maxCalls: {max_calls})", tool, key
            )
        per_minute = _rule_get(rule, "maxCallsPerMinute", "max_calls_per_minute")
        if per_minute is not None:
            cutoff = self._now() - _WINDOW_SECONDS
            window = [t for t in self._windows.get(key, []) if t > cutoff]
            self._windows[key] = window
            if len(window) >= per_minute:
                return Decision(
                    False, action, f"rate limit exceeded ({per_minute}/min)", tool, key
                )

        if action == "approve":
            if not invoke_approver:
                return Decision(
                    False, action, "approval required (not requested in dry-run)", tool, key
                )
            if self._approve is None:
                return Decision(
                    False,
                    action,
                    "approval required but no approver is configured",
                    tool,
                    key,
                )
            # The caller handles sync-vs-async approval; sentinel Decision here.
            return Decision(True, action, "__needs_approval__", tool, key)

        self._consume(key, per_minute is not None)
        return Decision(True, action, f'allowed by rule "{key}"', tool, key)

    def _consume(self, key: str, track_window: bool) -> None:
        self._total_calls[key] = self._total_calls.get(key, 0) + 1
        if track_window:
            self._windows.setdefault(key, []).append(self._now())

    def _finalize_approval(self, decision: Decision, approved: bool, rule: Dict[str, Any]) -> Decision:
        if not approved:
            return Decision(False, "approve", "approval declined", decision.tool, decision.rule)
        per_minute = _rule_get(rule, "maxCallsPerMinute", "max_calls_per_minute")
        self._consume(decision.rule, per_minute is not None)  # type: ignore[arg-type]
        return Decision(True, "approve", "approved", decision.tool, decision.rule)

    def _soften_and_audit(self, tool: str, args: Any, enforced: Decision) -> Decision:
        if self._mode == "dry-run":
            decision = Decision(
                True,
                enforced.action,
                enforced.reason,
                tool,
                enforced.rule,
                would_allow=enforced.allowed,
                dry_run=True,
            )
        else:
            decision = enforced
        event: AuditEvent = {
            "time": datetime.fromtimestamp(self._now(), tz=timezone.utc).isoformat(),
            "tool": tool,
            "rule": decision.rule,
            "action": decision.action,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "mode": self._mode,
        }
        if self._audit_args:
            event["args"] = args
        if self._mode == "dry-run":
            event["wouldAllow"] = enforced.allowed
        self.audit_log.append(event)
        if len(self.audit_log) > self._max_audit:
            self.audit_log.pop(0)
        if self._on_audit is not None:
            self._on_audit(event)
        return decision

    # ------------------------------------------------------------------ API

    def check(self, tool: str, args: Any = None) -> Decision:
        """Evaluate the policy for one call. Does not invoke the tool.

        Approvers must be synchronous here; use :meth:`acheck` for async ones.
        Dry-run never invokes approvers -- don't page a human for a rehearsal.
        """
        enforced = self._decide(tool, args, invoke_approver=self._mode == "enforce")
        if enforced.reason == "__needs_approval__":
            match = _match_rule(self._tools, tool)
            request = {"tool": tool, "args": args, "rule": enforced.rule}
            verdict = self._approve(request)  # type: ignore[misc]
            if inspect.isawaitable(verdict):
                verdict.close()
                raise TypeError(
                    "approve returned an awaitable; use acheck() for async approvers."
                )
            enforced = self._finalize_approval(enforced, bool(verdict), match[1])  # type: ignore[index]
        return self._soften_and_audit(tool, args, enforced)

    async def acheck(self, tool: str, args: Any = None) -> Decision:
        """Async :meth:`check` -- accepts sync or async approvers."""
        enforced = self._decide(tool, args, invoke_approver=self._mode == "enforce")
        if enforced.reason == "__needs_approval__":
            match = _match_rule(self._tools, tool)
            request = {"tool": tool, "args": args, "rule": enforced.rule}
            verdict = self._approve(request)  # type: ignore[misc]
            if inspect.isawaitable(verdict):
                verdict = await verdict
            enforced = self._finalize_approval(enforced, bool(verdict), match[1])  # type: ignore[index]
        return self._soften_and_audit(tool, args, enforced)

    def wrap(self, tool: str, fn: Callable) -> Callable:
        """Wrap a tool function: denied calls raise ToolCallDenied.

        Sync functions get a sync wrapper (sync approvers only); async
        functions get an async wrapper that supports async approvers too.
        The first positional argument is treated as the tool-call args.
        """
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapped(args: Any = None, *rest: Any, **kwargs: Any) -> Any:
                decision = await self.acheck(tool, args)
                if not decision.allowed:
                    raise ToolCallDenied(decision)
                return await fn(args, *rest, **kwargs)

            return async_wrapped

        @functools.wraps(fn)
        def wrapped(args: Any = None, *rest: Any, **kwargs: Any) -> Any:
            decision = self.check(tool, args)
            if not decision.allowed:
                raise ToolCallDenied(decision)
            return fn(args, *rest, **kwargs)

        return wrapped

    def protect(self, tool: str) -> Callable:
        """Decorator form of :meth:`wrap`::

            @guard.protect("send_email")
            def send_email(args): ...
        """

        def decorator(fn: Callable) -> Callable:
            return self.wrap(tool, fn)

        return decorator

    def wrap_tools(self, tools: Dict[str, Callable]) -> Dict[str, Callable]:
        """Wrap a ``{name: callable}`` record; each callable is guarded by its key."""
        return {name: self.wrap(name, fn) for name, fn in tools.items()}

    def reset(self) -> None:
        """Clear quotas, rate windows, and the audit log."""
        self._total_calls = {}
        self._windows = {}
        self.audit_log.clear()


def create_guard(policy: Policy, **options: Any) -> Guard:
    """Functional alias mirroring the JS API (``createGuard``)."""
    return Guard(policy, **options)


def jsonl_audit(file_path: str) -> Callable[[AuditEvent], None]:
    """Build an ``on_audit`` sink appending each event as one JSON line."""
    state = {"ready": False}

    def sink(event: AuditEvent) -> None:
        if not state["ready"]:
            parent = os.path.dirname(file_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            state["ready"] = True
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")

    return sink


__all__ = [
    "AuditEvent",
    "Decision",
    "Guard",
    "Policy",
    "ToolCallDenied",
    "create_guard",
    "jsonl_audit",
]
