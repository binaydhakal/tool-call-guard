"""Anthropic Claude Agent SDK integration for tool-call-guard."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional, Union

from tool_call_guard import Decision, Guard

if TYPE_CHECKING:
    from claude_agent_sdk import HookMatcher

Message = Union[str, Callable[[Decision], str]]
Hook = Callable[[Dict[str, Any], Optional[str], Any], Awaitable[Dict[str, Any]]]


def _message(decision: Decision, message: Optional[Message]) -> str:
    if callable(message):
        return message(decision)
    if message is not None:
        return message
    return "Tool call blocked by policy."


def create_pre_tool_use_hook(
    guard: Guard, *, message: Optional[Message] = None
) -> Hook:
    """Create a ``PreToolUse`` hook that denies calls rejected by ``guard``.

    Allowed calls return no permission decision, preserving the SDK's native
    permission checks. Dry-run decisions therefore observe without bypassing
    or tightening those checks.
    """

    async def hook(
        input_data: Dict[str, Any],
        _tool_use_id: Optional[str],
        _context: Any,
    ) -> Dict[str, Any]:
        if input_data.get("hook_event_name") != "PreToolUse":
            return {}

        tool = input_data.get("tool_name")
        tool_name = tool if isinstance(tool, str) else ""
        decision = await guard.acheck(tool_name, input_data.get("tool_input"))
        if decision.allowed:
            return {}

        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": _message(decision, message),
            }
        }

    return hook


def create_hook_matcher(
    guard: Guard,
    *,
    matcher: Optional[str] = None,
    timeout: Optional[float] = None,
    message: Optional[Message] = None,
) -> "HookMatcher":
    """Create a ready-to-register Claude Agent SDK hook matcher."""

    try:
        from claude_agent_sdk import HookMatcher
    except ImportError as exc:
        raise ImportError(
            "Claude Agent SDK integration requires the optional dependency; "
            "install 'tool-call-guard[anthropic]'."
        ) from exc

    kwargs: Dict[str, Any] = {"hooks": [create_pre_tool_use_hook(guard, message=message)]}
    if matcher is not None:
        kwargs["matcher"] = matcher
    if timeout is not None:
        kwargs["timeout"] = timeout
    return HookMatcher(**kwargs)


__all__ = ["create_hook_matcher", "create_pre_tool_use_hook"]
