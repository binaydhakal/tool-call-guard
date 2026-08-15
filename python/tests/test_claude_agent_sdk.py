import asyncio

import pytest

from tool_call_guard import Guard
from tool_call_guard.integrations.claude_agent_sdk import (
    create_hook_matcher,
    create_pre_tool_use_hook,
)

HookMatcher = pytest.importorskip("claude_agent_sdk").HookMatcher


def input_data(tool, tool_input):
    return {
        "session_id": "session-1",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/tmp/project",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_use_id": "tool-1",
    }


def invoke(hook, payload):
    return asyncio.run(hook(payload, payload.get("tool_use_id"), None))


class TestClaudeAgentSdkAdapter:
    def test_returns_real_sdk_matcher(self):
        matcher = create_hook_matcher(
            Guard({"tools": {"mcp__docs__*": {}}}),
            matcher="mcp__docs__.*",
            timeout=3,
        )
        assert isinstance(matcher, HookMatcher)
        assert matcher.matcher == "mcp__docs__.*"
        assert matcher.timeout == 3
        assert len(matcher.hooks) == 1

    def test_allowed_calls_defer_to_native_permissions(self):
        guard = Guard({"tools": {"Read": {}}})
        hook = create_pre_tool_use_hook(guard)
        output = invoke(hook, input_data("Read", {"file_path": "README.md"}))

        assert output == {}
        assert guard.audit_log[0]["args"] == {"file_path": "README.md"}

    def test_declined_human_approval_returns_sdk_denial(self):
        approvals = []

        async def approve(request):
            approvals.append(request)
            return False

        guard = Guard(
            {"tools": {"Write": {"action": "approve"}}}, approve=approve
        )
        hook = create_pre_tool_use_hook(guard)
        output = invoke(hook, input_data("Write", {"file_path": "release.json"}))

        assert len(approvals) == 1
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert output["hookSpecificOutput"]["permissionDecisionReason"] == (
            "Tool call blocked by policy."
        )

    def test_denied_calls_return_structured_decision(self):
        guard = Guard({"tools": {"Bash": {"action": "deny"}}})
        hook = create_pre_tool_use_hook(guard)
        output = invoke(hook, input_data("Bash", {"command": "whoami"}))

        assert output == {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Tool call blocked by policy.",
            }
        }

    def test_custom_message(self):
        hook = create_pre_tool_use_hook(
            Guard({"tools": {}}), message=lambda decision: f"Blocked {decision.tool}"
        )
        output = invoke(hook, input_data("Write", {"file_path": ".env"}))
        assert output["hookSpecificOutput"]["permissionDecisionReason"] == "Blocked Write"

    def test_dry_run_preserves_native_permissions(self):
        guard = Guard({"tools": {}}, mode="dry-run")
        hook = create_pre_tool_use_hook(guard)
        output = invoke(hook, input_data("Bash", {"command": "date"}))

        assert output == {}
        assert guard.audit_log[0]["wouldAllow"] is False

    def test_non_pre_tool_events_are_ignored(self):
        guard = Guard({"tools": {}})
        hook = create_pre_tool_use_hook(guard)
        output = invoke(
            hook,
            {
                "session_id": "session-1",
                "cwd": "/tmp/project",
                "hook_event_name": "Stop",
            },
        )
        assert output == {}
        assert guard.audit_log == []
