import asyncio
from types import SimpleNamespace

import pytest

from tool_call_guard import Guard
from tool_call_guard.integrations.openai_agents import create_tool_input_guardrail

agents = pytest.importorskip("agents")
ToolInputGuardrail = agents.ToolInputGuardrail
function_tool = agents.function_tool


def data(tool, arguments):
    return SimpleNamespace(
        context=SimpleNamespace(tool_name=tool, tool_arguments=arguments)
    )


class TestOpenAIAgentsAdapter:
    def test_returns_real_sdk_guardrail(self):
        guardrail = create_tool_input_guardrail(Guard({"tools": {"search": {}}}))
        assert isinstance(guardrail, ToolInputGuardrail)
        assert guardrail.get_name() == "tool_call_guard"

    def test_real_function_tool_accepts_guardrail(self):
        guardrail = create_tool_input_guardrail(Guard({"tools": {"search": {}}}))

        @function_tool(tool_input_guardrails=[guardrail])
        def search(query: str) -> str:
            """Search documents."""
            return query

        assert search.tool_input_guardrails == [guardrail]

    def test_allows_and_audits_parsed_arguments(self):
        guard = Guard({"tools": {"search": {}}})
        guardrail = create_tool_input_guardrail(guard)
        output = asyncio.run(guardrail.run(data("search", '{"query":"security"}')))

        assert output.behavior == {"type": "allow"}
        assert guard.audit_log[0]["args"] == {"query": "security"}

    def test_runs_human_approval_before_allowing(self):
        approvals = []

        async def approve(request):
            approvals.append(request)
            return True

        guard = Guard(
            {"tools": {"deploy": {"action": "approve"}}}, approve=approve
        )
        guardrail = create_tool_input_guardrail(guard)
        output = asyncio.run(
            guardrail.run(data("deploy", '{"environment":"staging"}'))
        )

        assert output.behavior == {"type": "allow"}
        assert approvals == [
            {
                "tool": "deploy",
                "args": {"environment": "staging"},
                "rule": "deploy",
            }
        ]
        assert output.output_info["decision"]["reason"] == "approved"

    def test_rejects_denied_calls(self):
        guard = Guard({"tools": {"shell": {"action": "deny"}}})
        guardrail = create_tool_input_guardrail(guard)
        output = asyncio.run(guardrail.run(data("shell", '{"command":"whoami"}')))

        assert output.behavior == {
            "type": "reject_content",
            "message": "Tool call blocked by policy.",
        }
        assert output.output_info["decision"]["allowed"] is False

    def test_supports_tripwires(self):
        guardrail = create_tool_input_guardrail(
            Guard({"tools": {}}), denied_behavior="raise_exception"
        )
        output = asyncio.run(guardrail.run(data("unknown", "{}")))
        assert output.behavior == {"type": "raise_exception"}

    def test_supports_curated_model_visible_message(self):
        guardrail = create_tool_input_guardrail(
            Guard({"tools": {}}), message=lambda decision: f"Blocked {decision.tool}"
        )
        output = asyncio.run(guardrail.run(data("unknown", "{}")))
        assert output.behavior == {
            "type": "reject_content",
            "message": "Blocked unknown",
        }

    def test_rejects_invalid_json_without_leaking_it(self):
        guard = Guard({"defaultAction": "allow"})
        guardrail = create_tool_input_guardrail(guard)
        output = asyncio.run(guardrail.run(data("search", "{secret")))

        assert output.behavior == {
            "type": "reject_content",
            "message": "Tool call blocked because its arguments were not valid JSON.",
        }
        assert output.output_info == {
            "adapter_error": "invalid_tool_arguments",
            "tool": "search",
        }
        assert "{secret" not in repr(output)
        assert guard.audit_log == []

    def test_dry_run_observes_without_blocking(self):
        guard = Guard({"tools": {}}, mode="dry-run")
        guardrail = create_tool_input_guardrail(guard)
        output = asyncio.run(guardrail.run(data("shell", "{}")))

        assert output.behavior == {"type": "allow"}
        assert output.output_info["decision"]["dry_run"] is True
        assert output.output_info["decision"]["would_allow"] is False

    def test_rejects_unknown_denied_behavior(self):
        try:
            create_tool_input_guardrail(
                Guard({"tools": {}}), denied_behavior="silently_ignore"
            )
        except ValueError as error:
            assert "denied_behavior" in str(error)
        else:
            raise AssertionError("expected ValueError")
