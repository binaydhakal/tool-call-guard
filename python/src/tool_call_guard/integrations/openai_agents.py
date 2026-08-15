"""OpenAI Agents SDK integration for tool-call-guard."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING, Any, Callable, Optional, Union

from tool_call_guard import Decision, Guard

if TYPE_CHECKING:
    from agents import ToolInputGuardrail

Message = Union[str, Callable[[Decision], str]]


def _message(decision: Decision, message: Optional[Message]) -> str:
    if callable(message):
        return message(decision)
    if message is not None:
        return message
    return "Tool call blocked by policy."


def create_tool_input_guardrail(
    guard: Guard,
    *,
    name: str = "tool_call_guard",
    denied_behavior: str = "reject_content",
    message: Optional[Message] = None,
) -> "ToolInputGuardrail[Any]":
    """Create an OpenAI function-tool input guardrail backed by ``guard``.

    ``denied_behavior`` may be ``"reject_content"`` to give the model a safe
    rejection message or ``"raise_exception"`` to halt the run with a tripwire.
    The default rejection text is generic; pass ``message`` to expose a curated
    reason to the model.
    """

    if denied_behavior not in ("reject_content", "raise_exception"):
        raise ValueError(
            'denied_behavior must be "reject_content" or "raise_exception"'
        )

    try:
        from agents import ToolGuardrailFunctionOutput, ToolInputGuardrail
    except ImportError as exc:
        raise ImportError(
            "OpenAI Agents integration requires the optional dependency; "
            "install 'tool-call-guard[openai]'."
        ) from exc

    async def check(data: Any) -> Any:
        raw_arguments = data.context.tool_arguments or "{}"
        try:
            args = json.loads(raw_arguments)
        except (TypeError, json.JSONDecodeError):
            output_info = {
                "adapter_error": "invalid_tool_arguments",
                "tool": data.context.tool_name,
            }
            if denied_behavior == "raise_exception":
                return ToolGuardrailFunctionOutput.raise_exception(output_info)
            return ToolGuardrailFunctionOutput.reject_content(
                "Tool call blocked because its arguments were not valid JSON.",
                output_info,
            )

        decision = await guard.acheck(data.context.tool_name, args)
        output_info = {"decision": asdict(decision)}
        if decision.allowed:
            return ToolGuardrailFunctionOutput.allow(output_info)
        if denied_behavior == "raise_exception":
            return ToolGuardrailFunctionOutput.raise_exception(output_info)
        return ToolGuardrailFunctionOutput.reject_content(
            _message(decision, message), output_info
        )

    return ToolInputGuardrail(guardrail_function=check, name=name)


__all__ = ["create_tool_input_guardrail"]
