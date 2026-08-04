import asyncio
import json

import pytest

from tool_call_guard import Guard, ToolCallDenied, create_guard, jsonl_audit


class FakeClock:
    def __init__(self, start=1_000_000.0):
        self.t = start

    def now(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class PydanticStyleValidator:
    """Duck-typed stand-in for a pydantic model class (model_validate)."""

    @classmethod
    def model_validate(cls, args):
        if not isinstance(args, dict) or not isinstance(args.get("q"), str):
            raise ValueError("q must be a string")
        return args


class TestDenyByDefault:
    def test_denies_unknown_tools(self):
        guard = Guard({"tools": {"search": {}}})
        decision = guard.check("delete_everything", {})
        assert decision.allowed is False
        assert decision.action == "deny"
        assert "denied by default" in decision.reason

    def test_allowlists_tools_with_a_rule(self):
        guard = Guard({"tools": {"search": {}}})
        decision = guard.check("search", {"q": "hi"})
        assert decision.allowed is True
        assert decision.rule == "search"

    def test_default_action_allow_flips_posture(self):
        guard = Guard({"defaultAction": "allow", "tools": {}})
        assert guard.check("anything").allowed is True

    def test_snake_case_default_action_alias(self):
        guard = Guard({"default_action": "allow", "tools": {}})
        assert guard.check("anything").allowed is True


class TestRulesAndPatterns:
    def test_explicit_deny_wins_in_allow_by_default(self):
        guard = Guard(
            {"defaultAction": "allow", "tools": {"shell_exec": {"action": "deny"}}}
        )
        decision = guard.check("shell_exec", {"cmd": "rm -rf /"})
        assert decision.allowed is False
        assert 'denied by rule "shell_exec"' in decision.reason

    def test_wildcards_match_groups(self):
        guard = Guard({"tools": {"fs_*": {}}})
        assert guard.check("fs_read", {}).allowed is True
        assert guard.check("fs_write", {}).allowed is True
        assert guard.check("net_fetch", {}).allowed is False

    def test_exact_rules_beat_wildcards(self):
        guard = Guard({"tools": {"fs_*": {}, "fs_delete": {"action": "deny"}}})
        assert guard.check("fs_read").allowed is True
        denied = guard.check("fs_delete")
        assert denied.allowed is False
        assert denied.rule == "fs_delete"

    def test_more_literal_patterns_beat_less_literal(self):
        guard = Guard({"tools": {"*": {}, "db_*": {"action": "deny"}}})
        assert guard.check("anything").allowed is True
        assert guard.check("db_drop").allowed is False


class TestArgumentValidation:
    def test_predicate_rejects_with_string_reason(self):
        guard = Guard(
            {"tools": {"pay": {"validate": lambda a: a["amount"] <= 100 or "amount over limit"}}}
        )
        assert guard.check("pay", {"amount": 50}).allowed is True
        denied = guard.check("pay", {"amount": 5000})
        assert denied.allowed is False
        assert "amount over limit" in denied.reason

    def test_predicate_returning_none_passes(self):
        guard = Guard({"tools": {"x": {"validate": lambda a: None}}})
        assert guard.check("x", {}).allowed is True

    def test_pydantic_style_model_validate(self):
        guard = Guard({"tools": {"search": {"validate": PydanticStyleValidator}}})
        assert guard.check("search", {"q": "ok"}).allowed is True
        denied = guard.check("search", {"q": 42})
        assert denied.allowed is False
        assert "q must be a string" in denied.reason

    def test_raising_validator_denies_with_message(self):
        def explode(args):
            raise RuntimeError("boom")

        guard = Guard({"tools": {"x": {"validate": explode}}})
        denied = guard.check("x", {})
        assert denied.allowed is False
        assert "boom" in denied.reason

    def test_invalid_args_do_not_consume_budget(self):
        guard = Guard(
            {"tools": {"pay": {"maxCalls": 1, "validate": lambda a: a.get("ok") is True}}}
        )
        guard.check("pay", {"ok": False})
        guard.check("pay", {"ok": False})
        assert guard.check("pay", {"ok": True}).allowed is True


class TestQuotas:
    def test_max_calls_caps_total(self):
        guard = Guard({"tools": {"search": {"maxCalls": 2}}})
        assert guard.check("search").allowed is True
        assert guard.check("search").allowed is True
        third = guard.check("search")
        assert third.allowed is False
        assert "maxCalls: 2" in third.reason

    def test_snake_case_max_calls_alias(self):
        guard = Guard({"tools": {"search": {"max_calls": 1}}})
        assert guard.check("search").allowed is True
        assert guard.check("search").allowed is False

    def test_per_minute_sliding_window_on_injectable_clock(self):
        clock = FakeClock()
        guard = Guard(
            {"tools": {"fetch": {"maxCallsPerMinute": 2}}}, now=clock.now
        )
        assert guard.check("fetch").allowed is True
        clock.advance(1)
        assert guard.check("fetch").allowed is True
        clock.advance(1)
        third = guard.check("fetch")
        assert third.allowed is False
        assert "2/min" in third.reason
        clock.advance(59.5)  # first call slides out of the 60s window
        assert guard.check("fetch").allowed is True

    def test_wildcard_rules_share_one_budget(self):
        guard = Guard({"tools": {"fs_*": {"maxCalls": 2}}})
        assert guard.check("fs_read").allowed is True
        assert guard.check("fs_write").allowed is True
        assert guard.check("fs_list").allowed is False

    def test_reset_clears_quotas_and_audit(self):
        guard = Guard({"tools": {"search": {"maxCalls": 1}}})
        guard.check("search")
        assert guard.check("search").allowed is False
        guard.reset()
        assert guard.audit_log == []
        assert guard.check("search").allowed is True


class TestApproval:
    def test_sync_approver_verdict_honored(self):
        requests = []

        def approve(req):
            requests.append(req)
            return req["args"].get("env") != "prod"

        guard = Guard({"tools": {"deploy": {"action": "approve"}}}, approve=approve)
        assert guard.check("deploy", {"env": "staging"}).allowed is True
        denied = guard.check("deploy", {"env": "prod"})
        assert denied.allowed is False
        assert denied.reason == "approval declined"
        assert len(requests) == 2
        assert requests[0]["tool"] == "deploy"
        assert requests[0]["rule"] == "deploy"

    def test_approve_without_approver_denies_safely(self):
        guard = Guard({"tools": {"deploy": {"action": "approve"}}})
        denied = guard.check("deploy", {})
        assert denied.allowed is False
        assert "no approver is configured" in denied.reason

    def test_sync_check_rejects_async_approver(self):
        async def approve(req):
            return True

        guard = Guard({"tools": {"deploy": {"action": "approve"}}}, approve=approve)
        with pytest.raises(TypeError, match="acheck"):
            guard.check("deploy", {})

    def test_acheck_awaits_async_approver(self):
        async def approve(req):
            await asyncio.sleep(0)
            return req["args"]["env"] != "prod"

        guard = Guard({"tools": {"deploy": {"action": "approve"}}}, approve=approve)
        ok = asyncio.run(guard.acheck("deploy", {"env": "staging"}))
        assert ok.allowed is True
        assert ok.reason == "approved"
        denied = asyncio.run(guard.acheck("deploy", {"env": "prod"}))
        assert denied.allowed is False

    def test_acheck_accepts_sync_approver_too(self):
        guard = Guard(
            {"tools": {"deploy": {"action": "approve"}}}, approve=lambda req: True
        )
        assert asyncio.run(guard.acheck("deploy", {})).allowed is True

    def test_approved_calls_consume_quota(self):
        guard = Guard(
            {"tools": {"deploy": {"action": "approve", "maxCalls": 1}}},
            approve=lambda req: True,
        )
        assert guard.check("deploy").allowed is True
        second = guard.check("deploy")
        assert second.allowed is False
        assert "budget exhausted" in second.reason


class TestWrappers:
    def test_wrap_blocks_denied_calls_without_invoking(self):
        invoked = []
        guard = Guard({"tools": {}})
        wrapped = guard.wrap("nuke", lambda args: invoked.append(1) or "done")
        with pytest.raises(ToolCallDenied, match="denied by default"):
            wrapped({})
        assert invoked == []

    def test_wrap_passes_allowed_calls_through(self):
        guard = Guard({"tools": {"echo": {}}})
        wrapped = guard.wrap("echo", lambda args, suffix: args["msg"] + suffix)
        assert wrapped({"msg": "hi"}, "!") == "hi!"

    def test_wrap_async_functions(self):
        guard = Guard({"tools": {"echo": {}}})

        async def echo(args):
            return f"echo {args['msg']}"

        wrapped = guard.wrap("echo", echo)
        assert asyncio.run(wrapped({"msg": "hey"})) == "echo hey"

        blocked = guard.wrap("blocked", echo)
        with pytest.raises(ToolCallDenied):
            asyncio.run(blocked({"msg": "x"}))

    def test_protect_decorator(self):
        guard = Guard({"tools": {"send_email": {}}})

        @guard.protect("send_email")
        def send_email(args):
            return f"sent to {args['to']}"

        assert send_email({"to": "a@b.c"}) == "sent to a@b.c"

        @guard.protect("drop_db")
        def drop_db(args):
            return "dropped"

        with pytest.raises(ToolCallDenied):
            drop_db({})

    def test_wrap_tools_record(self):
        guard = Guard({"tools": {"add": {}}})
        tools = guard.wrap_tools(
            {"add": lambda a: a["x"] + a["y"], "shell": lambda a: "ran"}
        )
        assert tools["add"]({"x": 2, "y": 3}) == 5
        with pytest.raises(ToolCallDenied):
            tools["shell"]({})


class TestAuditTrail:
    def test_records_every_decision(self):
        guard = Guard({"tools": {"search": {}}})
        guard.check("search", {"q": "hi"})
        guard.check("unknown", {"x": 1})
        assert len(guard.audit_log) == 2
        first, second = guard.audit_log
        assert first["tool"] == "search"
        assert first["allowed"] is True
        assert first["mode"] == "enforce"
        assert first["args"] == {"q": "hi"}
        assert second["allowed"] is False

    def test_audit_args_false_omits_args(self):
        guard = Guard({"tools": {"search": {}}}, audit_args=False)
        guard.check("search", {"secret": "hunter2"})
        assert "args" not in guard.audit_log[0]

    def test_ring_buffer_drops_oldest(self):
        guard = Guard({"tools": {"t": {}}}, max_audit_events=2)
        for n in range(3):
            guard.check("t", {"n": n})
        assert len(guard.audit_log) == 2
        assert guard.audit_log[0]["args"] == {"n": 1}

    def test_on_audit_sink_receives_events(self):
        events = []
        guard = Guard({"tools": {}}, on_audit=events.append)
        guard.check("x")
        assert len(events) == 1
        assert events[0]["allowed"] is False

    def test_jsonl_sink_appends_lines(self, tmp_path):
        path = tmp_path / "nested" / "audit.jsonl"
        guard = Guard({"tools": {"search": {}}}, on_audit=jsonl_audit(str(path)))
        guard.check("search", {"q": "a"})
        guard.check("blocked", {})
        lines = [json.loads(l) for l in path.read_text().strip().splitlines()]
        assert len(lines) == 2
        assert lines[0]["tool"] == "search" and lines[0]["allowed"] is True
        assert lines[1]["tool"] == "blocked" and lines[1]["allowed"] is False


class TestDryRun:
    def test_allows_everything_but_audits_enforcement(self):
        guard = Guard({"tools": {"search": {}}}, mode="dry-run")
        denied = guard.check("dangerous", {})
        assert denied.allowed is True
        assert denied.dry_run is True
        assert denied.would_allow is False
        allowed = guard.check("search", {})
        assert allowed.would_allow is True
        assert guard.audit_log[0]["mode"] == "dry-run"
        assert guard.audit_log[0]["wouldAllow"] is False

    def test_does_not_invoke_approvers_in_rehearsal(self):
        paged = []
        guard = Guard(
            {"tools": {"deploy": {"action": "approve"}}},
            mode="dry-run",
            approve=lambda req: paged.append(1) or True,
        )
        decision = guard.check("deploy", {})
        assert decision.allowed is True
        assert decision.would_allow is False
        assert paged == []

    def test_wrapped_tools_run_despite_would_deny(self):
        guard = Guard({"tools": {}}, mode="dry-run")
        wrapped = guard.wrap("anything", lambda args: "ran")
        assert wrapped({}) == "ran"

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValueError, match="dry-run"):
            Guard({"tools": {}}, mode="observe")


class TestPolicyReuse:
    def test_same_json_policy_drives_multiple_guards(self):
        policy = {
            "defaultAction": "deny",
            "tools": {
                "read_*": {},
                "write_file": {"action": "approve"},
                "shell": {"action": "deny"},
            },
        }
        a = Guard(policy, approve=lambda req: True)
        b = Guard(policy)
        assert a.check("read_doc").allowed is True
        assert a.check("write_file").allowed is True
        assert b.check("write_file").allowed is False  # no approver on b
        assert b.check("shell").allowed is False

    def test_create_guard_alias(self):
        guard = create_guard({"tools": {"x": {}}})
        assert guard.check("x").allowed is True
