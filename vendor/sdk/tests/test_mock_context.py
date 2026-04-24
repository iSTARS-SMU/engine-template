"""Tests for MockContext — the test double engine authors rely on.

MockContext is what students use to write unit tests without docker /
network / orchestrator. If it silently diverges from real RunContext,
engines that pass unit tests will fail contract tests (or worse, pass
contract tests and fail in production).

So MockContext must mirror RunContext's contracts exactly:
  * event whitelist (user-emittable only for emit_event)
  * scope check on fetch
  * scrub applied to captured events
  * secrets proxy honors declared + provided semantics
  * artifact refs tagged with (run_id, stage, stage_attempt_id)
"""

from __future__ import annotations

import pytest
from trustchain_contracts import (
    Capabilities,
    Confidence,
    FindingCandidateDraft,
    LLMConfig,
    Severity,
    SignatureEvidence,
    TargetRef,
)

from trustchain_sdk._errors import (
    ScopeViolation,
    SecretMissing,
    SecretNotDeclared,
    ToolUnavailable,
)
from trustchain_sdk.testing import MockContext


def _target(scope: list[str] | None = None) -> TargetRef:
    return TargetRef(
        id="t1",
        url="https://target.example",
        authorized_scope=scope or ["target.example"],
    )


# ============================================================
# Events — whitelist mirrors RunContext
# ============================================================


class TestEventWhitelist:
    @pytest.mark.asyncio
    async def test_user_emittable_kinds_allowed(self):
        ctx = MockContext(targets=[_target()])
        await ctx.emit_event("progress", {"percentage": 10})
        await ctx.emit_event("log", {"message": "ok"})
        await ctx.emit_event(
            "artifact_produced",
            {"artifact_id": "a1", "kind": "log", "size_bytes": 0, "sha256": "0" * 64},
        )
        kinds = [e["kind"] for e in ctx.captured_events()]
        assert sorted(kinds) == ["artifact_produced", "log", "progress"]

    @pytest.mark.asyncio
    async def test_orchestrator_owned_kind_rejected(self):
        """Spec §7.2: engines may NOT emit lifecycle events directly —
        MockContext must enforce the same barrier as real RunContext so
        unit-test-passing engine code will also pass in production."""
        ctx = MockContext(targets=[_target()])
        with pytest.raises(PermissionError):
            await ctx.emit_event("stage_started", {})

    @pytest.mark.asyncio
    async def test_engine_cannot_emit_tool_invoked_directly(self):
        """tool_invoked is SDK-auto — engine code must NOT emit it (would let
        engines fake their tool-call metrics). Real RunContext rejects; so
        does MockContext."""
        ctx = MockContext(targets=[_target()])
        with pytest.raises(PermissionError):
            await ctx.emit_event("tool_invoked", {"tool_id": "x", "duration_ms": 0, "success": True})

    @pytest.mark.asyncio
    async def test_engine_cannot_emit_llm_call_directly(self):
        ctx = MockContext(targets=[_target()])
        with pytest.raises(PermissionError):
            await ctx.emit_event(
                "llm_call",
                {"provider": "openai", "model": "x", "input_tokens": 0, "output_tokens": 0},
            )


# ============================================================
# Secrets
# ============================================================


class TestSecrets:
    @pytest.mark.asyncio
    async def test_required_secret_missing_at_construction_raises(self):
        """Parallel to real RunContext: when the factory is told a secret is
        required AND not provided, construction itself raises. Lets tests
        assert the orchestrator-fault path."""
        with pytest.raises(SecretMissing):
            MockContext(
                targets=[_target()],
                declared_secrets={"openai"},
                required_secrets={"openai"},
                provided_secrets={},  # not provided
            )

    @pytest.mark.asyncio
    async def test_mock_secret_requires_declaration(self):
        """Can't mock a secret the engine.yaml doesn't declare — prevents
        tests from accidentally validating engines that access undeclared
        secrets."""
        ctx = MockContext(targets=[_target()], declared_secrets={"openai"})
        with pytest.raises(AssertionError):
            ctx.mock_secret("stripe", "sk-bogus")

    @pytest.mark.asyncio
    async def test_undeclared_secret_access_raises(self):
        ctx = MockContext(targets=[_target()], declared_secrets={"openai"})
        ctx.mock_secret("openai", "sk-test")
        with pytest.raises(SecretNotDeclared):
            _ = ctx.secrets.aws

    @pytest.mark.asyncio
    async def test_provided_secret_accessible(self):
        ctx = MockContext(
            targets=[_target()],
            declared_secrets={"openai"},
            provided_secrets={"openai": "sk-test"},
        )
        assert ctx.secrets.openai == "sk-test"


# ============================================================
# fetch — scope enforcement mirrors real RunContext
# ============================================================


class TestFetchScope:
    @pytest.mark.asyncio
    async def test_fetch_out_of_scope_raises_scope_violation(self):
        ctx = MockContext(targets=[_target(["target.example"])])
        ctx.mock_tool(
            "http_fetch",
            {
                "status_code": 200,
                "headers": {},
                "body_preview": "",
                "final_url": "https://any",
                "truncated": False,
            },
        )
        with pytest.raises(ScopeViolation):
            await ctx.fetch("https://evil.example/")

    @pytest.mark.asyncio
    async def test_fetch_in_scope_returns_http_fetch_result(self):
        """Happy path: fetch passes scope → falls through to call_tool's
        mock response → parses as HttpFetchResult."""
        ctx = MockContext(targets=[_target(["target.example"])])
        ctx.mock_tool(
            "http_fetch",
            {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "body_preview": "<html>ok</html>",
                "final_url": "https://target.example/x",
                "truncated": False,
            },
        )
        result = await ctx.fetch("https://target.example/x")
        assert result.status_code == 200
        assert "ok" in result.body_preview


# ============================================================
# call_tool
# ============================================================


class TestCallTool:
    @pytest.mark.asyncio
    async def test_unconfigured_tool_raises_tool_unavailable(self):
        """No mock_tool registered → call_tool raises with a helpful message.
        Not KeyError — must match what real RunContext does when a tool
        container is down."""
        ctx = MockContext(targets=[_target()])
        with pytest.raises(ToolUnavailable):
            await ctx.call_tool("nmap", {"target": "127.0.0.1"})

    @pytest.mark.asyncio
    async def test_mock_tool_returns_result_dict(self):
        ctx = MockContext(targets=[_target()])
        ctx.mock_tool("nmap", {"result": {"ports": [80, 443]}})
        out = await ctx.call_tool("nmap", {"target": "127.0.0.1"})
        assert out == {"ports": [80, 443]}

    @pytest.mark.asyncio
    async def test_mock_tool_accepts_bare_result(self):
        """Test ergonomics: accept either wrapper-form {'tool_id':..,
        'result':..} OR just the bare result dict. Cuts boilerplate in
        student tests."""
        ctx = MockContext(targets=[_target()])
        ctx.mock_tool("nmap", {"ports": [22]})  # bare
        out = await ctx.call_tool("nmap", {})
        assert out == {"ports": [22]}

    @pytest.mark.asyncio
    async def test_calls_are_recorded_for_assertion(self):
        ctx = MockContext(targets=[_target()])
        ctx.mock_tool("nmap", {"ports": []})
        await ctx.call_tool("nmap", {"target": "1.2.3.4"})
        await ctx.call_tool("nmap", {"target": "1.2.3.5"})
        calls = ctx.captured_tool_calls()
        assert len(calls) == 2
        assert calls[0]["request"]["target"] == "1.2.3.4"


# ============================================================
# save_artifact — ref tagged with (run_id, stage, stage_attempt_id)
# ============================================================


class TestSaveArtifact:
    @pytest.mark.asyncio
    async def test_artifact_tagged_with_attempt_trio(self):
        ctx = MockContext(
            run_id="r_x",
            stage="recon",
            stage_attempt_id="sa_xyz",
            targets=[_target()],
        )
        ref = await ctx.save_artifact("data.bin", b"payload", kind="raw_output")
        assert ref.run_id == "r_x"
        assert ref.stage == "recon"
        assert ref.stage_attempt_id == "sa_xyz"
        assert ref.size_bytes == len(b"payload")

    @pytest.mark.asyncio
    async def test_artifact_sha256_is_computed(self):
        import hashlib

        ctx = MockContext(targets=[_target()])
        data = b"verifiable content"
        ref = await ctx.save_artifact("x.bin", data, kind="raw_output")
        assert ref.sha256 == hashlib.sha256(data).hexdigest()

    @pytest.mark.asyncio
    async def test_artifact_captured_for_assertions(self):
        ctx = MockContext(targets=[_target()])
        await ctx.save_artifact("a.bin", b"", kind="raw_output")
        await ctx.save_artifact("b.bin", b"x", kind="log")
        captured = ctx.captured_artifacts()
        assert len(captured) == 2
        assert {a.kind for a in captured} == {"raw_output", "log"}


# ============================================================
# emit_finding — two-channel
# ============================================================


class TestEmitFinding:
    @pytest.mark.asyncio
    async def test_emit_finding_produces_both_event_and_draft(self):
        """Spec §7.2.1 two-channel emit: an event for UI preview + a draft
        accumulated for authoritative EngineResult.finding_candidates."""
        ctx = MockContext(stage="report", targets=[_target()])
        draft = FindingCandidateDraft(
            vuln_type="sql_injection",
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            signature_evidence=SignatureEvidence(
                url="https://target.example/login",
                affected_parameters=["u"],
            ),
            affected_endpoint="/login",
        )
        await ctx.emit_finding(draft)

        # Channel 1: preview event.
        events = [e for e in ctx.captured_events() if e["kind"] == "finding_discovered"]
        assert len(events) == 1
        assert events[0]["payload"]["vuln_type"] == "sql_injection"

        # Channel 2: draft accumulator (authoritative).
        drafts = ctx.captured_findings()
        assert len(drafts) == 1
        assert drafts[0].vuln_type == "sql_injection"


# ============================================================
# Cancellation
# ============================================================


class TestCancellation:
    @pytest.mark.asyncio
    async def test_cancellation_flag_propagates(self):
        ctx = MockContext(targets=[_target()])
        assert await ctx.check_cancelled() is False
        ctx.trigger_cancellation()
        assert await ctx.check_cancelled() is True


# ============================================================
# LLM mock
# ============================================================


class TestMockLlm:
    @pytest.mark.asyncio
    async def test_queued_responses_returned_fifo(self):
        """Queue behaves as FIFO — first queued, first returned."""
        ctx = MockContext(
            targets=[_target()],
            capabilities=Capabilities(uses_llm=True),
            llm_config=LLMConfig(provider="openai", default_model="gpt-4o"),
        )
        ctx.mock_llm_response("first")
        ctx.mock_llm_response("second")
        r1 = await ctx.llm.chat([{"role": "user", "content": "x"}])
        r2 = await ctx.llm.chat([{"role": "user", "content": "x"}])
        assert r1.content == "first"
        assert r2.content == "second"

    @pytest.mark.asyncio
    async def test_default_response_when_queue_empty(self):
        ctx = MockContext(
            targets=[_target()],
            capabilities=Capabilities(uses_llm=True),
            llm_config=LLMConfig(provider="openai", default_model="gpt-4o"),
        )
        ctx.set_default_llm_response("fallback")
        result = await ctx.llm.chat([{"role": "user", "content": "x"}])
        assert result.content == "fallback"

    @pytest.mark.asyncio
    async def test_llm_metrics_accumulate(self):
        ctx = MockContext(
            targets=[_target()],
            capabilities=Capabilities(uses_llm=True),
            llm_config=LLMConfig(provider="openai", default_model="gpt-4o"),
        )
        ctx.mock_llm_response("hello")
        ctx.mock_llm_response("world")
        await ctx.llm.chat([{"role": "user", "content": "prompt1"}])
        await ctx.llm.chat([{"role": "user", "content": "prompt2"}])
        assert ctx.llm.total_calls == 2
        # Tokens are rough-counted by the mock — just assert they grew.
        assert ctx.llm.total_input_tokens > 0
        assert ctx.llm.total_output_tokens > 0

    @pytest.mark.asyncio
    async def test_llm_call_event_emitted(self):
        """llm_call is SDK-auto — engine code can't emit it — but the SDK
        DOES emit one per chat() call, with purpose tag."""
        ctx = MockContext(
            targets=[_target()],
            capabilities=Capabilities(uses_llm=True),
            llm_config=LLMConfig(provider="openai", default_model="gpt-4o"),
        )
        ctx.mock_llm_response("ok")
        await ctx.llm.chat(
            [{"role": "user", "content": "hi"}],
            purpose="unit_test",
        )
        llm_events = [e for e in ctx.captured_events() if e["kind"] == "llm_call"]
        assert len(llm_events) == 1
        payload = llm_events[0]["payload"]
        assert payload["model"] == "gpt-4o"
        assert payload["purpose"] == "unit_test"


# ============================================================
# Scrub — secret values never leak into captured events
# ============================================================


class TestScrub:
    @pytest.mark.asyncio
    async def test_declared_secret_value_scrubbed_from_event_payload(self):
        """If engine accidentally includes a known secret value in an event
        payload, the scrubber must replace it with [REDACTED] before the
        event is captured."""
        ctx = MockContext(
            targets=[_target()],
            declared_secrets={"openai"},
            provided_secrets={"openai": "sk-live-SENSITIVE-12345"},
        )
        # Engine accidentally logs the key:
        await ctx.emit_event("log", {"message": "using key sk-live-SENSITIVE-12345"})
        events = ctx.captured_events()
        msg = events[0]["payload"]["message"]
        assert "SENSITIVE-12345" not in msg
        assert "[REDACTED]" in msg

    @pytest.mark.asyncio
    async def test_pattern_based_scrub_catches_unknown_secrets(self):
        """Even if the secret wasn't declared, pattern-based fallback in the
        scrubber catches common formats (sk-*, ghp_*, AKIA*). Defense in
        depth for when secret_requirements declarations drift."""
        ctx = MockContext(targets=[_target()])
        await ctx.emit_event(
            "log",
            {"message": "found: sk-abcdefghij1234567890XYZ123 in response"},
        )
        msg = ctx.captured_events()[0]["payload"]["message"]
        assert "sk-abcdef" not in msg
        assert "[REDACTED]" in msg
