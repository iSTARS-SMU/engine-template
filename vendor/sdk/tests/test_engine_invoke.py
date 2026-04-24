"""Error-path tests for EngineApp.invoke().

The happy path is covered by the fake-recon / fake-report test_invoke.py
files. This suite focuses on the FAILURE matrix: every route through
invoke() that produces `EngineResult(status=failed, error_code=...)` must
produce the *right* error_code, the *right* retryable flag, and — when served
through the FastAPI /invoke route — the right HTTP status.

Why this suite is load-bearing: the orchestrator interprets error_code to
decide whether to retry, abort, or gate a destructive operation. A silent
mis-mapping breaks every downstream decision.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from trustchain_contracts import (
    CallbackConfig,
    Capabilities,
    EngineResult,
    EngineStatus,
    ErrorCode,
    LLMConfig,
    RunContextEnvelope,
    SecretRequirement,
    TargetRef,
)

from trustchain_sdk import EngineApp, RunContext
from trustchain_sdk._errors import ScopeViolation
from trustchain_sdk.engine import _http_status_for_error


# ============================================================
# Helpers: envelope factory + silent transport
# ============================================================


def _base_envelope(**overrides) -> RunContextEnvelope:
    """Minimal valid envelope. Override any field via kwargs."""
    base: dict = dict(
        run_id="r_test",
        project_id="p_test",
        stage="recon",
        stage_attempt_id="sa_test",
        attempt_number=1,
        engine_id="test-engine@0.1.0",
        deadline=datetime.now(timezone.utc) + timedelta(minutes=5),
        targets=[
            TargetRef(
                id="t1",
                url="https://target.example",
                authorized_scope=["target.example"],
            )
        ],
        upstream_outputs={},
        config={},
        secrets={},
        llm_config=None,
        callbacks=CallbackConfig(
            events_url="http://core/api/v1/runs/r_test/events",
            tools_url="http://core/api/v1/tools",
            token="cbt_test",
        ),
    )
    base.update(overrides)
    return RunContextEnvelope(**base)


def _silent_transport() -> httpx.MockTransport:
    """Handler that soaks up any callback traffic without side effects.
    Tests that don't care about callback semantics use this so RunContext
    can create an http client without hitting the real network."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/events"):
            return httpx.Response(204)
        if "/_artifact/put" in url:
            return httpx.Response(200, json={})
        if "/tools/" in url:
            return httpx.Response(200, json={"tool_id": "x", "duration_ms": 0, "result": {}})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


# ============================================================
# Engines used by tests
# ============================================================


class _NoopEngine(EngineApp):
    engine_id = "noop-engine"
    version = "0.1.0"
    stage = "recon"
    capabilities = Capabilities(uses_llm=False, writes_artifacts=False)
    secret_requirements: list[SecretRequirement] = []

    async def run(self, ctx: RunContext, config: dict):
        return {"ok": True}


class _RequiresOpenAIEngine(EngineApp):
    engine_id = "needs-openai"
    version = "0.1.0"
    stage = "recon"
    capabilities = Capabilities(uses_llm=False)
    secret_requirements = [SecretRequirement(name="openai", required=True)]

    async def run(self, ctx: RunContext, config: dict):
        # Will never reach here if envelope lacks the required secret.
        return {"fetched_secret_len": len(ctx.secrets.openai)}


class _LLMEngine(EngineApp):
    engine_id = "llm-engine"
    version = "0.1.0"
    stage = "attack_plan"
    capabilities = Capabilities(uses_llm=True)
    secret_requirements: list[SecretRequirement] = []

    async def run(self, ctx: RunContext, config: dict):
        return {}


class _ScopeViolatingEngine(EngineApp):
    """Tries to fetch a host OUTSIDE authorized_scope. ctx.fetch's
    pre-flight scope check should raise before any HTTP."""

    engine_id = "scope-violating"
    version = "0.1.0"
    stage = "recon"
    capabilities = Capabilities()

    async def run(self, ctx: RunContext, config: dict):
        await ctx.fetch("https://evil.example/steal")


class _CrashingEngine(EngineApp):
    engine_id = "crashing"
    version = "0.1.0"
    stage = "recon"
    capabilities = Capabilities(writes_artifacts=False)

    async def run(self, ctx: RunContext, config: dict):
        raise ZeroDivisionError("simulated engine bug")


class _OutputCoercionEngine(EngineApp):
    """Used to verify the output coercion matrix in EngineApp._coerce_output.
    Returns whatever the config tells it to — we construct several instances
    with different return values per test."""

    engine_id = "coerce"
    version = "0.1.0"
    stage = "recon"
    capabilities = Capabilities(writes_artifacts=False)

    def __init__(self, return_value):
        super().__init__()
        self._return_value = return_value

    async def run(self, ctx: RunContext, config: dict):
        return self._return_value


# ============================================================
# SECRET_MISSING — required secret absent from envelope
# ============================================================


@pytest.mark.asyncio
async def test_secret_missing_returns_structured_failure():
    """Engine.yaml declares openai as required; envelope.secrets is empty.
    RunContext construction raises SecretMissing, which invoke() wraps into
    a FAILED EngineResult with code=SECRET_MISSING + retryable=False
    (not an engine-side bug to retry — orchestrator's job to fix)."""
    env = _base_envelope(secrets={})  # no openai
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _RequiresOpenAIEngine().invoke(env, http_client=client)
    finally:
        await client.aclose()

    assert result.status == EngineStatus.FAILED
    assert result.error_code == ErrorCode.SECRET_MISSING
    assert result.retryable is False
    assert result.stage_attempt_id == env.stage_attempt_id


@pytest.mark.asyncio
async def test_secret_missing_does_not_leak_exception():
    """Whatever happens inside run(), invoke() returns an EngineResult —
    never lets a raw exception propagate to the HTTP layer."""
    env = _base_envelope(secrets={})
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        # Should not raise.
        result = await _RequiresOpenAIEngine().invoke(env, http_client=client)
    finally:
        await client.aclose()
    assert isinstance(result, EngineResult)


# ============================================================
# LLM_CONFIG_MISSING — uses_llm=true but envelope has no llm_config
# ============================================================


@pytest.mark.asyncio
async def test_llm_config_missing_returns_structured_failure():
    """capabilities.uses_llm=true requires envelope.llm_config. Constructing
    LLMClient inside RunContext raises LLMConfigMissing, handled by invoke()."""
    env = _base_envelope(llm_config=None)
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _LLMEngine().invoke(env, http_client=client)
    finally:
        await client.aclose()

    assert result.status == EngineStatus.FAILED
    assert result.error_code == ErrorCode.LLM_CONFIG_MISSING
    assert result.retryable is False


@pytest.mark.asyncio
async def test_llm_config_present_allows_engine_to_run():
    """Sanity: the opposite path — llm_config present → engine runs normally."""
    env = _base_envelope(
        llm_config=LLMConfig(provider="openai", default_model="gpt-4o"),
    )
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _LLMEngine().invoke(env, http_client=client)
    finally:
        await client.aclose()
    assert result.status == EngineStatus.SUCCESS


# ============================================================
# SCOPE_VIOLATION — engine calls ctx.fetch for out-of-scope host
# ============================================================


@pytest.mark.asyncio
async def test_scope_violation_returns_structured_failure():
    env = _base_envelope()  # scope = target.example
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _ScopeViolatingEngine().invoke(env, http_client=client)
    finally:
        await client.aclose()

    assert result.status == EngineStatus.FAILED
    assert result.error_code == ErrorCode.SCOPE_VIOLATION
    # Scope violation is never retryable — the scope set won't change
    # between retries unless the Target itself is edited.
    assert result.retryable is False


@pytest.mark.asyncio
async def test_scope_violation_error_carries_offending_url():
    """The ScopeViolation exception records url + authorized_scope for
    audit. invoke() folds this into error_message — it should mention the
    URL that got rejected (helps the engine author debug)."""
    env = _base_envelope()
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _ScopeViolatingEngine().invoke(env, http_client=client)
    finally:
        await client.aclose()
    assert "evil.example" in (result.error_message or "")


# ============================================================
# INTERNAL_ERROR — any unhandled exception in engine.run
# ============================================================


@pytest.mark.asyncio
async def test_unhandled_exception_becomes_internal_error():
    """Engines are not trusted to keep their exceptions from escaping.
    invoke()'s last-chance except clause catches ANY exception and produces
    a well-formed EngineResult with INTERNAL_ERROR + retryable=True (since
    a bug might be transient)."""
    env = _base_envelope()
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _CrashingEngine().invoke(env, http_client=client)
    finally:
        await client.aclose()

    assert result.status == EngineStatus.FAILED
    assert result.error_code == ErrorCode.INTERNAL_ERROR
    assert result.retryable is True


@pytest.mark.asyncio
async def test_unhandled_exception_message_does_not_leak_traceback():
    """error_message is exposed to operators via logs / audit, and should be
    a short one-liner — NOT a multi-line traceback. Code logs the traceback
    separately (via `logger.error(... traceback.format_exc())`)."""
    env = _base_envelope()
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _CrashingEngine().invoke(env, http_client=client)
    finally:
        await client.aclose()
    msg = result.error_message or ""
    # No traceback-style lines ("File "..."", "  at ...").
    assert "File \"" not in msg
    assert "Traceback" not in msg


# ============================================================
# Success path — output coercion matrix
# ============================================================


@pytest.mark.asyncio
async def test_output_coercion_from_dict():
    """Dict return → used directly as EngineResult.output."""
    env = _base_envelope()
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _OutputCoercionEngine({"a": 1, "b": [1, 2]}).invoke(
            env, http_client=client
        )
    finally:
        await client.aclose()
    assert result.status == EngineStatus.SUCCESS
    assert result.output == {"a": 1, "b": [1, 2]}


@pytest.mark.asyncio
async def test_output_coercion_from_none():
    """None return → {} (empty dict). Keeps the wire type stable even when
    an engine has no useful output for this stage."""
    env = _base_envelope()
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _OutputCoercionEngine(None).invoke(env, http_client=client)
    finally:
        await client.aclose()
    assert result.status == EngineStatus.SUCCESS
    assert result.output == {}


@pytest.mark.asyncio
async def test_output_coercion_from_scalar():
    """Scalar return → wrapped as {"value": scalar}. Avoids silently
    dropping a non-dict return — engine author gets a visible, inspectable
    output shape even if they were sloppy."""
    env = _base_envelope()
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _OutputCoercionEngine("hello").invoke(env, http_client=client)
    finally:
        await client.aclose()
    assert result.status == EngineStatus.SUCCESS
    assert result.output == {"value": "hello"}


@pytest.mark.asyncio
async def test_output_coercion_from_pydantic_model():
    """BaseModel return → .model_dump(mode='json'). Engine authors often
    return a contracts DTO (ReconOutput etc.) directly; this must survive
    the wire conversion."""
    from trustchain_contracts import ReconOutput, TechFingerprint

    recon = ReconOutput(
        target_ref=TargetRef(
            id="t1", url="https://x.example", authorized_scope=["x.example"]
        ),
        tech_fingerprint=TechFingerprint(framework="flask"),
        notes="test",
    )
    env = _base_envelope()
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _OutputCoercionEngine(recon).invoke(env, http_client=client)
    finally:
        await client.aclose()
    assert result.status == EngineStatus.SUCCESS
    assert isinstance(result.output, dict)
    assert result.output["tech_fingerprint"]["framework"] == "flask"
    assert result.output["notes"] == "test"


# ============================================================
# stage_attempt_id echo — orchestrator uses this to align state
# ============================================================


@pytest.mark.asyncio
async def test_stage_attempt_id_echoed_on_success():
    env = _base_envelope(stage_attempt_id="sa_unique_12345")
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _NoopEngine().invoke(env, http_client=client)
    finally:
        await client.aclose()
    assert result.stage_attempt_id == "sa_unique_12345"


@pytest.mark.asyncio
async def test_stage_attempt_id_echoed_on_failure():
    """Orchestrator aligns the failed-attempt's state by stage_attempt_id;
    it MUST survive error paths too."""
    env = _base_envelope(stage_attempt_id="sa_fail_67890")
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _CrashingEngine().invoke(env, http_client=client)
    finally:
        await client.aclose()
    assert result.stage_attempt_id == "sa_fail_67890"


# ============================================================
# Metrics populated
# ============================================================


@pytest.mark.asyncio
async def test_metrics_duration_ms_populated_on_success():
    """metrics.duration_ms is EngineApp-computed (monotonic clock)."""
    env = _base_envelope()
    client = httpx.AsyncClient(transport=_silent_transport())
    try:
        result = await _NoopEngine().invoke(env, http_client=client)
    finally:
        await client.aclose()
    # At minimum 0 (async is fast), at most a sane upper bound.
    assert 0 <= result.metrics.duration_ms < 60_000


# ============================================================
# ErrorCode → HTTP status mapping
# ============================================================


class TestHttpStatusMapping:
    """_http_status_for_error is the table the FastAPI /invoke route uses to
    choose the HTTP status for each failure. Locks every ErrorCode to a
    specific status so changes are explicit."""

    def test_caller_fault_codes_are_400(self):
        for code in [
            ErrorCode.CONFIG_INVALID,
            ErrorCode.CONTEXT_INVALID,
            ErrorCode.SECRET_MISSING,
            ErrorCode.LLM_CONFIG_MISSING,
        ]:
            assert _http_status_for_error(code) == 400, code

    def test_auth_codes_are_403(self):
        assert _http_status_for_error(ErrorCode.AUTHZ_FAILED) == 403
        assert _http_status_for_error(ErrorCode.SCOPE_VIOLATION) == 403

    def test_target_not_found_is_404(self):
        assert _http_status_for_error(ErrorCode.TARGET_NOT_FOUND) == 404

    def test_stage_superseded_is_409(self):
        assert _http_status_for_error(ErrorCode.STAGE_SUPERSEDED) == 409

    def test_upstream_infra_codes_are_5xx(self):
        assert _http_status_for_error(ErrorCode.TARGET_UNREACHABLE) == 502
        assert _http_status_for_error(ErrorCode.TOOL_UNAVAILABLE) == 502
        assert _http_status_for_error(ErrorCode.LLM_UNAVAILABLE) == 503
        assert _http_status_for_error(ErrorCode.DEADLINE_EXCEEDED) == 504
        assert _http_status_for_error(ErrorCode.INTERNAL_ERROR) == 500

    def test_none_error_defaults_to_500(self):
        """Defensive: if code somehow reaches us without an error_code
        (shouldn't happen), we return 500 — not crash."""
        assert _http_status_for_error(None) == 500

    def test_every_error_code_has_a_mapping(self):
        """Regression guard: if a new ErrorCode is added to the enum,
        _http_status_for_error must have an entry for it. Without this test,
        new codes silently default to 500 (still via the None path) — this
        test forces an explicit decision."""
        from trustchain_sdk.engine import _ERROR_HTTP_STATUS

        missing = [c for c in ErrorCode if c not in _ERROR_HTTP_STATUS]
        assert not missing, (
            f"ErrorCode(s) {missing} are not in _ERROR_HTTP_STATUS. Add "
            f"explicit mappings in engine.py's _ERROR_HTTP_STATUS dict."
        )


# ============================================================
# ScopeViolation dataclass structure (used by fetch) — quick smoke
# ============================================================


def test_scope_violation_exception_carries_structured_info():
    """ScopeViolation instances must expose .url and .authorized_scope —
    server-side audit logs and structured error responses rely on it."""
    exc = ScopeViolation(url="https://evil/", authorized_scope=["good.example"])
    assert exc.url == "https://evil/"
    assert exc.authorized_scope == ["good.example"]
    assert "evil" in str(exc)
