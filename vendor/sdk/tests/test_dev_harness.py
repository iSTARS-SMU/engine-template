"""Tests for DevHarness — the local mini-core for engine dev / integration.

The point of DevHarness is that the engine's code path stays identical to
prod: RealRunContext POSTs callbacks to a virtual `dev-harness` host which
the harness's routed httpx transport hands to an in-process FastAPI app.

Tests we care about:
  - happy path: real engine (fake-recon-style) runs, events + artifact land
    in the harness
  - tool proxy: engine's ctx.call_tool reaches a mock tool through the
    harness, response wraps back
  - scope check: out-of-scope tool target → 403 → ScopeViolation in engine
  - missing tool config → 502 → ToolUnavailable in engine
  - LLM unused engine works without an OpenAI key
  - context manager + idempotent start/stop
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from trustchain_contracts import (
    Capabilities,
    Endpoint,
    EngineStatus,
    ReconOutput,
    SecretRequirement,
    TargetRef,
    TechFingerprint,
)
from trustchain_sdk import EngineApp, RunContext
from trustchain_sdk.testing import DevHarness


# ---------- a minimal recon engine (mirrors fake-recon's shape) ----------

# A 1x1 transparent PNG (68 bytes). Same one fake-recon ships, embedded
# here so this test file is self-contained (doesn't need fake-recon installed).
_TINY_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xfa"
    b"\xff\xff?\x03\x00\x05\xfe\x02\xfeA\x7f\x8b\x16\x00\x00\x00\x00IEND"
    b"\xaeB`\x82"
)


class _NoToolRecon(EngineApp):
    engine_id = "no-tool-recon"
    version = "0.1.0"
    stage = "recon"
    capabilities = Capabilities(uses_llm=False)

    async def run(self, ctx: RunContext, config: dict) -> ReconOutput:
        await ctx.emit_event("progress", {"percentage": 50})
        ref = await ctx.save_artifact(
            name="page.png",
            data=_TINY_PNG,
            kind="screenshot",
            mime_type="image/png",
        )
        return ReconOutput(
            target_ref=ctx.targets[0],
            tech_fingerprint=TechFingerprint(framework="flask"),
            endpoints=[Endpoint(path="/", methods=["GET"])],
            screenshots=[ref],
            notes="dev-harness smoke",
        )


class _ToolUsingRecon(EngineApp):
    engine_id = "tool-using-recon"
    version = "0.1.0"
    stage = "recon"
    capabilities = Capabilities(uses_llm=False)

    async def run(self, ctx: RunContext, config: dict) -> dict:
        # Calls an arbitrary tool to exercise the proxy path.
        result = await ctx.call_tool(
            "fake-nmap",
            {"target": config.get("target", "scanme.example.com")},
        )
        return {"tool_response": result}


class _ScopeViolatingRecon(EngineApp):
    engine_id = "scope-violator"
    version = "0.1.0"
    stage = "recon"
    capabilities = Capabilities(uses_llm=False)

    async def run(self, ctx: RunContext, config: dict) -> dict:
        # Hit a target the harness scope doesn't allow.
        await ctx.call_tool("fake-nmap", {"target": "evil.example.org"})
        return {}


def _make_target(scope: list[str]) -> TargetRef:
    return TargetRef(
        id="t1",
        url="https://scanme.example.com/",
        target_type="web",
        authorized_scope=scope,
    )


# ---------- happy path ----------


@pytest.mark.asyncio
async def test_dev_harness_runs_engine_with_no_tools(tmp_path: Path):
    target = _make_target(["scanme.example.com"])

    async with DevHarness(
        engine_app=_NoToolRecon(),
        artifact_dir=tmp_path / "artifacts",
        events_path=tmp_path / "events.jsonl",
    ) as harness:
        result = await harness.run_once(target=target, config={})

    assert result.status == EngineStatus.SUCCESS
    out = ReconOutput.model_validate(result.output)
    assert out.tech_fingerprint.framework == "flask"
    assert out.target_ref.id == "t1"

    # Events came back through the harness's events route.
    events = harness.captured_events()
    kinds = [e["kind"] for e in events]
    assert "progress" in kinds
    # SDK auto-emits no tool_invoked here (engine called no tool)
    assert "tool_invoked" not in kinds

    # Artifact was uploaded + persisted to disk.
    artifacts = harness.captured_artifacts()
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.minio_key.endswith("page.png")
    assert art.size_bytes == len(_TINY_PNG)
    on_disk = tmp_path / "artifacts" / art.run_id / f"{art.id}_page.png"
    assert on_disk.exists()
    assert on_disk.stat().st_size == len(_TINY_PNG)

    # Events JSONL written.
    log = (tmp_path / "events.jsonl").read_text().splitlines()
    assert len(log) >= 1


# ---------- tool proxy ----------


@pytest.mark.asyncio
async def test_dev_harness_proxies_tool_call_to_real_url(tmp_path: Path):
    """Engine calls ctx.call_tool('fake-nmap', ...) → harness forwards via
    real httpx to the URL in tool_urls. We swap harness._tool_client out
    after start() to point at an in-process ASGI mock so no real socket
    is bound."""
    from fastapi import FastAPI

    mock_tool = FastAPI()

    captured: dict = {}

    @mock_tool.post("/invoke")
    async def fake_invoke(body: dict) -> dict:
        captured["body"] = body
        return {"stdout": "80/tcp open http", "rc": 0}

    target = _make_target(["scanme.example.com"])

    async with DevHarness(
        engine_app=_ToolUsingRecon(),
        tool_urls={"fake-nmap": "http://fake-nmap-svc"},
        authorized_scope=["scanme.example.com"],
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as harness:
        # Reroute the harness's own outbound tool client to the in-process mock.
        await harness._tool_client.aclose()
        harness._tool_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mock_tool)
        )
        result = await harness.run_once(
            target=target, config={"target": "scanme.example.com"}
        )

    assert result.status == EngineStatus.SUCCESS, result.error_message
    assert result.output["tool_response"]["stdout"] == "80/tcp open http"
    assert captured["body"]["target"] == "scanme.example.com"

    # SDK auto-emits tool_invoked on success.
    kinds = [e["kind"] for e in harness.captured_events()]
    assert "tool_invoked" in kinds


# ---------- scope check ----------


@pytest.mark.asyncio
async def test_dev_harness_rejects_out_of_scope_tool_target(tmp_path: Path):
    """Harness's tool proxy mirrors core's P0-2 scope gate: any request
    field named url/target/host gets matched against authorized_scope.
    Out-of-scope → 403 → engine sees ScopeViolation → EngineResult(failed,
    error_code=SCOPE_VIOLATION)."""
    from fastapi import FastAPI

    mock_tool = FastAPI()

    @mock_tool.post("/invoke")
    async def fake_invoke(body: dict) -> dict:
        return {"stdout": "should not reach here"}

    target = _make_target(["scanme.example.com"])

    async with DevHarness(
        engine_app=_ScopeViolatingRecon(),
        tool_urls={"fake-nmap": "http://fake-nmap-svc"},
        authorized_scope=["scanme.example.com"],
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as harness:
        await harness._tool_client.aclose()
        harness._tool_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mock_tool)
        )
        result = await harness.run_once(target=target, config={})

    assert result.status == EngineStatus.FAILED
    assert result.error_code == "SCOPE_VIOLATION"


# ---------- missing tool config ----------


@pytest.mark.asyncio
async def test_dev_harness_unknown_tool_surfaces_as_tool_unavailable(
    tmp_path: Path,
):
    """No tool_urls entry for the requested tool → harness returns 502 →
    SDK turns that into ToolUnavailable → EngineResult(failed, code=
    TOOL_UNAVAILABLE)."""
    target = _make_target(["scanme.example.com"])

    async with DevHarness(
        engine_app=_ToolUsingRecon(),
        tool_urls={},  # nothing — fake-nmap is unknown
        authorized_scope=["scanme.example.com"],
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as harness:
        result = await harness.run_once(target=target, config={})

    assert result.status == EngineStatus.FAILED
    assert result.error_code == "TOOL_UNAVAILABLE"


# ---------- LLM-required engine without key ----------


class _LLMRequiredEngine(EngineApp):
    engine_id = "llm-required"
    version = "0.1.0"
    stage = "weakness_gather"
    capabilities = Capabilities(uses_llm=True)
    secret_requirements = [SecretRequirement(name="openai", required=True)]

    async def run(self, ctx: RunContext, config: dict) -> dict:
        return {"unreachable": True}


@pytest.mark.asyncio
async def test_dev_harness_llm_engine_without_key_fails_secret_missing(
    tmp_path: Path,
):
    """Engine declares secret_requirements=[openai required], harness has
    no openai_api_key set → envelope's secrets dict is empty → SDK raises
    SecretMissing during RunContext construction → SECRET_MISSING."""
    target = _make_target(["scanme.example.com"])

    async with DevHarness(
        engine_app=_LLMRequiredEngine(),
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
        openai_api_key=None,
    ) as harness:
        result = await harness.run_once(target=target, config={})

    assert result.status == EngineStatus.FAILED
    assert result.error_code == "SECRET_MISSING"


# ---------- lifecycle ----------


@pytest.mark.asyncio
async def test_dev_harness_start_stop_idempotent(tmp_path: Path):
    harness = DevHarness(
        engine_app=_NoToolRecon(),
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    )
    # Repeated start/stop must not raise.
    await harness.start()
    await harness.start()  # idempotent
    await harness.stop()
    await harness.stop()  # idempotent


@pytest.mark.asyncio
async def test_dev_harness_run_once_auto_starts(tmp_path: Path):
    """Calling run_once without an explicit start() should auto-start so
    students can write 1-line scripts."""
    target = _make_target(["scanme.example.com"])
    harness = DevHarness(
        engine_app=_NoToolRecon(),
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    )
    try:
        result = await harness.run_once(target=target, config={})
        assert result.status == EngineStatus.SUCCESS
    finally:
        await harness.stop()


@pytest.mark.asyncio
async def test_dev_harness_run_once_requires_target_or_targets(tmp_path: Path):
    async with DevHarness(
        engine_app=_NoToolRecon(),
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as harness:
        with pytest.raises(ValueError, match="target"):
            await harness.run_once()


@pytest.mark.asyncio
async def test_dev_harness_propagates_default_scope_to_target(
    tmp_path: Path,
):
    """When the user supplies a target with empty authorized_scope but the
    harness has authorized_scope=['x'], we copy the harness scope into the
    target so SDK's scope check sees a non-empty pattern list."""
    bare_target = TargetRef(
        id="t_bare",
        url="https://scanme.example.com/",
        target_type="web",
        authorized_scope=[],  # explicitly empty
    )

    async with DevHarness(
        engine_app=_NoToolRecon(),
        authorized_scope=["scanme.example.com"],
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as harness:
        result = await harness.run_once(target=bare_target)

    assert result.status == EngineStatus.SUCCESS
    out = ReconOutput.model_validate(result.output)
    assert out.target_ref.authorized_scope == ["scanme.example.com"]


# ---------- Codex review hardening (2026-04-24) ----------


# P1.3: harness must NOT mutate caller's TargetRef in place when filling
# in default scope. Otherwise re-running the same TargetRef leaves stale
# scope on it.
@pytest.mark.asyncio
async def test_dev_harness_does_not_mutate_caller_target(tmp_path: Path):
    bare_target = TargetRef(
        id="t_bare",
        url="https://scanme.example.com/",
        target_type="web",
        authorized_scope=[],
    )
    async with DevHarness(
        engine_app=_NoToolRecon(),
        authorized_scope=["scanme.example.com"],
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as harness:
        await harness.run_once(target=bare_target)

    # Caller's object must still have the original empty scope.
    assert bare_target.authorized_scope == []


# P0: events route must reject orchestrator-only kinds the same way prod
# core does — otherwise engines that BYPASS the SDK (write httpx.post
# directly, use a non-SDK engine binary, etc.) ship "works locally, 400
# on lab" bugs. SDK's internal whitelist isn't enough; the harness has
# to defend in depth, just like prod core does.
@pytest.mark.asyncio
async def test_dev_harness_events_route_rejects_orchestrator_only_kinds(
    tmp_path: Path,
):
    async with DevHarness(
        engine_app=_NoToolRecon(),
        authorized_scope=["scanme.example.com"],
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as harness:
        # Bypass the SDK entirely — POST directly to the harness's
        # events route as if we were a non-SDK engine implementation.
        resp = await harness._routed_client.post(
            "http://dev-harness/api/v1/runs/r_x/events",
            json={"kind": "stage_started", "payload": {"foo": "bar"}},
            headers={"X-Callback-Token": "dev-harness-callback-token"},
        )
        assert resp.status_code == 400
        assert "orchestrator-only" in resp.text or "may not emit" in resp.text

        # Unknown kind is also rejected (mirrors core's EventKind enum check).
        resp_unknown = await harness._routed_client.post(
            "http://dev-harness/api/v1/runs/r_x/events",
            json={"kind": "totally-made-up-kind", "payload": {}},
            headers={"X-Callback-Token": "dev-harness-callback-token"},
        )
        assert resp_unknown.status_code == 400
        assert "unknown event kind" in resp_unknown.text

        # Engine-allowed kind passes (sanity).
        resp_ok = await harness._routed_client.post(
            "http://dev-harness/api/v1/runs/r_x/events",
            json={
                "kind": "progress",
                "payload": {"percentage": 10},
                "client_ts": "2026-04-24T00:00:00Z",
                "run_id": "r_x",
                "stage_attempt_id": "sa_x",
                "stage": "recon",
                "engine": "test",
            },
            headers={"X-Callback-Token": "dev-harness-callback-token"},
        )
        assert resp_ok.status_code == 204, resp_ok.text


# P0/parity: CIDR scan target — super-CIDR rejected (matches prod
# target_in_scope), unlike the previous DevHarness shortcut which used
# url_in_scope and would silently accept it.
@pytest.mark.asyncio
async def test_dev_harness_rejects_super_cidr_for_nmap(tmp_path: Path):
    from fastapi import FastAPI

    mock_nmap = FastAPI()

    @mock_nmap.post("/invoke")
    async def _invoke(body: dict) -> dict:
        return {"stdout": "should not reach"}

    class _NmapEngine(EngineApp):
        engine_id = "nmap-super-cidr"
        version = "0.1.0"
        stage = "recon"
        capabilities = Capabilities(uses_llm=False)

        async def run(self, ctx: RunContext, config: dict) -> dict:
            # /16 is a SUPERSET of the /24 in scope — must be rejected.
            await ctx.call_tool("nmap", {"target": "10.0.0.0/16"})
            return {}

    target = TargetRef(
        id="t1",
        url="http://10.0.0.5/",
        target_type="web",
        authorized_scope=["10.0.0.0/24"],
    )
    async with DevHarness(
        engine_app=_NmapEngine(),
        tool_urls={"nmap": "http://fake-nmap-svc"},
        authorized_scope=["10.0.0.0/24"],
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as harness:
        await harness._tool_client.aclose()
        harness._tool_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mock_nmap)
        )
        result = await harness.run_once(target=target, config={})

    assert result.status == EngineStatus.FAILED
    assert result.error_code == "SCOPE_VIOLATION"


# P0/parity: CIDR scan target — sub-CIDR allowed (matches prod
# target_in_scope behavior).
@pytest.mark.asyncio
async def test_dev_harness_accepts_sub_cidr_for_nmap(tmp_path: Path):
    from fastapi import FastAPI

    mock_nmap = FastAPI()

    @mock_nmap.post("/invoke")
    async def _invoke(body: dict) -> dict:
        return {"stdout": "scanned"}

    class _NmapEngine(EngineApp):
        engine_id = "nmap-sub-cidr"
        version = "0.1.0"
        stage = "recon"
        capabilities = Capabilities(uses_llm=False)

        async def run(self, ctx: RunContext, config: dict) -> dict:
            # /26 is a SUBSET of /24 — should be allowed.
            r = await ctx.call_tool("nmap", {"target": "10.0.0.0/26"})
            return {"tool": r}

    target = TargetRef(
        id="t1",
        url="http://10.0.0.5/",
        target_type="web",
        authorized_scope=["10.0.0.0/24"],
    )
    async with DevHarness(
        engine_app=_NmapEngine(),
        tool_urls={"nmap": "http://fake-nmap-svc"},
        authorized_scope=["10.0.0.0/24"],
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as harness:
        await harness._tool_client.aclose()
        harness._tool_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mock_nmap)
        )
        result = await harness.run_once(target=target, config={})

    assert result.status == EngineStatus.SUCCESS, result.error_message


# P1.1: pluggable secrets dict — engines that use exa / nvd / arbitrary
# named secrets must be able to provide them via DevHarness.
@pytest.mark.asyncio
async def test_dev_harness_pluggable_secrets(tmp_path: Path):
    class _ExaUserEngine(EngineApp):
        engine_id = "exa-user"
        version = "0.1.0"
        stage = "weakness_gather"
        capabilities = Capabilities(uses_llm=False)
        secret_requirements = [
            SecretRequirement(name="exa", required=True),
            SecretRequirement(name="nvd", required=True),
        ]

        async def run(self, ctx: RunContext, config: dict) -> dict:
            return {"exa": ctx.secrets.exa, "nvd": ctx.secrets.nvd}

    target = _make_target(["x.example"])
    async with DevHarness(
        engine_app=_ExaUserEngine(),
        secrets={"exa": "exa-key-abc", "nvd": "nvd-key-xyz"},
        authorized_scope=["x.example"],
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as harness:
        result = await harness.run_once(target=target, config={})

    assert result.status == EngineStatus.SUCCESS, result.error_message
    assert result.output == {"exa": "exa-key-abc", "nvd": "nvd-key-xyz"}


# P3: harness must save and restore a previously-installed test client
# rather than always wiping it back to None on stop().
@pytest.mark.asyncio
async def test_dev_harness_preserves_outer_test_client(tmp_path: Path):
    from trustchain_sdk.testing import install_test_http_client
    from trustchain_sdk.context import _test_http_client as _slot  # noqa: F401

    sentinel_client = httpx.AsyncClient()
    install_test_http_client(sentinel_client)
    try:
        async with DevHarness(
            engine_app=_NoToolRecon(),
            authorized_scope=["scanme.example.com"],
            artifact_dir=tmp_path / "artifacts",
            events_path=None,
        ) as harness:
            await harness.run_once(target=_make_target(["scanme.example.com"]))

        # After the harness exits, the SDK slot must hold what was
        # installed before, not None.
        from trustchain_sdk.context import _test_http_client as _after_slot

        assert _after_slot is sentinel_client, (
            "DevHarness clobbered an outer caller's test client"
        )
    finally:
        install_test_http_client(None)
        await sentinel_client.aclose()


# Test gap fill (Codex): engine raises uncaught exception → INTERNAL_ERROR.
@pytest.mark.asyncio
async def test_dev_harness_unhandled_engine_exception_surfaces_as_internal_error(
    tmp_path: Path,
):
    class _BuggyEngine(EngineApp):
        engine_id = "buggy"
        version = "0.1.0"
        stage = "recon"
        capabilities = Capabilities(uses_llm=False)

        async def run(self, ctx: RunContext, config: dict) -> dict:
            raise ValueError("off-by-one")

    target = _make_target(["x.example"])
    async with DevHarness(
        engine_app=_BuggyEngine(),
        authorized_scope=["x.example"],
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as harness:
        result = await harness.run_once(target=target, config={})

    assert result.status == EngineStatus.FAILED
    assert result.error_code == "INTERNAL_ERROR"
    assert "off-by-one" in (result.error_message or "")


# Test gap fill (Codex): multiple targets supported (spec §8.1).
@pytest.mark.asyncio
async def test_dev_harness_accepts_multiple_targets(tmp_path: Path):
    class _MultiTargetEngine(EngineApp):
        engine_id = "multi-target"
        version = "0.1.0"
        stage = "recon"
        capabilities = Capabilities(uses_llm=False)

        async def run(self, ctx: RunContext, config: dict) -> dict:
            return {"n_targets": len(ctx.targets), "ids": [t.id for t in ctx.targets]}

    targets = [
        TargetRef(id="t1", url="https://a.example/", target_type="web",
                  authorized_scope=["a.example"]),
        TargetRef(id="t2", url="https://b.example/", target_type="web",
                  authorized_scope=["b.example"]),
    ]
    async with DevHarness(
        engine_app=_MultiTargetEngine(),
        authorized_scope=["a.example", "b.example"],
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as harness:
        result = await harness.run_once(targets=targets, config={})

    assert result.status == EngineStatus.SUCCESS, result.error_message
    assert result.output == {"n_targets": 2, "ids": ["t1", "t2"]}
