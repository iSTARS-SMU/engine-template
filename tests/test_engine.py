"""Unit tests for hello-world — runnable on a dev laptop with no docker, no network.

Every engine should have at least:
    * 1 happy path
    * 2 error paths (bad upstream, missing secret, tool failure, ...)
    * 1 idempotency check — same (run_id, stage, config, upstream_outputs) →
      semantically equal outputs on two calls (see spec §7.5.4).
"""

import pytest

from trustchain_contracts import ReconOutput, TargetRef
from trustchain_sdk.testing import MockContext

from src.engine import HelloWorld


@pytest.mark.asyncio
async def test_happy_path():
    ctx = MockContext(
        targets=[
            TargetRef(
                id="t1",
                url="https://example.com",
                authorized_scope=["example.com"],
            )
        ],
    )

    result = await HelloWorld().run(ctx, config={"greeting": "hi"})

    # Result is a ReconOutput (contracts DTO — recommended stage output shape).
    assert isinstance(result, ReconOutput)
    assert result.target_ref.url == "https://example.com"
    assert "hi" in result.notes
    assert len(result.endpoints) >= 1

    # Progress events are emitted.
    progress = [e for e in ctx.captured_events() if e["kind"] == "progress"]
    assert len(progress) >= 2
    assert progress[0]["payload"]["percentage"] == 0
    assert progress[-1]["payload"]["percentage"] == 100


@pytest.mark.asyncio
async def test_yaml_loaded():
    """Smoke the yaml-as-SOT wiring: after construction, the engine identity
    and capabilities are those declared in engine.yaml (not class defaults)."""
    engine = HelloWorld()
    assert engine.engine_id == "hello-world"
    assert engine.version == "0.1.0"
    assert engine.stage == "recon"
    assert engine.capabilities.uses_llm is False
    assert "$ref" in engine.output_schema


@pytest.mark.asyncio
async def test_no_targets():
    """Degenerate input — engine should not crash."""
    ctx = MockContext(targets=[])
    result = await HelloWorld().run(ctx, config={})
    assert isinstance(result, ReconOutput)
    assert "no target" in result.notes


@pytest.mark.asyncio
async def test_default_greeting():
    """Missing config key falls back to yaml schema default ('hello')."""
    ctx = MockContext(
        targets=[TargetRef(id="t1", url="https://x", authorized_scope=["x"])]
    )
    result = await HelloWorld().run(ctx, config={})
    assert "hello" in result.notes


@pytest.mark.asyncio
async def test_idempotent():
    """Spec §7.5.4: two calls with the same (config, upstream_outputs) should
    produce semantically equal output."""
    mk_ctx = lambda: MockContext(  # noqa: E731
        targets=[TargetRef(id="t1", url="https://example.com", authorized_scope=["example.com"])]
    )
    a = await HelloWorld().run(mk_ctx(), config={"greeting": "hi"})
    b = await HelloWorld().run(mk_ctx(), config={"greeting": "hi"})
    assert a == b
