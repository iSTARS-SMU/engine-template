"""Tests for DevHarness.run_pipeline — multi-stage local integration.

Phase 1.5e. Covers what the per-stage `run_once` tests in `test_dev_harness.py`
can't reach:
  - upstream output flowing from stage N to stage N+1
  - shared run_id across all stages of one pipeline (prod parity — engines
    that namespace artifacts by ctx.run_id break otherwise)
  - PipelineResult.events / .artifacts scoped to THIS pipeline only
  - first failed stage halts pipeline (later stages don't run)
  - duplicate stage name → ValueError (no silent overwrite)
  - upstream_outputs= seed kwarg (skip a stage by feeding canned input)
  - DevHarness(engine_app=None) supported when only run_pipeline is used
  - missing engine_app → meaningful ValueError, not AttributeError
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trustchain_contracts import (
    Capabilities,
    Endpoint,
    EngineStatus,
    ReconOutput,
    TargetRef,
    TechFingerprint,
)
from trustchain_sdk import EngineApp, RunContext
from trustchain_sdk.testing import DevHarness, PipelineResult


# ---------- shared engines for the suite ----------

# A 1x1 PNG; embedded so the suite doesn't depend on fake-recon being installed.
_TINY_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xfa"
    b"\xff\xff?\x03\x00\x05\xfe\x02\xfeA\x7f\x8b\x16\x00\x00\x00\x00IEND"
    b"\xaeB`\x82"
)


class _ReconLite(EngineApp):
    """Recon stage. No tools. Captures ctx.run_id into the output so we can
    assert run_id propagation from outside."""

    engine_id = "recon-lite"
    version = "0.1.0"
    stage = "recon"
    capabilities = Capabilities(uses_llm=False)

    async def run(self, ctx: RunContext, config: dict) -> dict:
        await ctx.emit_event("progress", {"percentage": 50})
        ref = await ctx.save_artifact(
            name="recon.png", data=_TINY_PNG, kind="screenshot",
            mime_type="image/png",
        )
        # Return as dict (not Pydantic) so downstream stages can introspect freely.
        return {
            "ran_run_id": ctx.run_id,
            "tech": "flask",
            "endpoints": ["/", "/login"],
            "artifact_id": ref.id,
        }


class _WeaknessGather(EngineApp):
    """Weakness gather. Reads upstream recon output. Echoes it back so
    tests can assert exact propagation."""

    engine_id = "weakness-lite"
    version = "0.1.0"
    stage = "weakness_gather"
    capabilities = Capabilities(uses_llm=False)

    async def run(self, ctx: RunContext, config: dict) -> dict:
        recon = ctx.upstream_outputs.get("recon", {})
        return {
            "ran_run_id": ctx.run_id,
            "saw_recon": recon,
            "weaknesses": [
                {"id": "W-1", "from_endpoint": ep}
                for ep in recon.get("endpoints", [])
            ],
        }


class _ReportLite(EngineApp):
    engine_id = "report-lite"
    version = "0.1.0"
    stage = "report"
    capabilities = Capabilities(uses_llm=False)

    async def run(self, ctx: RunContext, config: dict) -> dict:
        weak = ctx.upstream_outputs.get("weakness_gather", {})
        return {
            "ran_run_id": ctx.run_id,
            "n_weaknesses": len(weak.get("weaknesses", [])),
            "title": config.get("title", "untitled"),
        }


class _BadFirst(EngineApp):
    """Always fails. Used to verify halt-on-first-failure semantics."""

    engine_id = "bad-first"
    version = "0.1.0"
    stage = "recon"
    capabilities = Capabilities(uses_llm=False)

    async def run(self, ctx: RunContext, config: dict) -> dict:
        raise ValueError("intentional first-stage failure")


def _make_target() -> TargetRef:
    return TargetRef(
        id="t1",
        url="https://x.example/",
        target_type="web",
        authorized_scope=["x.example"],
    )


# ---------- happy path ----------


@pytest.mark.asyncio
async def test_run_pipeline_three_stages_chain_outputs(tmp_path: Path):
    async with DevHarness(
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as h:
        result = await h.run_pipeline(
            target=_make_target(),
            stages=[
                (_ReconLite(),       {}),
                (_WeaknessGather(),  {}),
                (_ReportLite(),      {"title": "test"}),
            ],
        )

    assert isinstance(result, PipelineResult)
    assert result.succeeded
    assert result.failed_stage is None

    # All three stages have outputs.
    assert set(result.outputs) == {"recon", "weakness_gather", "report"}
    # Per-stage EngineResult full detail available.
    assert set(result.stage_results) == {"recon", "weakness_gather", "report"}
    for r in result.stage_results.values():
        assert r.status == EngineStatus.SUCCESS

    # Stage 2 saw stage 1's output exactly.
    assert result.outputs["weakness_gather"]["saw_recon"] == result.outputs["recon"]
    # Stage 3 saw stage 2's weakness count.
    assert result.outputs["report"]["n_weaknesses"] == 2  # 2 endpoints → 2 weaknesses


@pytest.mark.asyncio
async def test_run_pipeline_shares_one_run_id_across_stages(tmp_path: Path):
    """Codex P0: all stages of one pipeline must share one run_id (prod
    parity — engines that namespace artifacts by ctx.run_id silently
    break otherwise)."""
    async with DevHarness(
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as h:
        result = await h.run_pipeline(
            target=_make_target(),
            stages=[
                (_ReconLite(),      {}),
                (_WeaknessGather(), {}),
                (_ReportLite(),     {}),
            ],
        )

    # PipelineResult exposes the shared run_id.
    assert result.run_id.startswith("r_")

    # Every stage's run() saw the SAME run_id (we captured it into output).
    assert result.outputs["recon"]["ran_run_id"] == result.run_id
    assert result.outputs["weakness_gather"]["ran_run_id"] == result.run_id
    assert result.outputs["report"]["ran_run_id"] == result.run_id

    # Every event the harness captured carries the same run_id.
    assert all(e["run_id"] == result.run_id for e in result.events)
    # Every artifact too.
    assert all(a.run_id == result.run_id for a in result.artifacts)


# ---------- failure handling ----------


@pytest.mark.asyncio
async def test_run_pipeline_first_failed_stage_halts(tmp_path: Path):
    async with DevHarness(
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as h:
        result = await h.run_pipeline(
            target=_make_target(),
            stages=[
                (_BadFirst(),        {}),
                (_WeaknessGather(),  {}),  # MUST NOT run
                (_ReportLite(),      {}),  # MUST NOT run
            ],
        )

    assert not result.succeeded
    assert result.failed_stage is not None
    failed_name, failed_result = result.failed_stage
    assert failed_name == "recon"
    assert failed_result.status == EngineStatus.FAILED
    assert failed_result.error_code == "INTERNAL_ERROR"

    # Only the failed stage appears in stage_results; downstream stages didn't run.
    assert set(result.stage_results) == {"recon"}
    assert "weakness_gather" not in result.outputs
    assert "report" not in result.outputs


# ---------- duplicate stage name ----------


@pytest.mark.asyncio
async def test_run_pipeline_duplicate_stage_name_raises(tmp_path: Path):
    """Two engines with the same `stage` value → ValueError (loud), not
    silent overwrite of the first stage's output dict."""
    async with DevHarness(
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as h:
        with pytest.raises(ValueError, match="duplicate stage name"):
            await h.run_pipeline(
                target=_make_target(),
                stages=[
                    (_ReconLite(), {}),
                    (_ReconLite(), {}),  # same stage="recon" — should fail
                ],
            )


# ---------- captured events scoping ----------


@pytest.mark.asyncio
async def test_run_pipeline_events_scoped_to_this_pipeline(tmp_path: Path):
    """Two run_pipeline calls in one harness session — second result's
    events MUST contain only the second pipeline's events, not both."""
    async with DevHarness(
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as h:
        first = await h.run_pipeline(
            target=_make_target(),
            stages=[(_ReconLite(), {})],
        )
        second = await h.run_pipeline(
            target=_make_target(),
            stages=[(_ReconLite(), {})],
        )

    # Each pipeline emitted its own events; results are independently scoped.
    assert first.run_id != second.run_id
    assert all(e["run_id"] == first.run_id for e in first.events)
    assert all(e["run_id"] == second.run_id for e in second.events)
    # Artifacts too.
    assert all(a.run_id == first.run_id for a in first.artifacts)
    assert all(a.run_id == second.run_id for a in second.artifacts)


# ---------- upstream_outputs seed kwarg ----------


@pytest.mark.asyncio
async def test_run_pipeline_seed_upstream_outputs_skips_earlier_stage(
    tmp_path: Path,
):
    """Caller can feed canned upstream data and skip recon entirely. Useful
    for migration debug — iterate on weakness_gather without rerunning a
    30-second recon every time."""
    canned_recon = {
        "tech": "django",
        "endpoints": ["/api/users", "/api/orders", "/admin"],
    }
    async with DevHarness(
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as h:
        result = await h.run_pipeline(
            target=_make_target(),
            stages=[(_WeaknessGather(), {})],   # no recon stage at all
            upstream_outputs={"recon": canned_recon},
        )

    assert result.succeeded
    # weakness_gather stage saw the canned recon data, not an empty dict.
    saw = result.outputs["weakness_gather"]["saw_recon"]
    assert saw == canned_recon
    # 3 endpoints in the canned data → 3 weaknesses.
    assert len(result.outputs["weakness_gather"]["weaknesses"]) == 3


# ---------- pipeline-only DevHarness construction ----------


@pytest.mark.asyncio
async def test_devharness_engine_app_optional_for_pipeline_only(tmp_path: Path):
    """Constructor's engine_app is now optional — pipeline-only callers
    pass engines per-stage."""
    async with DevHarness(
        # NO engine_app=
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as h:
        result = await h.run_pipeline(
            target=_make_target(),
            stages=[(_ReconLite(), {}), (_WeaknessGather(), {})],
        )
    assert result.succeeded


@pytest.mark.asyncio
async def test_run_once_no_engine_app_raises_clear_error(tmp_path: Path):
    """When neither constructor nor run_once supply an engine_app, raise a
    helpful ValueError instead of AttributeError on None.invoke(...)."""
    async with DevHarness(
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as h:
        with pytest.raises(ValueError, match="no engine_app"):
            await h.run_once(target=_make_target(), config={})


# ---------- empty stages list ----------


@pytest.mark.asyncio
async def test_run_pipeline_empty_stages_raises(tmp_path: Path):
    async with DevHarness(
        artifact_dir=tmp_path / "artifacts",
        events_path=None,
    ) as h:
        with pytest.raises(ValueError, match="non-empty"):
            await h.run_pipeline(target=_make_target(), stages=[])
