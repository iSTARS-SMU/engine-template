"""Run multiple engines as a pipeline end-to-end against real local tools.

Multi-stage sibling of `dev_run.py` (which only runs ONE engine). Uses the
SDK's DevHarness.run_pipeline() — same fake-core under the hood, just chains
each stage's output into the next stage's `ctx.upstream_outputs`.

Two ways to use it:

    Option 1 — Real chained pipeline
        Bring up the tool services your stages need:
            docker compose -f docker-compose.tools.yml up -d nmap-svc http-fetch-svc
        Then run:
            python dev_pipeline.py
        Each stage runs in order; later stages see earlier stages' outputs.

    Option 2 — Skip earlier stages (debug mode)
        Set CANNED_RECON below to a previously-saved ReconOutput dict (e.g.,
        loaded from a JSON file). Comment out the recon stage in STAGES.
        run_pipeline() seeds ctx.upstream_outputs["recon"] = CANNED_RECON
        and only weakness_gather + report run. Lets you iterate on a
        downstream stage without re-running expensive recon every time.

⚠️  COST WARNING ⚠️
A real recon → weakness_gather pipeline against an actual target with
gpt-4o can easily burn $5+ in LLM cost (recon's framework extraction +
weakness_gather's CVE extraction). To keep dev cheap:
  - Use OPENAI_API_KEY=sk-... env var pointing at a model like gpt-4o-mini
  - OR use Option 2 (canned upstream) to skip stages that don't need
    re-running while iterating on a downstream stage
  - OR leave OPENAI_API_KEY unset; LLM-using engines will soft-fail their
    LLM step (success=false in events, partial output) — fine for
    iterating on non-LLM logic
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from trustchain_contracts import TargetRef
from trustchain_sdk.testing import DevHarness

# ---------- import your engines (one EngineApp class per stage) ----------
# Replace with the engines YOUR pipeline needs. Each must be pip-installed
# from its repo (or pip install -e path/to/engine-source for local dev).
#
# from recon_targetinfo.engine import ReconTargetInfo
# from weakness_gather_exa.engine import WeaknessGatherExa
# from report_pro.engine import ReportPro

# For this template, we use the bundled hello-world engine as a single
# stage just so `python dev_pipeline.py` runs out-of-the-box. Swap in
# real engines (multiple stages, different `stage` values per engine.yaml)
# from your `STAGES` list below.
from hello_world.engine import HelloWorld


# ---------- where harness writes outputs ----------
OUT_DIR = Path("./.dev-pipeline")
ARTIFACT_DIR = OUT_DIR / "artifacts"
EVENTS_LOG = OUT_DIR / "events.jsonl"


# ---------- engine inputs ----------
TARGET = TargetRef(
    id="t1",
    url="https://scanme.nmap.org/",
    target_type="web",
    authorized_scope=["scanme.nmap.org"],
)


# ---------- tool URLs ----------
# Map tool_id (string passed to ctx.call_tool) → URL where its FastAPI
# service is listening on localhost. Bring matching services up with
# docker-compose.tools.yml first. Comment out tools your pipeline doesn't use.
TOOL_URLS: dict[str, str] = {
    # "nmap":       "http://localhost:9211",
    # "http_fetch": "http://localhost:9220",
    # "dig":        "http://localhost:9207",
    # "nuclei":     "http://localhost:9214",
    # "feroxbuster":"http://localhost:9215",
    # "whatweb":    "http://localhost:9212",
    # "wafw00f":    "http://localhost:9213",
    # "exa-search": "http://localhost:9216",
}


# ---------- the pipeline ----------
# List of (engine_instance, config_dict) tuples. Stages run in order;
# each stage's output becomes the next stage's ctx.upstream_outputs[<prev_stage>].
STAGES = [
    (HelloWorld(), {"greeting": "stage 1 hi"}),
    # (ReconTargetInfo(),   {"nmap_mode": "basic"}),
    # (WeaknessGatherExa(), {}),
    # (ReportPro(),         {"title": "test"}),
]


# ---------- (optional) seed upstream_outputs to skip earlier stages ----------
# Set to a dict of {stage_name: stage_output_dict} to feed canned upstream
# data. Useful for iterating on weakness_gather without re-running recon
# every time. None = no seed; pipeline starts from STAGES[0] with empty
# upstream_outputs.
CANNED_UPSTREAM: dict | None = None
# CANNED_UPSTREAM = json.loads(Path("./fixtures/recon_output.json").read_text())


async def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)

    # Engines that declare uses_llm=true expect an "openai" secret in the
    # envelope. We pull it from env so the student keeps full control of cost.
    secrets: dict[str, str] = {}
    if openai_key := os.environ.get("OPENAI_API_KEY"):
        secrets["openai"] = openai_key

    async with DevHarness(
        # No engine_app= — we're pipeline-only; engines come from STAGES.
        tool_urls=TOOL_URLS,
        authorized_scope=list(TARGET.authorized_scope),
        artifact_dir=ARTIFACT_DIR,
        events_path=EVENTS_LOG,
        secrets=secrets,
    ) as harness:
        result = await harness.run_pipeline(
            target=TARGET,
            stages=STAGES,
            upstream_outputs={"recon": CANNED_UPSTREAM} if CANNED_UPSTREAM else None,
        )

    # ---- pretty-print summary ----
    print("=" * 60)
    print(f"pipeline run_id: {result.run_id}")
    print(f"succeeded:       {result.succeeded}")
    if result.failed_stage is not None:
        stage_name, failed_result = result.failed_stage
        print(f"FAILED stage:    {stage_name}")
        print(f"  error_code:    {failed_result.error_code}")
        print(f"  error_message: {failed_result.error_message}")
        print(f"  retryable:     {failed_result.retryable}")
    print(f"events:          {len(result.events)} → {EVENTS_LOG}")
    print(f"artifacts:       {len(result.artifacts)} → {ARTIFACT_DIR / result.run_id}")
    print()
    print("=== outputs ===")
    for stage_name, output in result.outputs.items():
        print(f"--- {stage_name} ---")
        print(json.dumps(output, indent=2, default=str))
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
