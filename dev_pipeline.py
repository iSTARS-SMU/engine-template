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
  - Set per-stage env vars in `.env`:
      TRUSTCHAIN_RECON_LLM_MODE=mock|real
      TRUSTCHAIN_WEAKNESS_GATHER_LLM_MODE=mock|real
  - Use OPENAI_API_KEY=sk-... only for stages running in real mode
  - OR use Option 2 (canned upstream) to skip stages that don't need
    re-running while iterating on a downstream stage
  - In mock mode this script injects a placeholder `openai` secret so
    engines with `required: true` still run, but their LLM step returns
    canned output instead of calling the provider
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import re
from pathlib import Path
from types import MethodType
from typing import Any

from trustchain_contracts import Severity, TargetRef, TechFingerprint, Weakness
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
DOTENV_PATH = Path("./.env")


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


_MOCK_MODE_VALUES = {"mock", "stub", "sub"}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _load_dotenv_if_present(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        os.environ.setdefault(key, value)


def _llm_mode_for_stage(stage_name: str) -> str:
    stage_name = stage_name.strip().lower()
    if stage_name == "recon":
        raw = os.environ.get("TRUSTCHAIN_RECON_LLM_MODE", "real")
    elif stage_name == "weakness_gather":
        raw = os.environ.get(
            "TRUSTCHAIN_WEAKNESS_GATHER_LLM_MODE",
            os.environ.get("TRUSTCHAIN_WEAKNESS_LLM_MODE", "real"),
        )
    else:
        raw = "real"
    return "mock" if raw.strip().lower() in _MOCK_MODE_VALUES else "real"


def _llm_stages(stages: list[tuple[Any, dict[str, Any]]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for engine_app, _ in stages:
        caps = getattr(engine_app, "capabilities", None)
        if not bool(getattr(caps, "uses_llm", False)):
            continue
        stage_name = getattr(engine_app, "stage", "") or "<unknown>"
        out.append((stage_name, _llm_mode_for_stage(stage_name)))
    return out


def _mock_recon_fingerprint() -> TechFingerprint:
    return TechFingerprint(
        framework="django",
        server="nginx/1.24.0",
        language="python",
        versions={"django": "4.2.0", "nginx": "1.24.0"},
    )


def _build_mock_search_plan(recon: Any, max_queries: int) -> list[str]:
    fp = recon.tech_fingerprint
    versions = dict(fp.versions or {})
    queries: list[str] = []

    def _add(query: str) -> None:
        query = " ".join(query.split())
        if query and query not in queries:
            queries.append(query)

    if fp.framework:
        ver = versions.get(fp.framework) or versions.get(fp.framework.lower())
        _add(f"{fp.framework} {ver or ''} CVE")
    if fp.server:
        _add(f"{fp.server.replace('/', ' ')} vulnerability")
    if fp.cms:
        ver = versions.get(fp.cms) or versions.get(fp.cms.lower())
        _add(f"{fp.cms} {ver or ''} security advisory")
    if fp.language:
        ver = versions.get(fp.language) or versions.get(fp.language.lower())
        _add(f"{fp.language} {ver or ''} CVE")
    if not queries:
        target_url = recon.target_ref.url if recon.target_ref else "web app"
        _add(f"{target_url} known vulnerabilities")
    return queries[:max_queries]


def _mock_extract_weaknesses(exa_responses: list[dict[str, Any]], *, start_id: int) -> list[Weakness]:
    out: list[Weakness] = []
    seen: set[str] = set()
    next_id = start_id

    for response in exa_responses:
        query = str(response.get("query") or "")
        for entry in response.get("results", [])[:3]:
            title = str(entry.get("title") or "")
            text = str(entry.get("text") or "")
            url = str(entry.get("url") or "")
            combined = f"{title}\n{text}"
            cve_match = _CVE_RE.search(combined)
            cve = cve_match.group(0) if cve_match else None
            dedup_key = cve or url or title or query
            if not dedup_key or dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = Severity.HIGH if cve else Severity.MEDIUM
            description = (title or text or query or "candidate weakness from exa result")[:1000]
            evidence = (text or title or query)[:200] or None
            refs = [url] if url else []

            out.append(
                Weakness(
                    id=f"w_{next_id}",
                    type="cve" if cve else "web_vulnerability",
                    severity_hint=severity,
                    description=description,
                    cve=cve,
                    source="exa",
                    evidence_snippet=evidence,
                    references=refs,
                )
            )
            next_id += 1
            if len(out) >= 5:
                return out
    return out


def _install_llm_mocks(stages: list[tuple[Any, dict[str, Any]]]) -> list[tuple[Any, str, Any]]:
    patches: list[tuple[Any, str, Any]] = []
    patched_weakness_module = False

    for engine_app, _ in stages:
        stage_name = getattr(engine_app, "stage", "") or ""
        mode = _llm_mode_for_stage(stage_name)
        if mode != "mock":
            continue

        module_name = engine_app.__class__.__module__
        if stage_name == "recon" and module_name == "recon_targetinfo.engine":
            original = engine_app._extract_fingerprint

            async def _mock_extract_fingerprint(
                self,
                ctx,
                *,
                nmap_result,
                dig_result=None,
                whatweb_result=None,
                wafw00f_result=None,
                endpoints,
                target_url,
                model,
                notes_parts,
                max_chars=4000,
                max_endpoints=30,
            ):
                notes_parts.append("llm fingerprint mocked (TRUSTCHAIN_RECON_LLM_MODE=mock)")
                return _mock_recon_fingerprint()

            engine_app._extract_fingerprint = MethodType(_mock_extract_fingerprint, engine_app)
            patches.append((engine_app, "_extract_fingerprint", original))

        if stage_name == "weakness_gather" and module_name == "weakness_gather_exa.engine" and not patched_weakness_module:
            module = importlib.import_module(module_name)
            original_plan = module._llm_search_plan
            original_extract = module._llm_extract_weaknesses

            async def _mock_search_plan(ctx, recon, max_exa):
                return _build_mock_search_plan(recon, max_exa)

            async def _mock_extract(ctx, exa_responses, recon, *, start_id):
                return _mock_extract_weaknesses(exa_responses, start_id=start_id)

            module._llm_search_plan = _mock_search_plan
            module._llm_extract_weaknesses = _mock_extract
            patches.append((module, "_llm_search_plan", original_plan))
            patches.append((module, "_llm_extract_weaknesses", original_extract))
            patched_weakness_module = True

    return patches


def _restore_patches(patches: list[tuple[Any, str, Any]]) -> None:
    for obj, attr, original in reversed(patches):
        setattr(obj, attr, original)


async def main() -> None:
    _load_dotenv_if_present(DOTENV_PATH)
    OUT_DIR.mkdir(exist_ok=True)

    # Engines that declare uses_llm=true expect an "openai" secret in the
    # envelope. We pull it from env so the student keeps full control of cost.
    secrets: dict[str, str] = {}
    llm_modes = _llm_stages(STAGES)
    mock_llm_stages = [stage for stage, mode in llm_modes if mode == "mock"]
    real_llm_stages = [stage for stage, mode in llm_modes if mode == "real"]
    if openai_key := os.environ.get("OPENAI_API_KEY"):
        secrets["openai"] = openai_key
    elif mock_llm_stages and not real_llm_stages:
        # Required secret check still runs before the stage body. Inject a
        # placeholder so engines with `required: true` can enter their mocked
        # LLM path without needing a live provider key.
        secrets["openai"] = "mock-openai-key"
    elif real_llm_stages:
        raise SystemExit(
            "OPENAI_API_KEY is required for real LLM mode. "
            f"Stages in real mode: {', '.join(real_llm_stages)}"
        )

    patches = _install_llm_mocks(STAGES)

    try:
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
    finally:
        _restore_patches(patches)

    # ---- pretty-print summary ----
    print("=" * 60)
    if llm_modes:
        print("llm_modes:       " + ", ".join(f"{stage}={mode}" for stage, mode in llm_modes))
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
