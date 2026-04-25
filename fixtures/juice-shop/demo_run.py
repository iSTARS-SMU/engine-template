"""Run the full 5-stage TrustChain pipeline against OWASP Juice Shop
with curated LLM responses (zero LLM cost). REAL tools, REAL exploit
execution, mock LLM "intelligence".

This is the canonical "first demo" for new students after the README
Quickstart. It proves the platform end-to-end against a known-vulnerable
target without spending any LLM credits.

Prereq (all from a fresh student-style sibling-checkout):

    # Step 0 — sibling-checkout layout (same as README §Quickstart)
    mkdir -p ~/pentest-dev && cd ~/pentest-dev
    git clone git@github.com:iSTARS-SMU/engine-template.git my-engine
    git clone git@github.com:iSTARS-SMU/recon-targetinfo.git
    git clone git@github.com:iSTARS-SMU/weakness-gather-exa.git
    git clone git@github.com:iSTARS-SMU/attack-plan-llm.git
    git clone git@github.com:iSTARS-SMU/exploit-autoeg.git
    git clone git@github.com:iSTARS-SMU/report-docx-pro.git

    # Step 1 — venv + install all 5 engines + my-engine editable
    cd my-engine
    python3 -m venv .venv && source .venv/bin/activate
    pip install -e ./vendor/contracts -e './vendor/sdk[server,openai]' -e '.[dev]'
    pip install -e ../recon-targetinfo -e ../weakness-gather-exa \\
                -e ../attack-plan-llm -e ../exploit-autoeg -e ../report-docx-pro

    # Step 2 — juice-shop running locally on port 3001
    docker run --rm -p 3001:3000 bkimminich/juice-shop

    # Step 3 — start all 14 tool services (uses the demo-bundle compose)
    docker compose -f fixtures/juice-shop/docker-compose.tools-all.yml up -d

    # Step 4 — run the demo
    python fixtures/juice-shop/demo_run.py

Outputs land in ./fixtures/juice-shop/.juice-shop-demo/ — events.jsonl
plus all artifacts (raw tool outputs, exploit scripts, server responses,
the final .docx report).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from trustchain_contracts import TargetRef
from trustchain_sdk import install_fixture_hook
from trustchain_sdk.testing import DevHarness


# Engines (sibling-installed by dev-install.sh)
from recon_targetinfo.engine import ReconTargetinfoEngine
from weakness_gather_exa.engine import WeaknessGatherExaEngine
from attack_plan_llm.engine import AttackPlanLLMEngine
from exploit_autoeg.engine import ExploitAutoEGEngine
from report_docx_pro.engine import ReportDocxProEngine


HERE = Path(__file__).parent.resolve()
OUT_DIR = HERE / ".juice-shop-demo"
ARTIFACT_DIR = OUT_DIR / "artifacts"
EVENTS_LOG = OUT_DIR / "events.jsonl"


# ---------- target ----------
TARGET = TargetRef(
    id="t_juice",
    url="http://localhost:3001/",
    target_type="web",
    authorized_scope=["localhost", "localhost:3001", "127.0.0.1", "127.0.0.1:3001"],
)


# ---------- tool URLs (must match running container ports) ----------
TOOL_URLS: dict[str, str] = {
    "nmap":        "http://localhost:9211",
    "http_fetch":  "http://localhost:9220",
    "dig":         "http://localhost:9207",
    "whatweb":     "http://localhost:9212",
    "wafw00f":     "http://localhost:9213",
    "nuclei":      "http://localhost:9214",
    "feroxbuster": "http://localhost:9215",
    "exa-search":  "http://localhost:9216",
    "nvd-search":  "http://localhost:9217",
    "webstructure":"http://localhost:9218",
    "whois":       "http://localhost:9208",
    "gau":         "http://localhost:9103",
    "waybackurls": "http://localhost:9104",
    "linkfinder":  "http://localhost:9105",
}


# ---------- 5-stage pipeline. safe_mode=False → exploit script REALLY
#            runs against juice-shop. ----------
STAGES = [
    (ReconTargetinfoEngine(), {
        "nmap_mode": "basic",
        "webstructure_max_pages": 80,
        "webstructure_max_depth": 2,
        # Playwright on (default) so juice-shop's Angular routes get rendered.
    }),
    (WeaknessGatherExaEngine(), {
        "max_exa_queries": 3,
        # Bypass weakness-gather-exa v0.1.0 bug: default sends
        # cvss_v3_severity="HIGH,CRITICAL" but the nvd-search tool API
        # only accepts a single literal value (LOW/MEDIUM/HIGH/CRITICAL).
        # Empty string → engine sends None → NVD returns all severities.
        # Engine-side fix tracked separately (will land in v0.2.0).
        "nvd_severity_filter": "",
    }),
    (AttackPlanLLMEngine(), {
        "max_steps": 4,
        # AttackPlanLLM defaults force_safe_mode=True for safety; demo
        # explicitly opts out so our fixture's safe_mode=false claim
        # propagates through to the exploit stage. Demo is against a
        # local juice-shop on a known-vulnerable port — safe.
        "force_safe_mode": False,
    }),
    (ExploitAutoEGEngine(), {
        "safe_mode": False,                  # REAL EXECUTION
        "budget_usd_per_step": 5.00,         # generous (fixture costs $0 anyway)
        "max_exploit_attempts": 2,           # 1 main + 1 refine
        "exec_timeout_sec": 15,
    }),
    (ReportDocxProEngine(), {
        "use_llm_summary": True,             # routes through fixture
        "report_title": "OWASP Juice Shop — TrustChain Demo Assessment",
        "organization_name": "iSTARS Lab Demo",
    }),
]


async def main() -> int:
    OUT_DIR.mkdir(exist_ok=True)

    # Install the fixture hook BEFORE any engine runs. This monkey-
    # patches LLMClient.chat at the class level — every ctx that any
    # engine constructs from this point routes LLM calls through the
    # fixture dir.
    install_fixture_hook(HERE)

    # Even with the fixture, engines whose engine.yaml declares openai
    # as a required secret will refuse to start without it set. The
    # fixture intercepts before the real provider is called, so the
    # value just needs to be non-empty.
    os.environ.setdefault("OPENAI_API_KEY", "sk-fixture-mode")

    secrets = {"openai": os.environ.get("OPENAI_API_KEY", "sk-fixture-mode")}

    print("=" * 70)
    print("TrustChain Pentest — OWASP Juice Shop demo run (fixture-driven LLM)")
    print(f"Target:          {TARGET.url}")
    print(f"Stages:          {len(STAGES)} (recon → weakness → attack → exploit → report)")
    print(f"Tool services:   {len(TOOL_URLS)} configured")
    print(f"Fixture dir:     {HERE}")
    print(f"safe_mode:       FALSE (exploit will REALLY run against {TARGET.url})")
    print(f"Output dir:      {OUT_DIR}")
    print("=" * 70)
    print()

    started = datetime.now(timezone.utc)
    async with DevHarness(
        tool_urls=TOOL_URLS,
        authorized_scope=list(TARGET.authorized_scope),
        artifact_dir=ARTIFACT_DIR,
        events_path=EVENTS_LOG,
        secrets=secrets,
        llm_default_model="gpt-4o-mini",
    ) as harness:
        result = await harness.run_pipeline(stages=STAGES, target=TARGET)
    elapsed = (datetime.now(timezone.utc) - started).total_seconds()

    print()
    print("=" * 70)
    print(f"pipeline run_id: {result.run_id}")
    print(f"succeeded:       {result.failed_stage is None}")
    print(f"elapsed:         {elapsed:.1f}s")
    print(f"events:          {len(result.events)} → {EVENTS_LOG}")
    print(f"artifacts:       {len(result.artifacts)} → {ARTIFACT_DIR}/{result.run_id}/")
    if result.failed_stage:
        stage_name, stage_result = result.failed_stage
        print(f"FAILED at stage: {stage_name}: {stage_result.status} {stage_result.error_code} {stage_result.error_message}")
    print("=" * 70)
    print()
    print("=== outputs ===")
    for stage_name, stage_result in result.stage_results.items():
        print(f"--- {stage_name} ---")
        out = stage_result.output
        if hasattr(out, "model_dump"):
            out = out.model_dump(mode="json")
        print(json.dumps(out, indent=2, default=str)[:2000])
    return 0 if result.failed_stage is None else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
