"""Run THIS engine end-to-end against real tool services on localhost.

Uses `trustchain_sdk.testing.DevHarness` — a thin FastAPI app that fakes
core's three engine-callback endpoints (events / tools / artifacts) so
your engine code path is byte-identical to lab production. The only
difference: callbacks land on localhost in-process, and tool calls are
forwarded to whatever you put in `tool_urls`.

Two ways to bring up the tool services:

  Option A — pull pre-built images (easiest, recommended)
      docker compose -f docker-compose.tools.yml up -d nmap-svc http-fetch-svc
      python dev_run.py

  Option B — build tool images yourself from
      https://github.com/iSTARS-SMU/trustchain-tools
      (only needed if you're modifying a tool wrapper)

After this script runs, find the artifacts and event log under ./.dev-run/.

Hello-world engine doesn't actually call any tools — but the wiring below
shows you how to add tool URLs once your engine grows ctx.call_tool() calls.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from trustchain_contracts import TargetRef
from trustchain_sdk.testing import DevHarness

# Import the EngineApp subclass (NOT the FastAPI app) — DevHarness calls
# its .invoke() method directly, no HTTP. Match this to your engine class.
from hello_world.engine import HelloWorld as EngineClass


# ---------- where harness writes outputs ----------
OUT_DIR = Path("./.dev-run")
ARTIFACT_DIR = OUT_DIR / "artifacts"
EVENTS_LOG = OUT_DIR / "events.jsonl"


# ---------- engine inputs ----------
TARGET = TargetRef(
    id="t1",
    url="https://scanme.nmap.org/",
    target_type="web",
    # In real production runs the operator declares authorized_scope when
    # submitting the run. Here you (the engine dev) set it for your local test.
    authorized_scope=["scanme.nmap.org"],
)

CONFIG: dict = {
    # Hello-world reads `greeting`. Replace with your engine's config keys.
    "greeting": "hello from dev_run",
}

# ---------- tool URLs ----------
# Map tool_id (the string you'd pass to ctx.call_tool("<tool_id>", ...)) to
# the URL its FastAPI service is listening on. Bring matching services up
# with docker-compose.tools.yml first. Comment out tools you don't use.
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


async def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)

    # If your engine declares uses_llm=true, set OPENAI_API_KEY in env or
    # pass openai_api_key=... here. Without it, ctx.llm.chat() raises
    # LLMUnavailable — useful for testing soft-fail paths.
    async with DevHarness(
        engine_app=EngineClass(),
        tool_urls=TOOL_URLS,
        authorized_scope=list(TARGET.authorized_scope),
        artifact_dir=ARTIFACT_DIR,
        events_path=EVENTS_LOG,
    ) as harness:
        result = await harness.run_once(target=TARGET, config=CONFIG)

    print("=" * 60)
    print(f"status:        {result.status}")
    if result.error_code:
        print(f"error_code:    {result.error_code}")
        print(f"error_message: {result.error_message}")
    if result.output:
        print("output:")
        print(json.dumps(result.output, indent=2, default=str))
    print(f"events:        {len(harness.captured_events())} → {EVENTS_LOG}")
    print(f"artifacts:     {len(harness.captured_artifacts())} → {ARTIFACT_DIR}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
