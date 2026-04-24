"""Hello-world engine — reference implementation.

Demonstrates the recommended pattern: yaml is the single source of truth
for declarative metadata (id / version / stage / capabilities / schemas);
the class only implements ``run()``. Fork this file to start a new engine.
"""

from trustchain_sdk import EngineApp, RunContext
from trustchain_contracts import Endpoint, ReconOutput, TechFingerprint


class HelloWorld(EngineApp):
    # --- Class-level defaults (fallback when engine.yaml is not on disk —
    # e.g. when this engine is `pip install`ed as a wheel without the
    # accompanying engine.yaml at the repo root). yaml STILL wins when
    # found; these match the yaml exactly so detection of drift is clean.
    engine_id = "hello-world"
    version = "0.1.0"
    stage = "recon"

    # --- engine.yaml (source of truth when present) ---
    # Resolved relative to THIS file (src/<pkg>/engine.py) → ../../engine.yaml
    # at the engine repo root. Found in editable install + Docker; missing
    # in wheel install → above class defaults take over.
    engine_yaml_path = "../../engine.yaml"

    async def run(self, ctx: RunContext, config: dict):
        greeting = config.get("greeting", "hello")
        ctx.logger.info("%s from hello-world", greeting)

        # --- Progress events give the UI something to animate. ---
        await ctx.emit_event("progress", {"percentage": 0, "message": "starting"})

        # --- Do work here. Examples:
        #   result = await ctx.fetch("https://target/...")    # scope-checked HTTP
        #   result = await ctx.call_tool("nmap", {...})       # named tool
        #   result = await ctx.llm.chat(messages=[...])       # LLM (declares uses_llm=true)
        #   ref = await ctx.save_artifact("out.txt", data, kind="log")
        #   await ctx.emit_finding(FindingCandidateDraft(...)) # two-channel finding emit
        target = ctx.targets[0] if ctx.targets else None

        await ctx.emit_event("progress", {"percentage": 100, "message": "done"})

        # --- Return the canonical stage output DTO.
        # Since engine.yaml sets stage=recon, we return ReconOutput. Returning
        # a raw dict also works but loses type safety across the pipeline.
        if target is None:
            # Degenerate input — return an empty but well-formed output.
            return ReconOutput(
                target_ref=ctx.targets[0] if ctx.targets else _placeholder_target(),
                tech_fingerprint=TechFingerprint(),
                notes=f"{greeting} (no target provided)",
            )

        return ReconOutput(
            target_ref=target,
            tech_fingerprint=TechFingerprint(
                framework="unknown",
                server="unknown",
            ),
            endpoints=[Endpoint(path="/", methods=["GET"])],
            notes=f"{greeting} from hello-world; replace with your recon logic",
        )


def _placeholder_target():
    from trustchain_contracts import TargetRef

    return TargetRef(id="t_placeholder", url="https://unknown.local", target_type="web")


# FastAPI app for ``uvicorn hello_world.engine:app``.
app = HelloWorld().build_app()
