"""
trustchain-sdk CLI — scaffold + helpers for engine authors.

Commands:
    trustchain-sdk new engine --stage <stage> --name <name> [--dest <dir>]
        Scaffold a fresh engine repo from the engine-template.

    trustchain-sdk validate <path>
        Sanity-check an engine.yaml (parse + schema).

    trustchain-sdk version
        Print SDK + contracts versions.
"""

from __future__ import annotations

import importlib.resources as resources
import shutil
import sys
from pathlib import Path

import typer

from . import __version__ as sdk_version

app = typer.Typer(
    name="trustchain-sdk",
    help="TrustChain Pentest engine SDK tools.",
    add_completion=False,
    no_args_is_help=True,
)
new_app = typer.Typer(help="Create new artifacts from templates.", no_args_is_help=True)
app.add_typer(new_app, name="new")


# --- new engine ------------------------------------------------------------


@new_app.command("engine")
def new_engine(
    name: str = typer.Option(..., "--name", help="Engine id, e.g. 'my-recon'."),
    stage: str = typer.Option(..., "--stage", help="Pipeline stage (recon | weakness_gather | attack_plan | exploit | report)."),
    dest: Path = typer.Option(Path.cwd(), "--dest", help="Where to create the engine dir."),
) -> None:
    """Scaffold a new engine from the bundled engine-template.

    Creates ``dest/<name>/`` with standard Python src layout — source under
    ``src/<name_underscored>/`` so ``pip install`` registers a uniquely-named
    top-level package (avoids the collision two engines hit if both shipped
    a package literally called ``src``).

        * engine.yaml                       (pre-filled metadata)
        * pyproject.toml                    (depends on trustchain-sdk + contracts)
        * Dockerfile                        (python:3.11-slim base)
        * src/<pkg>/engine.py               (EngineApp skeleton)
        * tests/test_engine.py              (MockContext example)
        * README.md                         (what to edit next)
    """

    stage = stage.strip()
    _allowed_stages = {"recon", "weakness_gather", "attack_plan", "exploit", "report"}
    if stage not in _allowed_stages:
        typer.echo(
            f"error: --stage must be one of {sorted(_allowed_stages)}; got {stage!r}",
            err=True,
        )
        raise typer.Exit(code=2)

    dest_root = (dest / name).resolve()
    if dest_root.exists():
        typer.echo(f"error: {dest_root} already exists", err=True)
        raise typer.Exit(code=2)

    # Engine name (e.g. "my-recon") → Python-safe top-level package name
    # ("my_recon"). pip-installable; never collides with another engine.
    pkg = name.replace("-", "_")

    dest_root.mkdir(parents=True)
    (dest_root / "src" / pkg).mkdir(parents=True)
    (dest_root / "tests").mkdir()

    files = {
        "engine.yaml": _tpl_engine_yaml(name, stage),
        "pyproject.toml": _tpl_pyproject(name),
        "Dockerfile": _tpl_dockerfile(name),
        "dev-compose.yml": _tpl_dev_compose(name),
        "README.md": _tpl_readme(name, stage),
        ".gitignore": _tpl_gitignore(),
        f"src/{pkg}/__init__.py": "",
        f"src/{pkg}/engine.py": _tpl_engine_py(name, stage),
        "tests/__init__.py": "",
        "tests/test_engine.py": _tpl_test_py(name),
    }
    for rel, content in files.items():
        (dest_root / rel).write_text(content)

    typer.echo(f"created engine skeleton at {dest_root}")
    typer.echo("next steps:")
    typer.echo(f"  cd {dest_root}")
    typer.echo("  pip install -e .[dev]")
    typer.echo("  pytest")


# --- validate --------------------------------------------------------------


@app.command("validate")
def validate(path: Path) -> None:
    """Parse and validate an engine.yaml against EngineYamlSpec."""
    import yaml

    from trustchain_contracts import EngineYamlSpec

    try:
        data = yaml.safe_load(path.read_text())
    except FileNotFoundError:
        typer.echo(f"error: {path} not found", err=True)
        raise typer.Exit(code=2) from None

    try:
        spec = EngineYamlSpec.model_validate(data)
    except Exception as exc:
        typer.echo(f"validation failed:\n{exc}", err=True)
        raise typer.Exit(code=1) from None

    typer.echo(f"OK: {spec.id}@{spec.version} (stage={spec.stage})")


# --- version ---------------------------------------------------------------


@app.command("version")
def version() -> None:
    """Print SDK and contracts versions."""
    try:
        import trustchain_contracts

        contracts_version = getattr(trustchain_contracts, "__version__", "unknown")
    except ImportError:
        contracts_version = "not installed"
    typer.echo(f"trustchain-sdk:      {sdk_version}")
    typer.echo(f"trustchain-contracts: {contracts_version}")


# ---------- template strings (kept inline; small enough) ----------


def _tpl_engine_yaml(name: str, stage: str) -> str:
    return f"""id: {name}
version: 0.1.0
stage: {stage}
entry: http://{name}-svc:9000

# Set destructive=true if this engine may cause irreversible changes
# to the target. exploit / report most often have this false; destructive
# exploit engines (e.g. write-level SQLi) set true and force safe_mode in config.
capabilities:
  destructive: false
  network_egress: true
  uses_llm: false
  writes_artifacts: true
risk_level: low
timeout_default: 300
resource_profile:
  memory_mb: 256
  cpu: 0.25

required_tools: []
optional_tools: []
secret_requirements: []
artifact_types: []

input_schema: {{}}
output_schema: {{}}
config_schema:
  type: object
  properties:
    greeting:
      type: string
      default: "hello"
"""


def _tpl_pyproject(name: str) -> str:
    module = name.replace("-", "_")
    return f"""[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "{name}"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "trustchain-sdk>=0.1,<0.2",
    "trustchain-contracts>=0.1,<0.2",
]

[project.optional-dependencies]
dev = ["pytest>=7.4", "pytest-asyncio>=0.23"]
server = ["trustchain-sdk[server]>=0.1,<0.2"]

[tool.hatch.build.targets.wheel]
packages = ["src/{module}"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
"""


def _tpl_dockerfile(name: str) -> str:
    module = name.replace("-", "_")
    return f"""FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY engine.yaml ./

RUN pip install --no-cache-dir -e '.[server]'

EXPOSE 9000
CMD ["uvicorn", "{module}.engine:app", "--host", "0.0.0.0", "--port", "9000"]
"""


def _tpl_dev_compose(name: str) -> str:
    return f"""# Local one-engine dev loop — no core, no orchestrator, no other engines.
# Use this to manually curl /invoke with a hand-crafted envelope while you
# iterate. For real integration testing, run the full trustchain stack via
# the core repo's compose.sh.
#
#   docker compose -f dev-compose.yml up --build
#   curl -X POST localhost:9000/schema
#   curl -X POST localhost:9000/healthz
services:
  {name}:
    build: .
    ports:
      - "9000:9000"
    environment:
      # Uncomment + set if ENGINE_SHARED_SECRET is configured on core:
      # ENGINE_SHARED_SECRET: dev-secret
      PYTHONUNBUFFERED: "1"
"""


def _tpl_readme(name: str, stage: str) -> str:
    module = name.replace("-", "_")
    return f"""# {name}

A TrustChain Pentest engine for the `{stage}` stage.

## Develop

```bash
pip install -e '.[dev]'
pytest
```

## Run locally

```bash
pip install -e '.[dev,server]'
uvicorn {module}.engine:app --port 9000
```

## Deliverables

See the core project's `doc/engine-author-guide.md` §6 — three things to
submit:

1. Source + `engine.yaml` (this repo)
2. Unit tests (in `tests/`)
3. Docker image pushed to the team registry
"""


def _tpl_gitignore() -> str:
    return """__pycache__/
*.egg-info/
.venv/
.pytest_cache/
.mypy_cache/
.ruff_cache/
*.pyc
.env
"""


def _tpl_engine_py(name: str, stage: str) -> str:
    class_name = "".join(p.capitalize() for p in name.replace("_", "-").split("-"))
    return f'''"""Engine implementation for {name}."""

from trustchain_sdk import EngineApp, RunContext


class {class_name}(EngineApp):
    # Class-level defaults mirror engine.yaml — used as fallback when yaml
    # isn't on disk (e.g. wheel install without the repo-root yaml). Keep
    # in sync with engine.yaml; SDK warns on drift.
    engine_id = "{name}"
    version = "0.1.0"
    stage = "{stage}"

    # engine.yaml is the single source of truth when present. Path is relative
    # to THIS file: src/<pkg>/engine.py → ../../engine.yaml at the engine root.
    engine_yaml_path = "../../engine.yaml"

    async def run(self, ctx: RunContext, config: dict):
        greeting = config.get("greeting", "hello")
        ctx.logger.info("%s from {name}", greeting)
        await ctx.emit_event("progress", {{"percentage": 0, "message": "start"}})

        # TODO: your engine logic here. Use ctx.fetch() / ctx.call_tool() /
        # ctx.llm.chat() / ctx.save_artifact() / ctx.emit_finding() as needed.

        await ctx.emit_event("progress", {{"percentage": 100, "message": "done"}})

        # Return is EngineResult.output. Prefer a contracts DTO (ReconOutput,
        # Weakness list, ...) for the stage you implement — easier downstream
        # and gets auto-validated against output_schema.
        return {{"greeting": greeting, "target_count": len(ctx.targets)}}


app = {class_name}().build_app()
'''


def _tpl_test_py(name: str) -> str:
    class_name = "".join(p.capitalize() for p in name.replace("_", "-").split("-"))
    module = name.replace("-", "_")
    return f'''"""Unit tests for {name}. Runs with MockContext — no docker, no network."""

import pytest

from trustchain_contracts import TargetRef
from trustchain_sdk.testing import MockContext

from {module}.engine import {class_name}


@pytest.mark.asyncio
async def test_happy_path():
    ctx = MockContext(
        targets=[TargetRef(id="t1", url="https://example.com", authorized_scope=["example.com"])],
    )

    engine = {class_name}()
    result = await engine.run(ctx, config={{"greeting": "hi"}})

    assert result["greeting"] == "hi"
    assert any(e["kind"] == "progress" for e in ctx.captured_events())


@pytest.mark.asyncio
async def test_idempotent():
    """Spec §7.5.4: same (run_id, stage, config, upstream_outputs) must give
    semantically-equal outputs on two calls."""
    ctx_a = MockContext(targets=[TargetRef(id="t1", url="https://x", authorized_scope=["x"])])
    ctx_b = MockContext(targets=[TargetRef(id="t1", url="https://x", authorized_scope=["x"])])
    out_a = await {class_name}().run(ctx_a, config={{"greeting": "hello"}})
    out_b = await {class_name}().run(ctx_b, config={{"greeting": "hello"}})
    assert out_a == out_b
'''


def main() -> None:
    """Entry point for `trustchain-sdk` script."""
    try:
        app()
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()


_ = resources, shutil  # keep imports alive for future use
