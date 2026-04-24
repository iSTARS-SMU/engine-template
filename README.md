# engine-template — starter repo for an engine

A fully-working reference implementation. Fork it to start a new engine; use
it as a sanity source when you hit questions about "what should my engine
look like?"

> **Source of truth.** Mirrored to
> [`iSTARS-SMU/engine-template`](https://github.com/iSTARS-SMU/engine-template)
> for the student "Use this template" flow on GitHub. After editing here,
> sync the mirror with `bash trustchain/scripts/sync-mirrors.sh template`.
> Don't edit the org mirror directly — changes there will be overwritten on
> next sync.

## What's here

```
engine-template/
├── engine.yaml              # registration manifest (id / stage / capabilities / ...)
├── pyproject.toml           # depends on trustchain-sdk + trustchain-contracts
├── Dockerfile               # builds the runnable engine image (uses vendor/)
├── dev-compose.yml          # run the engine standalone (no orchestrator)
├── docker-compose.tools.yml # pull tool services from GHCR for local dev
├── dev_run.py               # single-engine integration via DevHarness
├── dev_pipeline.py          # multi-stage pipeline via DevHarness.run_pipeline
├── src/
│   └── hello_world/         # standard src layout: source under a named pkg
│       ├── __init__.py
│       └── engine.py        # EngineApp subclass; run() implementation
├── tests/
│   ├── __init__.py
│   └── test_engine.py       # MockContext-driven unit tests
├── vendor/                  # bundled trustchain-contracts + trustchain-sdk
│   ├── contracts/           # (so Dockerfile + pip install work without a
│   └── sdk/                 # PyPI index — 0.1-alpha not on PyPI yet)
└── README.md
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate

# Install the bundled platform packages (contracts + sdk) from vendor/
# editable, plus this engine itself. The [server] extra on sdk pulls uvicorn
# for running the engine as a service; [dev] on the engine pulls pytest.
pip install -e ./vendor/contracts -e './vendor/sdk[server]' -e '.[dev]'

# Sanity check
python -c "import trustchain_contracts, trustchain_sdk; print('OK')"

# Optional but recommended for pipeline/dev harness runs:
cp .env.example .env
```

Why vendor: `trustchain-sdk` + `trustchain-contracts` are 0.1-alpha and
not yet on PyPI. This directory ships a bundled copy rsynced from the
trustchain monorepo. When we migrate to PyPI later, you'll just
`pip install trustchain-sdk trustchain-contracts` instead and the vendor
dir gets removed — no pyproject changes needed on your side.

## Environment Variables

Some engines need secrets during local development. The common case is
OpenAI-backed engines such as `recon-targetinfo`, which declare `openai`
in `secret_requirements`.

For `dev_pipeline.py`, you can control LLM behavior per stage in `.env`:

```bash
cp .env.example .env
```

Key variables:

- `TRUSTCHAIN_RECON_LLM_MODE=mock|real`
- `TRUSTCHAIN_WEAKNESS_GATHER_LLM_MODE=mock|real`
- `OPENAI_API_KEY=...` (only needed for stages running in `real` mode)

If you prefer shell env vars, set the key before `python dev_run.py` or
`python dev_pipeline.py`:

```bash
export OPENAI_API_KEY=sk-...
```

Or inline for a single run:

```bash
OPENAI_API_KEY=sk-... python dev_pipeline.py
```

Important: behavior depends on both the engine's own `engine.yaml` and
the per-stage LLM mode.

- If the secret is declared `required: true`, the run fails with
  `SECRET_MISSING` when the env var is unset **and that stage is running
  in `real` mode**.
- If the secret is optional, the engine may continue in a degraded path
  (for example, skipping an LLM step and returning partial output).
- If a stage is in `mock` mode, `dev_pipeline.py` injects a placeholder
  secret and returns canned LLM output while still running the real
  engine code and real tool calls.

## Run the tests

```bash
pytest -v
```

Tests run with no Docker, no orchestrator, no network — `MockContext`
stands in for the real `RunContext`.

## Run the service (no orchestrator)

```bash
uvicorn hello_world.engine:app --host 0.0.0.0 --port 9000

# In another terminal:
curl http://localhost:9000/healthz
curl http://localhost:9000/schema | jq .
```

POSTing to `/invoke` requires a full `RunContextEnvelope` JSON body — see
[../../doc/engine-contract.md §2.2](../../doc/engine-contract.md).

## Run end-to-end against real tools (DevHarness)

For real integration testing — your engine, real tool services, no
orchestrator — use the bundled `dev_run.py` + `docker-compose.tools.yml`.

```bash
# 1. Pull (or build) the tool services your engine uses. Default subset
#    is nmap + http_fetch + dig — enough for most recon engines.
docker compose -f docker-compose.tools.yml up -d

# 2. Run the engine via DevHarness — fakes core's callback endpoints in
#    process so RealRunContext POSTs land on localhost. Engine code path
#    is byte-identical to lab production.
python dev_run.py
```

Outputs land in `./.dev-run/`:
- `events.jsonl` — every event your engine emitted (progress, tool_invoked, ...)
- `artifacts/<run_id>/` — every artifact your engine saved

Edit `dev_run.py` to:
- Set `TARGET` to your test target (must be in `authorized_scope`)
- Uncomment tool URLs in `TOOL_URLS` as your engine grows `ctx.call_tool()` calls
- Set `OPENAI_API_KEY` in your shell if your engine declares a required
  `openai` secret

Tool images come from
[`iSTARS-SMU/trustchain-tools`](https://github.com/iSTARS-SMU/trustchain-tools)
(GHCR public). For tools not in the default subset, uncomment the
relevant block in `docker-compose.tools.yml` or pull from there.

## Run a multi-stage pipeline locally (`dev_pipeline.py`)

`dev_run.py` only runs ONE engine. When you need to test stage chaining
— e.g., `recon → weakness_gather → attack_plan` — use the bundled
`dev_pipeline.py`. Same DevHarness under the hood, just chains each
stage's output into the next stage's `ctx.upstream_outputs`.

### Quickstart: full 3-stage `recon → weakness_gather → attack_plan`

**Prerequisites**: you must be an outside-collaborator on each engine
repo you want to clone (engine repos are private; images are public).
If you don't have access, ask the admin to add you — see
[engine-release-flow.md §3](../../doc/engine-release-flow.md) for the
permission model.

```bash
# 0. Sibling-checkout pattern. Assumes this engine-template lives at
#    ~/pentest-dev/engine-template/. Everything else sits next to it.
cd ~/pentest-dev

# 1. Clone the three published engines (private repos, need org access).
git clone git@github.com:iSTARS-SMU/recon-targetinfo.git
git clone git@github.com:iSTARS-SMU/weakness-gather-exa.git
git clone git@github.com:iSTARS-SMU/attack-plan-llm.git

# 2. Install them editable into the template's venv (so you can edit
#    code in any of them and see changes without reinstalling).
cd engine-template
source .venv/bin/activate       # venv from the Setup section above
pip install -e ../recon-targetinfo \
            -e ../weakness-gather-exa \
            -e ../attack-plan-llm

# 3. Bring up tool services. The 3-stage pipeline needs 5 tools:
#      recon-targetinfo uses: nmap + http_fetch + dig (+ soft-fails on
#                             nuclei/feroxbuster/whatweb/wafw00f — skip those)
#      weakness-gather-exa uses: exa-search + nvd-search
#    Uncomment `exa-search-svc` + `nvd-search-svc` blocks in
#    docker-compose.tools.yml first, then:
docker compose -f docker-compose.tools.yml up -d \
    nmap-svc http-fetch-svc dig-svc exa-search-svc nvd-search-svc

# 4. Set env. Copy template + fill in as needed.
cp .env.example .env
# Edit .env to set:
#   TRUSTCHAIN_RECON_LLM_MODE=mock           (dev), or =real (with gpt-4o-mini)
#   TRUSTCHAIN_WEAKNESS_GATHER_LLM_MODE=mock (dev), or =real
#   OPENAI_API_KEY=sk-...                    (needed ONLY if any stage is real mode,
#                                            OR if you add attack-plan-llm which has
#                                            no mock path today — treat openai as required)
#   EXA_API_KEY=...                          (optional; without it, exa soft-fails)
#   NVD_API_KEY=...                          (optional; without it, 10× tighter NVD rate limit)

# 5. Edit dev_pipeline.py — replace the default HelloWorld stage with:
#      from recon_targetinfo.engine import ReconTargetInfo
#      from weakness_gather_exa.engine import WeaknessGatherExa
#      from attack_plan_llm.engine import AttackPlanLLMEngine
#
#      STAGES = [
#          (ReconTargetInfo(),        {"nmap_mode": "basic"}),
#          (WeaknessGatherExa(),      {"max_exa_queries": 3}),
#          (AttackPlanLLMEngine(),    {"max_steps": 5}),
#      ]
#
#    Also uncomment the 5 TOOL_URLS entries matching what you started
#    in step 3 so the engines can actually reach their tools.

# 6. Run.
python dev_pipeline.py
```

**Tip (VSCode users)**: open `engine-template.code-workspace` (File →
*Open Workspace from File...*, NOT *Open Folder*) instead of just
opening the engine-template directory. The workspace file ships with
the template and loads engine-template + the 3 sibling repos in one
window, so breakpoints and "Go to definition" work across all of
them. Sibling folders show as greyed-out "missing" until you clone
them in step 1; refresh after cloning.

Expected output:
- `pipeline run_id: r_...`
- `succeeded: True`
- `events: ~20-30` → `./.dev-pipeline/events.jsonl`
- `artifacts: 4-6` → `./.dev-pipeline/artifacts/<run_id>/`
- Per-stage outputs printed as JSON — the last one is an `AttackPlan`
  with `steps: [...]` each describing one exploit objective

### Alternative: shorter 2-stage pipeline

If `attack-plan-llm` is overkill for what you're testing:

```python
STAGES = [
    (ReconTargetInfo(),   {"nmap_mode": "basic"}),
    (WeaknessGatherExa(), {"max_exa_queries": 3}),
]
```

### Alternative: single-stage dev with canned upstream

If you're iterating on, say, `weakness-gather-exa` and don't want to
burn 30 seconds on recon + all its tool calls every run:

1. Save one real `ReconOutput` to `fixtures/recon_output.json` (run the
   2-stage once with save_intermediate=true, then copy from
   `.dev-pipeline/artifacts/<run_id>/`).
2. In `dev_pipeline.py`:
   ```python
   CANNED_UPSTREAM = json.loads(Path("./fixtures/recon_output.json").read_text())
   STAGES = [
       (WeaknessGatherExa(), {"max_exa_queries": 3}),  # recon stage skipped
   ]
   ```
3. `python dev_pipeline.py` runs weakness-gather-exa with the canned
   recon output pre-loaded. Seconds per iteration instead of minutes.

Outputs always land in `./.dev-pipeline/` (parallel to `.dev-run/`).

### ⚠️ LLM cost warning

A real `recon → weakness_gather` pipeline against an actual target with
`gpt-4o` can easily burn **$5+ in LLM cost per run** (recon's framework
extraction step + weakness_gather's CVE extraction). To keep iteration
cheap during development:

- Set `TRUSTCHAIN_RECON_LLM_MODE=mock` and/or
  `TRUSTCHAIN_WEAKNESS_GATHER_LLM_MODE=mock` in `.env` to keep tools real
  while stubbing the LLM outputs. This is the easiest way to test stage
  chaining without incurring OpenAI cost.
- If you want a real provider call, set the stage mode to `real` and set
  `OPENAI_API_KEY` to a key billed to a model like `gpt-4o-mini`
- OR use the **canned upstream** mode: load a previously-saved
  `ReconOutput` JSON into `CANNED_UPSTREAM` in `dev_pipeline.py` and
  comment out the recon stage. Iterating on weakness_gather then takes
  seconds and zero LLM cost (recon is the expensive part)
- OR leave `OPENAI_API_KEY` unset only when every LLM-using stage is in
  `mock` mode (or the engine's secret is optional)

Reference: [`doc/codex-review-phase-1.6-lite.md`](../../doc/codex-review-phase-1.6-lite.md)
for the full Phase 1.5e design doc.

## Or scaffold your own from this template via the CLI

```bash
trustchain-sdk new engine --name my-new-engine --stage recon --dest .
```

The CLI emits the same files this directory ships.

## Next steps in your fork

1. Rename `engine_id` / `version` / `stage` everywhere — [engine.yaml](./engine.yaml) + [src/engine.py](./src/engine.py)
2. Declare `required_tools` / `optional_tools` / `secret_requirements` — see [doc/spec.md §4.1](../../doc/spec.md)
3. Replace `run()` body with your actual logic
4. Add tests covering normal path + at least 2 error paths + 1 idempotency check
5. Push image to the shared registry
6. Open a PR against `trustchain-core` adding a single YAML under [trustchain/engine-registry/<stage>/](../engine-registry/)

Core team reviews the registry YAML + contract-test CI output. They don't
read your source.
