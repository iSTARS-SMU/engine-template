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
├── fixtures/
│   └── juice-shop/          # curated zero-LLM-cost demo against OWASP Juice Shop
│       ├── demo_run.py                  # entrypoint
│       ├── docker-compose.tools-all.yml # bundle of all 14 tool services
│       ├── README.md
│       ├── *.json / *.txt               # 12 fixture LLM responses
│       └── tools/                       # tool-level fixtures (exa-search.json)
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

`dev_run.py` only runs ONE engine. When you need to test the full stage
chain — `recon → weakness_gather → attack_plan → exploit → report` —
use `dev_pipeline.py`. Same `DevHarness` under the hood; it threads each
stage's output into the next stage's `ctx.upstream_outputs`.

### Quickstart: full 5-stage pipeline, VSCode-first

**Prerequisites**
- Docker running (tool services run as containers)
- Python 3.11+ with `venv` available
- Outside-collaborator access on the 5 example engine repos (they're
  private; ask the admin to add you — see
  [engine-release-flow.md §3](../../doc/engine-release-flow.md))
- Your SSH key added to GitHub (the clones below use `git@`)

The commands assume a sibling-checkout layout where `engine-template/`
and the 5 example engines sit as siblings under one parent directory.
The workspace file (`engine-template.code-workspace`) expects this
exact layout.

**Step 1 — Clone all 6 repos as siblings**
```bash
mkdir -p ~/pentest-dev && cd ~/pentest-dev
git clone git@github.com:iSTARS-SMU/engine-template.git my-engine
git clone git@github.com:iSTARS-SMU/recon-targetinfo.git
git clone git@github.com:iSTARS-SMU/weakness-gather-exa.git
git clone git@github.com:iSTARS-SMU/attack-plan-llm.git
git clone git@github.com:iSTARS-SMU/exploit-autoeg.git
git clone git@github.com:iSTARS-SMU/report-docx-pro.git
ls   # should list: my-engine + 5 sibling repos
```

`my-engine/` is YOUR engine — rename when you publish. The other 5 are
upstream examples you install editable so `dev_pipeline.py` can import
them AND so you can debug into their source.

**Step 2 — Create a venv in `my-engine/` and install everything editable**
```bash
cd my-engine
python3 -m venv .venv
source .venv/bin/activate

# Platform packages (vendored; not on PyPI)
pip install -e ./vendor/contracts -e './vendor/sdk[server,openai]'

# Your engine
pip install -e '.[dev]'

# The 5 sibling engines — editable means edits in their repos take
# effect immediately with no reinstall; great for cross-engine debugging.
pip install -e ../recon-targetinfo \
            -e ../weakness-gather-exa \
            -e ../attack-plan-llm \
            -e ../exploit-autoeg \
            -e ../report-docx-pro
```

**Step 3 — Open the multi-root workspace in VSCode**

In VSCode: **File → Open Workspace from File…** (NOT *Open Folder*), pick
`~/pentest-dev/my-engine/engine-template.code-workspace`. The Explorer
should show 6 roots:

```
engine-template (this engine)   ← your code
recon-targetinfo (sibling)
weakness-gather-exa (sibling)
attack-plan-llm (sibling)
exploit-autoeg (sibling)
report-docx-pro (sibling)
```

Then pick the interpreter (`Python: Select Interpreter` in the command
palette) and point at `my-engine/.venv/bin/python`. Breakpoints, "Go to
definition", and hot-reload now work across all 6 roots.

**Step 4 — Bring up tool services**
```bash
# From my-engine/ (where docker-compose.tools.yml lives)
docker compose -f docker-compose.tools.yml up -d nmap-svc http-fetch-svc dig-svc
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "nmap|http-fetch|dig"
```

3 tools are the minimum for recon to produce real data. recon's
enhancement tools (feroxbuster / whatweb / wafw00f / nuclei) and
weakness_gather's external APIs (exa-search / nvd-search) are commented
out in `docker-compose.tools.yml` by default; uncomment + restart when
you need them. Without them, those engines soft-fail that specific call
and continue — the pipeline still runs end-to-end.

**Step 5 — Configure `.env`**
```bash
cp .env.example .env
```

Edit `.env` for a zero-cost dry run:
```
TRUSTCHAIN_RECON_LLM_MODE=mock
TRUSTCHAIN_WEAKNESS_GATHER_LLM_MODE=mock
OPENAI_API_KEY=sk-fake-walkthrough-key
```

The fake key satisfies `dev_pipeline.py`'s real-mode guard (attack_plan,
exploit, and report each declare `uses_llm=true` and don't yet have
mock-mode env toggles). The fake key triggers a 401 at OpenAI, the
engine soft-fails that LLM call and continues with degraded output —
so you still see the full pipeline shape without paying for real LLM.

For real runs, set a real `OPENAI_API_KEY` and flip the first two modes
to `real`. EXA / NVD keys are optional (soft-fail without them).

**Step 6 — Wire the 5 engines into `dev_pipeline.py`**

At the top of `dev_pipeline.py`, replace the `HelloWorld` import with:
```python
from recon_targetinfo.engine import ReconTargetinfoEngine
from weakness_gather_exa.engine import WeaknessGatherExaEngine
from attack_plan_llm.engine import AttackPlanLLMEngine
from exploit_autoeg.engine import ExploitAutoEGEngine
from report_docx_pro.engine import ReportDocxProEngine
```

Uncomment the 3 tool URLs you just brought up:
```python
TOOL_URLS: dict[str, str] = {
    "nmap":       "http://localhost:9211",
    "http_fetch": "http://localhost:9220",
    "dig":        "http://localhost:9207",
    # "nuclei":     "http://localhost:9214",
    # ...
}
```

Replace the `STAGES` list:
```python
STAGES = [
    (ReconTargetinfoEngine(),   {"nmap_mode": "basic"}),
    (WeaknessGatherExaEngine(), {"max_exa_queries": 3}),
    (AttackPlanLLMEngine(),     {"max_steps": 5}),
    (ExploitAutoEGEngine(),     {"safe_mode": True}),
    (ReportDocxProEngine(),     {"use_llm_summary": False,
                                 "report_title": "Demo Assessment"}),
]
```

Two config notes:
- `safe_mode=True` — exploit script is generated and saved as artifact,
  but the sandbox skips actual execution. Keep this on until you have a
  real target and know what you're launching at it.
- `use_llm_summary=False` — skips the executive-summary LLM call; the
  deterministic template fallback still produces a coherent summary.
  Turn on once you have a real `OPENAI_API_KEY`.

**Step 7 — Run**
```bash
python dev_pipeline.py
```

Expected output (about 30–90 seconds, mostly recon's real tool calls):

- A `--- <stage> ---` JSON block for each of the 5 stages
- `recon` returns a `ReconOutput` with a `tech_fingerprint` (mocked) and
  2 raw-output artifacts (nmap + dig stdouts)
- `weakness_gather` / `attack_plan` / `exploit` return empty lists with
  `notes` explaining the soft-fail chain (exa/nvd unavailable →
  no weaknesses → nothing to plan → nothing to exploit)
- `report` returns a `report_artifact_ref` pointing to a ~40 KB `.docx`
  with 8 sections (executive summary + recon + 4 pipeline sections +
  appendix). `notes` includes
  `report_input assembled from stage-keyed outputs (dev-harness mode)`,
  meaning the report engine bootstrapped its own input from the 4 prior
  stages' outputs (DevHarness doesn't pre-assemble like core does)

Open the `.docx` to verify rendering:
```bash
open .dev-pipeline/artifacts/<run_id>/pentest-report-*.docx
```

### Alternative: shorter 2-stage run

If you only need to test recon → weakness_gather interaction:
```python
STAGES = [
    (ReconTargetinfoEngine(),   {"nmap_mode": "basic"}),
    (WeaknessGatherExaEngine(), {"max_exa_queries": 3}),
]
```
Both stages have proper mock modes, so you don't need a fake
`OPENAI_API_KEY` — leave it blank.

### Alternative: single-stage dev with canned upstream

If you're iterating on just your own engine and don't want to re-run
recon every time:

1. Save one real `ReconOutput` to `fixtures/recon_output.json` (run the
   2-stage pipeline once with `save_intermediate=true`, then copy from
   `.dev-pipeline/artifacts/<run_id>/`).
2. In `dev_pipeline.py`:
   ```python
   CANNED_UPSTREAM = json.loads(Path("./fixtures/recon_output.json").read_text())
   STAGES = [
       (WeaknessGatherExaEngine(), {"max_exa_queries": 3}),  # recon skipped
   ]
   ```
3. `python dev_pipeline.py` runs only your stage with the canned input —
   seconds per iteration, zero LLM cost from recon.

Outputs always land in `./.dev-pipeline/` (parallel to `.dev-run/`).

## Run the curated demo (`fixtures/juice-shop/demo_run.py`)

When you want to **see the platform work end-to-end** against a real
known-vulnerable target — and you don't want to spend any LLM credits or
configure a multi-stage `dev_pipeline.py` yourself — use the bundled
juice-shop demo. It's a one-shot script that drives the full 5-stage
pipeline against [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
with **real tools** (nmap, Playwright-rendered crawl, nuclei, NVD
lookup, etc.), **mocked LLM** (12 curated responses shipped with the
template), and **real exploit execution** (a SQL injection POST to
`/rest/user/login` that actually returns a JWT for the admin user).

Total cost: $0. Total time: ~70 s.

```bash
# 1. juice-shop on :3001
docker run --rm -p 3001:3000 bkimminich/juice-shop

# 2. all 14 tool services (uses the bundle compose ≠ the parent's 3-tool default)
docker compose -f fixtures/juice-shop/docker-compose.tools-all.yml up -d

# 3. run
python fixtures/juice-shop/demo_run.py
```

Outputs land in `fixtures/juice-shop/.juice-shop-demo/` — `events.jsonl`
plus all artifacts (raw tool outputs, generated exploit script, captured
server response with the real JWT, the final `.docx` report).

### `dev_pipeline.py` vs `demo_run.py` — when to use which

|  | `dev_pipeline.py` | `demo_run.py` |
|---|---|---|
| Position | Top-level student daily driver | One-shot curated demo |
| Target | You edit `TARGET` | Hardcoded juice-shop on :3001 |
| `STAGES` | You edit | All 5 pre-wired |
| LLM | Real (or generic mock for recon/weakness) | Curated juice-shop fixtures (12 responses, $0) |
| `safe_mode` | Default `True` | `False` (real exploit against the demo target) |
| Iteration | Edit, rerun, evolve | Idempotent — same input = same output |
| Owner | The student | The platform |

Think of `demo_run.py` as a **screenshot** of what `dev_pipeline.py`
would look like if you locked in juice-shop and curated everything.

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
