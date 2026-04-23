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
├── Dockerfile               # builds the runnable engine image
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
└── README.md
```

## Run the tests

```bash
python3 -m venv .venv
source .venv/bin/activate

# From the monorepo root, install contracts + sdk editable first
bash ../../scripts/dev-install.sh

# Then install this template in editable mode
pip install -e '.[dev]'

pytest -v
```

Tests run with no Docker, no orchestrator, no network — `MockContext`
stands in for the real `RunContext`.

## Run the service (no orchestrator)

```bash
pip install -e '.[dev,server]'
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
- Provide `openai_api_key=...` to `DevHarness(...)` if your engine declares `uses_llm=true`

Tool images come from
[`iSTARS-SMU/trustchain-tools`](https://github.com/iSTARS-SMU/trustchain-tools)
(GHCR public). For tools not in the default subset, uncomment the
relevant block in `docker-compose.tools.yml` or pull from there.

## Run a multi-stage pipeline locally (`dev_pipeline.py`)

`dev_run.py` only runs ONE engine. When you need to test stage chaining
— e.g., `recon → weakness_gather → report` — use the bundled
`dev_pipeline.py`. Same DevHarness under the hood, just chains each
stage's output into the next stage's `ctx.upstream_outputs`.

```bash
# 1. Bring up the tool services your pipeline needs (same as dev_run).
docker compose -f docker-compose.tools.yml up -d nmap-svc http-fetch-svc

# 2. pip install the engines that make up your pipeline.
#    Each is its own repo published in iSTARS-SMU/<name>.
pip install ./recon-targetinfo
pip install -e ./weakness-gather-exa  # editable so your edits take effect

# 3. Edit dev_pipeline.py — fill in the STAGES list with your engine
#    instances + per-stage configs.

# 4. Run.
python dev_pipeline.py
```

Outputs land in `./.dev-pipeline/` (parallel to `.dev-run/`).

### ⚠️ LLM cost warning

A real `recon → weakness_gather` pipeline against an actual target with
`gpt-4o` can easily burn **$5+ in LLM cost per run** (recon's framework
extraction step + weakness_gather's CVE extraction). To keep iteration
cheap during development:

- Set `OPENAI_API_KEY` to a key billed to a model like `gpt-4o-mini`
  (and set `llm_default_model="gpt-4o-mini"` if you want to override
  per-engine yaml defaults)
- OR use the **canned upstream** mode: load a previously-saved
  `ReconOutput` JSON into `CANNED_UPSTREAM` in `dev_pipeline.py` and
  comment out the recon stage. Iterating on weakness_gather then takes
  seconds and zero LLM cost (recon is the expensive part)
- OR leave `OPENAI_API_KEY` unset — LLM-using engines soft-fail their
  LLM step (`success=false` in events, partial output) but otherwise
  run fine. Useful for iterating on non-LLM logic

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
