# engine-template — starter repo for an engine

A fully-working reference implementation. Fork it to start a new engine; use
it as a sanity source when you hit questions about "what should my engine
look like?"

## What's here

```
engine-template/
├── engine.yaml              # registration manifest (id / stage / capabilities / ...)
├── pyproject.toml           # depends on trustchain-sdk + trustchain-contracts
├── Dockerfile               # builds the runnable engine image
├── dev-compose.yml          # run the engine standalone (no orchestrator)
├── src/
│   ├── __init__.py
│   └── engine.py            # EngineApp subclass; run() implementation
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
uvicorn src.engine:app --host 0.0.0.0 --port 9000

# In another terminal:
curl http://localhost:9000/healthz
curl http://localhost:9000/schema | jq .
```

POSTing to `/invoke` requires a full `RunContextEnvelope` JSON body — see
[../../doc/engine-contract.md §2.2](../../doc/engine-contract.md).

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
