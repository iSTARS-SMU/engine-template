# Fixture: OWASP Juice Shop demo

Curated LLM responses for running the full TrustChain pipeline against
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) at
`http://localhost:3001` with **zero LLM cost**. Real tools (nmap, dig,
whatweb, wafw00f, nuclei, webstructure with Playwright, gau, waybackurls,
linkfinder, whois, exa-search, nvd-search) still run for real, real
network traffic to juice-shop, real exploit execution. Only the LLM
"intelligence" layer is mocked from these files.

Used by `trustchain/engine-template/dev_pipeline.py` when env var
`TRUSTCHAIN_FIXTURE_DIR` points here. The wiring lives in
`trustchain_sdk.testing.fixture_llm`.

## Why a fixture exists

LLM calls are the only non-deterministic + non-free piece of the
pipeline. For:

- **Smoke tests** before a release — proves the platform glues correctly
  without touching OpenAI billing.
- **Onboarding demo** — new lab users see a working end-to-end run
  immediately, not after they figure out an API key.
- **Reproducibility** — same input target → identical pipeline output
  every time, useful for screenshots / paper figures / video demos.

## Demo scenario (deliberately narrow)

We curate responses that drive the pipeline toward **one** confirmed
finding — a SQL-injection authentication bypass on
`/rest/user/login`. Other weaknesses surface in `weakness_gather` but
get filtered out in `attack_plan` so `exploit` only generates one
script. Keeps the curated content scope tight while still demonstrating:

- recon discovers the real endpoint surface (~120 endpoints)
- weakness_gather identifies multiple realistic juice-shop weaknesses
- attack_plan filters to the highest-value target
- exploit-autoeg generates a working SQLi payload + executes it +
  obtains a JWT (real impact against juice-shop)
- report writes an executive summary referencing the real impact

## Fixture file layout

```
juice-shop/
├── README.md                              ← you're here
├── recon_tech_fingerprint.json            ← LLM purpose=recon_tech_fingerprint
├── weakness_gather_search_plan.json       ← LLM purpose=weakness_gather_search_plan
├── weakness_gather_extract.json           ← LLM purpose=weakness_gather_extract
├── attack_plan_filter.json                ← LLM purpose=attack_plan_filter
├── attack_plan_decide.json                ← LLM purpose=attack_plan_decide
├── autoeg_ptf_generation.txt              ← LLM purpose=autoeg_ptf_generation
├── autoeg_testcase_generation.txt         ← LLM purpose=autoeg_testcase_generation
├── autoeg_exploit_generation.txt          ← LLM purpose=autoeg_exploit_generation
├── autoeg_exploit_verdict.txt             ← LLM purpose=autoeg_exploit_verdict
├── autoeg_ptf_refinement.txt              ← LLM purpose=autoeg_ptf_refinement (rare path)
├── autoeg_exploit_refinement.txt          ← LLM purpose=autoeg_exploit_refinement (rare path)
└── report_exec_summary.txt                ← LLM purpose=report_exec_summary
```

The chat interceptor maps `purpose` → file. JSON files are returned as
the `LLMResult.content` string verbatim (engines parse it themselves).
`.txt` files are returned as plain text content (Python source for
exploits, free text for summary/verdict).

## How to run

```bash
# 1. juice-shop running locally
docker run --rm -p 3001:3000 bkimminich/juice-shop

# 2. all 14 trustchain tools running locally (default 3 + uncomment the
#    others in docker-compose.tools.yml)
docker compose -f trustchain/engine-template/docker-compose.tools.yml up -d

# 3. point dev_pipeline at the fixture, set safe_mode=false in STAGES
export TRUSTCHAIN_FIXTURE_DIR=$(pwd)/trustchain/fixtures/juice-shop
cd trustchain/engine-template
python dev_pipeline.py
```

Expected output: pipeline runs ~5 minutes (recon = 30-90s with real
nmap/whatweb/etc., webstructure Playwright = 30-60s for juice-shop's
~40 SPA routes), one exploit script materializes, sandbox runs it
against `http://localhost:3001/rest/user/login`, the response carries
a JWT (real auth bypass), report engine writes a 8-section .docx
summarizing the finding.

## Updating the fixture

If juice-shop's API surface or curated weaknesses change, edit the
relevant `.json` / `.txt` file. Files are interpreted as the LLM's
chat() reply verbatim — match the shape the engine downstream expects.
For DTO-style responses (recon/weakness/attack_plan), look at the
engine's parser to confirm the JSON shape.
