# Standalone Dockerfile for the engine-template / hello-world engine.
#
# Build context = this directory (the engine root). No monorepo access needed —
# trustchain-contracts + trustchain-sdk are shipped bundled under vendor/,
# kept in sync with the monorepo source by scripts/sync-template-vendor.sh.
#
# Build:
#   docker build -t hello-world .
#
# Or via docker compose:
#   docker compose -f dev-compose.yml up --build
#
# When SDK / contracts contract updates, re-run the monorepo's
# scripts/sync-template-vendor.sh + commit vendor/ diff + rebuild.
# Until then this image pins whatever was in vendor/ at last sync.

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# --- Install bundled trustchain platform packages ---
COPY vendor/contracts /opt/contracts
COPY vendor/sdk /opt/sdk
# [server] extra includes uvicorn for the CMD below.
RUN pip install --no-cache-dir /opt/contracts "/opt/sdk[server]"

# --- Engine package ---
COPY pyproject.toml ./
COPY engine.yaml ./
COPY src ./src
# pip resolves trustchain-sdk + trustchain-contracts from already-installed
# versions above; no network / index required.
RUN pip install --no-cache-dir -e .

EXPOSE 9000
CMD ["uvicorn", "hello_world.engine:app", "--host", "0.0.0.0", "--port", "9000"]
