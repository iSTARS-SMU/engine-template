# Dockerfile for engine-template / hello-world.
#
# Build context MUST be the monorepo root — this Dockerfile copies trustchain-
# contracts and trustchain-sdk from the same repo so the container doesn't
# depend on those packages being on pip index (0.1-alpha hasn't published yet).
#
# From docker-compose.dev.yml this is wired as:
#   build:
#     context: .
#     dockerfile: trustchain/engine-template/Dockerfile
#
# To build manually from the monorepo root:
#   docker build -t trustchain/hello-world -f trustchain/engine-template/Dockerfile .

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# --- Install platform packages from monorepo sources ---
COPY trustchain/contracts /opt/contracts
COPY trustchain/sdk/python /opt/sdk
# Install trustchain-sdk with [server] extra so uvicorn is present for the
# CMD below. Engines only need sdk[server] + contracts on top of python stdlib.
RUN pip install --no-cache-dir /opt/contracts "/opt/sdk[server]"

# --- Engine package ---
COPY trustchain/engine-template/pyproject.toml ./
COPY trustchain/engine-template/engine.yaml ./
COPY trustchain/engine-template/src ./src
# No --no-deps: pip resolves the engine's pypi deps (pytest-asyncio etc stay
# in the dev extra; base deps are just trustchain-sdk+contracts already present).
RUN pip install --no-cache-dir -e .

EXPOSE 9000
CMD ["uvicorn", "src.engine:app", "--host", "0.0.0.0", "--port", "9000"]
