"""
EngineApp — the base class student engines subclass.

Typical flow:
    from trustchain_sdk import EngineApp, RunContext
    from trustchain_contracts import Capabilities, SecretRequirement, Severity

    class MyRecon(EngineApp):
        engine_id = "my-recon"
        version = "0.1.0"
        stage = "recon"
        capabilities = Capabilities(uses_llm=True, destructive=False)
        secret_requirements = [SecretRequirement(name="openai", required=True)]

        async def run(self, ctx: RunContext, config: dict):
            await ctx.emit_event("progress", {"percentage": 50})
            return {"target_url": ctx.targets[0].url, "framework": "flask"}

    app = MyRecon().build_app()   # FastAPI instance

SDK auto-exposes:
    POST /invoke    → EngineApp.invoke (wraps run() with envelope/result plumbing)
    GET  /schema    → engine.yaml-derived schema summary
    GET  /healthz   → liveness probe

See doc/engine-contract.md for HTTP semantics.
"""

from __future__ import annotations

import logging
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any, ClassVar

import httpx
from pydantic import BaseModel

from trustchain_contracts import (
    ArtifactKind,
    Capabilities,
    EngineResult,
    EngineStatus,
    EngineYamlSpec,
    ErrorCode,
    ResourceProfile,
    RiskLevel,
    RunContextEnvelope,
    SecretRequirement,
)

from ._errors import (
    TrustchainSDKError,
)
from .context import RunContext

logger = logging.getLogger(__name__)


class EngineApp:
    """Base class. Subclass and implement `run()`.

    Declarative metadata (identity, capabilities, schemas, ...) is loaded from
    an accompanying `engine.yaml` — the same file the registry reads. The class
    only needs to point at the yaml via ``engine_yaml_path`` and implement the
    ``run()`` method. This keeps the yaml as the single source of truth and
    prevents drift between /schema and registry (see spec §6.3).

    Class-level defaults are still supported for engines without a yaml (unit
    tests, ad-hoc scripts). When yaml is loaded, its values win.
    """

    # --- Path to engine.yaml (relative to the module file, or absolute).
    # When set, __init__ loads the yaml and hydrates every declarative field
    # from it. This is the recommended pattern.
    engine_yaml_path: ClassVar[str | None] = None

    # --- Identity (class-level defaults; overridden by yaml when loaded) ---
    engine_id: ClassVar[str] = ""
    version: ClassVar[str] = "0.0.0"
    stage: ClassVar[str] = ""

    # --- Capability declarations (defaults; yaml wins) ---
    capabilities: ClassVar[Capabilities] = Capabilities()
    secret_requirements: ClassVar[list[SecretRequirement]] = []
    artifact_types: ClassVar[list[ArtifactKind]] = []

    # --- Schemas (defaults; yaml wins) ---
    config_schema: ClassVar[dict[str, Any]] = {}
    input_schema: ClassVar[dict[str, Any]] = {}
    output_schema: ClassVar[dict[str, Any]] = {}

    def __init__(self) -> None:
        """Hydrate declarative fields from engine.yaml (if path is set).

        The loaded fields are set as instance attributes so they shadow the
        class-level defaults for every access (runtime + /schema endpoint).
        If a class-level default disagrees with the yaml, the yaml wins and
        we log a warning — this usually indicates an out-of-sync copy that a
        developer should reconcile.
        """
        spec = self._load_yaml_spec()
        if spec is None:
            return

        # Check for silent drift: warn ONLY when the subclass explicitly set
        # an attribute to something different from yaml. Inherited base-class
        # defaults ("", "0.0.0", etc.) shouldn't trigger a warning.
        subclass_attrs = type(self).__dict__
        for field, yaml_val in [
            ("engine_id", spec.id),
            ("version", spec.version),
            ("stage", spec.stage),
        ]:
            if field in subclass_attrs and subclass_attrs[field] != yaml_val:
                logger.warning(
                    "engine %s: class-level %s=%r disagrees with yaml %r; yaml wins",
                    spec.id,
                    field,
                    subclass_attrs[field],
                    yaml_val,
                )

        self.engine_id = spec.id
        self.version = spec.version
        self.stage = spec.stage
        self.capabilities = spec.capabilities
        self.risk_level = spec.risk_level
        self.timeout_default = spec.timeout_default
        self.resource_profile = spec.resource_profile
        self.required_tools = list(spec.required_tools)
        self.optional_tools = list(spec.optional_tools)
        self.secret_requirements = list(spec.secret_requirements)
        self.artifact_types = list(spec.artifact_types)
        self.config_schema = dict(spec.config_schema)
        self.input_schema = dict(spec.input_schema)
        self.output_schema = dict(spec.output_schema)

    def _load_yaml_spec(self) -> EngineYamlSpec | None:
        """Resolve engine_yaml_path relative to the subclass module, load,
        return EngineYamlSpec. Returns None if no path declared."""
        if not self.engine_yaml_path:
            return None

        path = Path(self.engine_yaml_path)
        if not path.is_absolute():
            module = sys.modules.get(type(self).__module__)
            module_file = getattr(module, "__file__", None) if module else None
            if module_file:
                path = (Path(module_file).resolve().parent / path).resolve()

        if not path.exists():
            logger.warning(
                "engine_yaml_path=%r does not exist (resolved to %s); "
                "falling back to class-level defaults",
                self.engine_yaml_path,
                path,
            )
            return None

        import yaml  # lazy import to keep SDK import cheap

        data = yaml.safe_load(path.read_text())
        return EngineYamlSpec.model_validate(data)

    # --- Engine run implementation (subclass must override) ---

    async def run(self, ctx: RunContext, config: dict[str, Any]) -> Any:
        """Main engine entrypoint. Return value:
          * Pydantic BaseModel — SDK calls .model_dump() for EngineResult.output
          * dict / None         — used as EngineResult.output directly
          * str / int / etc     — coerced into {"value": ...} to satisfy wire dict shape

        Emit events / findings / artifacts via ``ctx.*`` during execution.
        """
        raise NotImplementedError(
            f"engine {self.engine_id} must override EngineApp.run()"
        )

    # --- FastAPI app factory ---

    def build_app(self):  # type: ignore[no-untyped-def]
        """Construct a FastAPI app with /invoke, /schema, /healthz bound.

        Lazy FastAPI import so `import trustchain_sdk` stays fast for test-only
        workflows that never need the server.
        """
        from fastapi import Depends, FastAPI, Header, HTTPException
        from fastapi.responses import JSONResponse

        app = FastAPI(title=f"engine/{self.engine_id}@{self.version}")

        shared_secret = os.environ.get("ENGINE_SHARED_SECRET", "")
        require_auth = bool(shared_secret)

        def _check_auth(authorization: str = Header(default="")) -> None:
            if not require_auth:
                return
            if authorization != f"Bearer {shared_secret}":
                raise HTTPException(status_code=403, detail="AUTHZ_FAILED")

        @app.post("/invoke", dependencies=[Depends(_check_auth)])
        async def invoke_endpoint(envelope: RunContextEnvelope):
            result = await self.invoke(envelope)
            if result.status != EngineStatus.FAILED:
                http_status = 200
            else:
                http_status = _http_status_for_error(result.error_code)
            return JSONResponse(
                content=result.model_dump(mode="json"),
                status_code=http_status,
            )

        @app.get("/schema")
        async def schema_endpoint():
            return self._schema_snapshot().model_dump(mode="json")

        @app.get("/healthz")
        async def healthz_endpoint():
            return {"status": "healthy"}

        return app

    # --- Core /invoke plumbing ---

    async def invoke(
        self,
        envelope: RunContextEnvelope,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> EngineResult:
        """Process one /invoke. Used by the FastAPI route AND by direct callers
        (e.g. contract tests).

        All failure paths — including RunContext construction failures
        (LLMConfigMissing, SecretMissing for required secrets) — return a
        structured EngineResult(status=failed, error_code=...) so orchestrator
        can act on the code. Raw exceptions should never leak from this method.

        ``http_client`` is injectable for tests:
            transport = httpx.MockTransport(handler)
            client = httpx.AsyncClient(transport=transport)
            result = await engine.invoke(envelope, http_client=client)
        Production code leaves this None; RunContext owns/closes its own client.
        """
        # Sanity: envelope's stage / engine_id should match class declaration.
        # Keep soft-check for now (registry does the firm check).
        if envelope.engine_id and self.engine_id:
            exp = f"{self.engine_id}@{self.version}"
            if envelope.engine_id not in (self.engine_id, exp):
                logger.warning(
                    "envelope.engine_id=%r does not match class (%s); continuing",
                    envelope.engine_id,
                    exp,
                )

        ctx: RunContext | None = None
        start = time.monotonic()

        try:
            # NOTE: RunContext construction itself can raise LLMConfigMissing
            # / SecretMissing / (future) ContextInvalid. Those paths MUST go
            # through the same structured-failure return below, not escape
            # this method. Hence the construction is inside the try block.
            ctx = RunContext(
                envelope,
                engine_id=self.engine_id,
                capabilities=self.capabilities,
                secret_requirements=self.secret_requirements,
                http_client=http_client,
            )

            raw_output = await self.run(ctx, envelope.config)

            output_dict = _coerce_output(raw_output)
            finding_candidates = ctx._drain_findings()
            artifacts = ctx._drain_artifacts()
            metrics = ctx._current_metrics()
            metrics.duration_ms = int((time.monotonic() - start) * 1000)

            return EngineResult(
                status=EngineStatus.SUCCESS,
                stage_attempt_id=envelope.stage_attempt_id,
                output=output_dict,
                finding_candidates=finding_candidates,
                artifact_refs=artifacts,
                metrics=metrics,
            )
        except TrustchainSDKError as exc:
            # Includes LLMConfigMissing, SecretMissing, ScopeViolation,
            # CallbackAuthzFailed, StageSuperseded, ToolUnavailable, etc.
            # Each carries the right ErrorCode.
            return _failed_result(
                envelope.stage_attempt_id,
                exc.error_code,
                str(exc),
                retryable=(exc.error_code in _RETRYABLE),
                partial_artifacts=ctx._drain_artifacts() if ctx is not None else [],
            )
        except Exception as exc:
            # Unhandled — log trace but don't leak it into the wire response.
            logger.error(
                "engine.run() unhandled exception: %s\n%s",
                exc,
                traceback.format_exc(),
            )
            return _failed_result(
                envelope.stage_attempt_id,
                ErrorCode.INTERNAL_ERROR,
                f"unhandled: {exc}",
                retryable=True,
                partial_artifacts=ctx._drain_artifacts() if ctx is not None else [],
            )
        finally:
            if ctx is not None:
                await ctx.close()

    # --- Schema endpoint payload ---

    def _schema_snapshot(self) -> _SchemaSnapshot:
        """Build the GET /schema response. Registry compares this against the
        engine.yaml on record; anything that drifts marks the engine as
        `mismatch` and removes it from scheduling.

        Must include every field the registry compares (see
        ``core/registry._compare_schema``). Missing a field here means the
        registry can't detect drift on it — historically risk_level /
        timeout_default / resource_profile / required_tools / optional_tools
        were silently invisible to mismatch detection (Codex P0-1).
        """
        return _SchemaSnapshot(
            engine_id=self.engine_id,
            version=self.version,
            stage=self.stage,
            config_schema=self.config_schema,
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            capabilities=self.capabilities,
            risk_level=self.risk_level,
            timeout_default=self.timeout_default,
            resource_profile=self.resource_profile,
            required_tools=list(self.required_tools),
            optional_tools=list(self.optional_tools),
            secret_requirements=list(self.secret_requirements),
            artifact_types=list(self.artifact_types),
            sdk_version=_sdk_version(),
            contracts_version=_contracts_version(),
        )

    # --- Load from engine.yaml (for dev convenience) ---

    @classmethod
    def from_yaml(cls, path: str) -> EngineYamlSpec:
        """Parse a yaml file into EngineYamlSpec. Doesn't mutate the class;
        just returns the parsed spec for tests / the registry's view."""
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f)
        return EngineYamlSpec.model_validate(data)


# -------------- helpers --------------


_RETRYABLE = {
    ErrorCode.TARGET_UNREACHABLE,
    ErrorCode.TOOL_UNAVAILABLE,
    ErrorCode.LLM_UNAVAILABLE,
    ErrorCode.DEADLINE_EXCEEDED,
    ErrorCode.INTERNAL_ERROR,
}


# Error code → HTTP status. Mirrors engine-contract.md §2.4.
# Used by the /invoke endpoint to return the right HTTP status for each failure.
_ERROR_HTTP_STATUS: dict[ErrorCode, int] = {
    # 400 — caller fault
    ErrorCode.CONFIG_INVALID: 400,
    ErrorCode.CONTEXT_INVALID: 400,
    ErrorCode.SECRET_MISSING: 400,
    ErrorCode.LLM_CONFIG_MISSING: 400,
    # 403 — auth
    ErrorCode.AUTHZ_FAILED: 403,
    ErrorCode.SCOPE_VIOLATION: 403,
    # 404
    ErrorCode.TARGET_NOT_FOUND: 404,
    # 409 — attempt state conflict
    ErrorCode.STAGE_SUPERSEDED: 409,
    # 5xx — transient / infra
    ErrorCode.TARGET_UNREACHABLE: 502,
    ErrorCode.TOOL_UNAVAILABLE: 502,
    ErrorCode.LLM_UNAVAILABLE: 503,
    ErrorCode.DEADLINE_EXCEEDED: 504,
    ErrorCode.INTERNAL_ERROR: 500,
}


def _http_status_for_error(code: ErrorCode | None) -> int:
    """Map a failure ErrorCode to the wire HTTP status. None → 500."""
    if code is None:
        return 500
    return _ERROR_HTTP_STATUS.get(code, 500)


def _coerce_output(raw: Any) -> dict[str, Any]:
    """Normalize engine.run() return into dict for EngineResult.output."""
    if raw is None:
        return {}
    if isinstance(raw, BaseModel):
        return raw.model_dump(mode="json")
    if isinstance(raw, dict):
        return raw
    return {"value": raw}


def _failed_result(
    stage_attempt_id: str,
    code: ErrorCode,
    message: str,
    *,
    retryable: bool,
    partial_artifacts: list[Any] | None = None,
) -> EngineResult:
    return EngineResult(
        status=EngineStatus.FAILED,
        stage_attempt_id=stage_attempt_id,
        error_code=code,
        error_message=message,
        retryable=retryable,
        partial_artifacts=partial_artifacts or [],
    )


# GET /schema response model. Kept internal (no re-export from __init__) —
# it's an internal protocol between registry and SDK, not a stable DTO.
from pydantic import Field  # noqa: E402
from trustchain_contracts import ContractModel  # noqa: E402


class _SchemaSnapshot(ContractModel):
    engine_id: str
    version: str
    stage: str
    config_schema: dict[str, Any] = Field(default_factory=dict)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    capabilities: Capabilities
    # Five fields below were shadowed onto EngineApp during Phase 2A SDK
    # cleanup but originally got dropped from the /schema response — that
    # meant registry mismatch detection (registry._compare_schema) couldn't
    # see drift in tool deps / risk_level / timeouts / resources. Adding
    # them here closes the contract gap (Codex P0-1).
    risk_level: "RiskLevel"
    timeout_default: int
    resource_profile: "ResourceProfile"
    required_tools: list[str] = Field(default_factory=list)
    optional_tools: list[str] = Field(default_factory=list)
    secret_requirements: list[SecretRequirement] = Field(default_factory=list)
    artifact_types: list[ArtifactKind] = Field(default_factory=list)
    sdk_version: str
    contracts_version: str


def _sdk_version() -> str:
    try:
        from importlib.metadata import version

        return version("trustchain-sdk")
    except Exception:
        return "unknown"


def _contracts_version() -> str:
    try:
        import trustchain_contracts

        return getattr(trustchain_contracts, "__version__", "unknown")
    except Exception:
        return "unknown"
