"""
MockContext — in-process stand-in for RunContext in unit tests.

Unit tests MUST be runnable on a developer laptop with no docker, no network,
no orchestrator. MockContext captures everything the engine does so tests can
assert against emitted events, saved artifacts, requested tool calls, LLM
responses served, and finding drafts produced.

Typical use:

    from trustchain_sdk.testing import MockContext
    from trustchain_contracts import TargetRef

    @pytest.mark.asyncio
    async def test_happy_path():
        ctx = MockContext(
            targets=[TargetRef(id="t1", url="https://x.example", authorized_scope=["x.example"])],
            declared_secrets={"openai"},
        )
        ctx.mock_secret("openai", "sk-test-fake")
        ctx.mock_tool("nmap", {"result": {"ports": [80, 443]}})
        ctx.mock_llm_response("the framework is Flask")

        engine = MyRecon()
        result = await engine.run(ctx, config={"depth": 2})

        assert any(e["kind"] == "progress" for e in ctx.captured_events())
        assert len(ctx.captured_findings()) == 1
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from trustchain_contracts import (
    ENGINE_ALLOWED_KINDS,
    ENGINE_USER_EMITTABLE_KINDS,
    ArtifactKind,
    ArtifactRef,
    CallbackConfig,
    Capabilities,
    EventKind,
    EventLevel,
    FindingCandidateDraft,
    HttpFetchResult,
    LLMConfig,
    SecretRequirement,
    TargetRef,
)

from ._errors import ScopeViolation, SecretMissing, ToolUnavailable
from .context import RunContext, _install_test_http_client
from .llm import LLMClient, LLMResult
from .secrets import SecretsProxy


def install_test_http_client(client: "httpx.AsyncClient | None") -> None:  # type: ignore[name-defined]
    """Test-only: set a process-wide httpx.AsyncClient that every RunContext
    will use for its callbacks (events, tools, artifacts).

    Integration tests that run engines in-process alongside core (via
    httpx.ASGITransport routing) call this to make sure engine callbacks go
    back to the test's in-process core, not the network.

    Pass ``None`` to clear.
    """
    _install_test_http_client(client)


class _MockLLMClient(LLMClient):
    """LLMClient that returns queued fake responses instead of hitting an API."""

    def __init__(
        self,
        *,
        config: LLMConfig | None,
        uses_llm: bool,
        secrets: SecretsProxy,
        emit_event,  # type: ignore[no-untyped-def]
        exception_box=None,  # callable returning a BaseException | None
    ) -> None:
        super().__init__(
            config=config, uses_llm=uses_llm, secrets=secrets, emit_event=emit_event
        )
        self._queued_responses: list[str] = []
        self._default_response: str | None = None
        # Lazy callable so MockContext can flip the slot post-construction
        # via mock_llm_exception(...) without rebuilding the LLM.
        self._exception_box = exception_box or (lambda: None)

    def queue(self, content: str) -> None:
        self._queued_responses.append(content)

    def set_default(self, content: str) -> None:
        self._default_response = content

    async def _call_openai(  # override
        self, messages: list[dict[str, Any]], model: str, temperature: float
    ) -> LLMResult:
        _ = messages, temperature
        # Honor mock_llm_exception(...) injected from MockContext.
        exc = self._exception_box()
        if exc is not None:
            raise exc
        if self._queued_responses:
            content = self._queued_responses.pop(0)
        elif self._default_response is not None:
            content = self._default_response
        else:
            content = "[mock llm: no response queued]"
        # Rough token counting — just for smoke tests, not accurate.
        input_tokens = sum(len(m.get("content", "") or "") // 4 for m in messages)
        output_tokens = max(1, len(content) // 4)
        return LLMResult(
            content=content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=0.0,
            model=model,
            provider="openai",
            finish_reason="stop",
        )


class MockContext(RunContext):
    """Test double. Skips the network plane; captures side effects.

    All of RunContext's public API works identically — engine code under test
    can't tell it's a mock.
    """

    def __init__(
        self,
        *,
        run_id: str = "r_test",
        project_id: str = "p_test",
        stage: str = "recon",
        stage_attempt_id: str = "sa_test",
        attempt_number: int = 1,
        engine_id: str = "test-engine@0.0.0",
        deadline: datetime | None = None,
        targets: list[TargetRef] | None = None,
        upstream_outputs: dict[str, Any] | None = None,
        declared_secrets: set[str] | frozenset[str] | None = None,
        provided_secrets: dict[str, str] | None = None,
        required_secrets: set[str] | frozenset[str] | None = None,
        capabilities: Capabilities | None = None,
        llm_config: LLMConfig | None = None,
    ) -> None:
        # Intentionally does NOT call super().__init__ — we bypass the
        # network-constructing parts. All fields set manually.
        self.run_id = run_id
        self.project_id = project_id
        self.stage = stage
        self.stage_attempt_id = stage_attempt_id
        self.attempt_number = attempt_number
        self.engine_id = engine_id
        self.deadline = deadline or (datetime.now(timezone.utc) + timedelta(minutes=10))

        self.targets = targets or []
        self.upstream_outputs = upstream_outputs or {}

        allowed = frozenset(declared_secrets or ())
        self.secrets = SecretsProxy(raw=provided_secrets or {}, allowed=allowed)

        # Mirror RunContext: required secrets must actually be provided.
        required = frozenset(required_secrets or ())
        missing = [n for n in required if not self.secrets._has(n)]
        if missing:
            raise SecretMissing(
                f"required secrets missing from MockContext: {sorted(missing)}"
            )

        caps = capabilities or Capabilities(
            uses_llm=(llm_config is not None),
        )
        self._capabilities = caps

        # Capture channels
        self._captured_events: list[dict[str, Any]] = []
        self._captured_tool_calls: list[dict[str, Any]] = []
        self._finding_drafts: list[FindingCandidateDraft] = []
        self._artifact_refs: list[ArtifactRef] = []
        self._tool_responses: dict[str, dict[str, Any]] = {}
        self._tool_exceptions: dict[str, BaseException] = {}
        self._llm_exception: BaseException | None = None
        self._artifact_save_exception: BaseException | None = None
        self._cancelled = False
        self._tool_call_count = 0

        # Scope
        self._scope_patterns = sorted({p for t in self.targets for p in t.authorized_scope})

        # LLM (mock). Uses the INTERNAL emit path to match RunContext: llm_call
        # is SDK-emitted, engine code can't emit it directly. The MockContext
        # holds a reference to its exception slot so callers can flip it via
        # mock_llm_exception() without rebuilding the LLM client.
        self.llm = _MockLLMClient(
            config=llm_config,
            uses_llm=caps.uses_llm,
            secrets=self.secrets,
            emit_event=self._emit_internal_event,
            exception_box=lambda: self._llm_exception,
        )

        # Not owning a network client here.
        self._http = None  # type: ignore[assignment]
        self._owns_http = False
        self._callbacks = CallbackConfig(
            events_url="http://mock/events",
            tools_url="http://mock/tools",
            token="mock-token",
        )

        import logging

        self.logger = logging.getLogger(f"mock.{engine_id}.{run_id}")

    # ---------- assertion helpers ----------

    def captured_events(self) -> list[dict[str, Any]]:
        """List of all events the engine emitted. Each is a dict with the
        EventIn fields plus a ``kind`` string for convenient filtering."""
        return list(self._captured_events)

    def captured_findings(self) -> list[FindingCandidateDraft]:
        return list(self._finding_drafts)

    def captured_tool_calls(self) -> list[dict[str, Any]]:
        return list(self._captured_tool_calls)

    def captured_artifacts(self) -> list[ArtifactRef]:
        return list(self._artifact_refs)

    # ---------- mock configuration ----------

    def mock_secret(self, name: str, value: str) -> None:
        """Inject a secret value. Must be in declared_secrets or this raises."""
        if name not in self.secrets._declared():
            raise AssertionError(
                f"cannot mock_secret({name!r}): not in declared_secrets "
                f"{sorted(self.secrets._declared())}"
            )
        self.secrets._secrets[name] = value  # type: ignore[attr-defined]

    def mock_tool(self, tool_id: str, response: dict[str, Any]) -> None:
        """Set the response that call_tool(tool_id, ...) will return.

        Response may be either a bare result dict (what the tool produces) or
        a full {"tool_id": ..., "result": {...}} shape. Both work.
        """
        self._tool_responses[tool_id] = response

    def mock_tool_exception(self, tool_id: str, exc: BaseException) -> None:
        """Make ``call_tool(tool_id, ...)`` raise ``exc`` instead of returning.

        Used to test soft-fail / error-handling paths. Common choices for
        ``exc``: ``ToolUnavailable`` (tool service down), ``ScopeViolation``
        (engine bypassed SDK pre-check), ``StageSuperseded`` (cancellation).
        """
        self._tool_exceptions[tool_id] = exc

    def mock_llm_exception(self, exc: BaseException) -> None:
        """Make the next (and subsequent) ``ctx.llm.chat(...)`` calls raise
        ``exc``. Use this instead of monkey-patching ``ctx.llm.chat`` in
        tests — patching is fragile because some SDK code paths call
        ``self.llm.chat`` internally and miss the patched attribute.
        Common choices: ``LLMUnavailable``, ``StageSuperseded``."""
        self._llm_exception = exc

    def mock_artifact_save_exception(self, exc: BaseException) -> None:
        """Make ``ctx.save_artifact(...)`` raise ``exc``. Same rationale as
        mock_llm_exception — beats monkey-patching. Common choices:
        ``ToolUnavailable`` (MinIO down), ``CallbackAuthzFailed`` (token
        rejected), ``StageSuperseded`` (cancellation)."""
        self._artifact_save_exception = exc

    def mock_llm_response(self, content: str) -> None:
        """Queue one LLM response. FIFO — multiple calls pop in order."""
        assert isinstance(self.llm, _MockLLMClient)
        self.llm.queue(content)

    def set_default_llm_response(self, content: str) -> None:
        """Default if the queue is empty. Good for tests that don't care about LLM."""
        assert isinstance(self.llm, _MockLLMClient)
        self.llm.set_default(content)

    def trigger_cancellation(self) -> None:
        """Simulate orchestrator-initiated cancellation."""
        self._cancelled = True

    # ---------- RunContext overrides (no network) ----------

    async def emit_event(self, kind, payload=None, *, level="info") -> None:  # type: ignore[override,no-untyped-def]
        """Engine-emitted event; must be in ENGINE_USER_EMITTABLE_KINDS (same
        rule as real RunContext)."""
        if isinstance(kind, str):
            kind = EventKind(kind)
        if kind not in ENGINE_USER_EMITTABLE_KINDS:
            raise PermissionError(
                f"engine cannot emit event kind {kind.value!r} directly; "
                f"user-emittable: {sorted(k.value for k in ENGINE_USER_EMITTABLE_KINDS)}"
            )
        await self._emit_internal_event(kind, payload, level=level)

    async def _emit_internal_event(self, kind, payload=None, *, level="info") -> None:  # type: ignore[override,no-untyped-def]
        """SDK-internal emit (tool_invoked / llm_call). Same wider whitelist
        as real RunContext."""
        if isinstance(kind, str):
            kind = EventKind(kind)
        if kind not in ENGINE_ALLOWED_KINDS:
            raise PermissionError(
                f"internal emit: kind {kind.value!r} not allowed"
            )
        evt = {
            "kind": kind.value,
            "level": EventLevel(level).value if isinstance(level, str) else level.value,
            "payload": self._scrub(payload or {}),
            "stage": self.stage,
            "stage_attempt_id": self.stage_attempt_id,
            "run_id": self.run_id,
            "engine": self.engine_id,
            "client_ts": datetime.now(timezone.utc).isoformat(),
        }
        self._captured_events.append(evt)

    async def call_tool(
        self,
        tool_id: str,
        request: dict[str, Any],
        *,
        timeout_s: float = 30.0,
    ) -> dict[str, Any]:
        self._tool_call_count += 1
        self._captured_tool_calls.append(
            {"tool_id": tool_id, "request": request, "timeout_s": timeout_s}
        )
        if tool_id in self._tool_exceptions:
            raise self._tool_exceptions[tool_id]
        if tool_id not in self._tool_responses:
            raise ToolUnavailable(
                f"no mock response set for tool {tool_id!r}; "
                f"call ctx.mock_tool({tool_id!r}, {{...}}) first"
            )
        raw = self._tool_responses[tool_id]
        # Accept either a result-dict or a full ToolResponse shape.
        return raw.get("result", raw) if isinstance(raw, dict) else raw

    async def fetch(  # type: ignore[override]
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: Any = None,
        timeout_s: float = 30.0,
    ) -> HttpFetchResult:
        if not self._host_in_scope(url):
            raise ScopeViolation(url=url, authorized_scope=self._scope_patterns)
        raw = await self.call_tool(
            "http_fetch",
            {"url": url, "method": method, "headers": headers or {}, "body": body},
            timeout_s=timeout_s,
        )
        # Allow mock_tool('http_fetch', {...}) to return a full HttpFetchResult dict
        return HttpFetchResult.model_validate(raw)

    async def save_artifact(  # type: ignore[override]
        self,
        name: str,
        data: bytes,
        *,
        kind: ArtifactKind,
        mime_type: str = "application/octet-stream",
    ) -> ArtifactRef:
        import hashlib
        import uuid

        # Honor mock_artifact_save_exception(...) for error-path tests.
        if self._artifact_save_exception is not None:
            raise self._artifact_save_exception

        ref = ArtifactRef(
            id=f"mock_art_{uuid.uuid4().hex[:8]}",
            kind=kind,
            mime_type=mime_type,
            minio_key=f"mock/{self.run_id}/{name}",
            size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            created_at=datetime.now(timezone.utc),
            run_id=self.run_id,
            stage=self.stage,
            stage_attempt_id=self.stage_attempt_id,
        )
        self._artifact_refs.append(ref)
        return ref

    async def check_cancelled(self) -> bool:  # type: ignore[override]
        await asyncio.sleep(0)
        return self._cancelled

    async def close(self) -> None:  # type: ignore[override]
        # No-op: mock owns no network resources.
        return None


# ============================================================
# DevHarness — local mini-core for engine end-to-end dev / integration tests.
#
# Codex review (2026-04-24, see doc/codex-review-phase-1.5.md) explicitly
# rejected adding a third RunContext subclass ("LocalRunContext"). The
# argument: 3 ctx implementations means 3 places to update for every SDK
# contract change, and the local one is the one students actually use, so
# silent drift between local and prod would be devastating in lab.
#
# Instead: keep RealRunContext as the only real ctx. Stand up a small
# FastAPI app that fakes core's three engine-callback endpoints
# (events / tools / artifacts) and route the engine's outbound httpx at
# it via a routing transport. The engine code path is byte-identical to
# prod — RealRunContext just happens to hit `http://dev-harness/...` which
# resolves in-process.
# ============================================================

import hashlib  # noqa: E402  (kept near DevHarness rather than top of file)
import json     # noqa: E402
import logging as _logging  # noqa: E402
import uuid     # noqa: E402
from dataclasses import dataclass, field  # noqa: E402
from pathlib import Path  # noqa: E402

import httpx  # noqa: E402

# FastAPI imports at module level because `from __future__ import annotations`
# stores route param types as strings; FastAPI's get_type_hints() needs the
# names resolvable in the module's global scope to recognize Request as a
# special parameter (not a query string field). Cost: importing testing.py
# pulls FastAPI in, which is fine because anyone in this module is already
# in test/dev territory.
from fastapi import FastAPI, HTTPException, Request, Response  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

from trustchain_contracts import (  # noqa: E402
    ENGINE_ALLOWED_KINDS as _ENGINE_ALLOWED_KINDS,
    ArtifactRef as _ArtifactRef,
    CallbackConfig as _CallbackConfig,
    EngineResult as _EngineResult,
    EventKind as _EventKind,
    LLMConfig as _LLMConfig,
    RunContextEnvelope as _RunContextEnvelope,
    RunMetadata as _RunMetadata,
    check_request_scope as _check_request_scope,
)

_dev_logger = _logging.getLogger(__name__)


# Virtual hostname the engine's RealRunContext POSTs callbacks to. Routed
# in-process to the harness's FastAPI app via _RoutedTransport.
_HARNESS_HOST = "dev-harness"
_HARNESS_BASE_URL = f"http://{_HARNESS_HOST}"
_HARNESS_TOKEN = "dev-harness-callback-token"

# Sentinel to distinguish "the previous test client was None" from "we
# never saved one" in DevHarness.start/stop. Plain ``None`` would conflate
# the two and would wipe the slot even when the user never installed
# anything before the harness started.
_UNSET: Any = object()


@dataclass
class PipelineResult:
    """Outcome of ``DevHarness.run_pipeline(...)``. Holds everything a
    debugger / migration owner needs to inspect after a multi-stage local
    integration run.

    Field reference:
      * ``run_id``        — shared across every stage's envelope, every
                            event's ``run_id`` field, and every artifact's
                            ``minio_key`` prefix. Mirror of prod where
                            one Run = one ``run_id`` + N stage_attempt_ids.
      * ``outputs``       — convenience: ``{stage_name: output_dict}``
                            (stages that didn't run are absent, including
                            stages after the failed one).
      * ``stage_results`` — full per-stage ``EngineResult`` (output +
                            error_code + retryable + metrics +
                            partial_artifacts + finding_candidates).
                            Required for debugging failed stages — outputs
                            alone strips error context.
      * ``events``        — events emitted by THIS pipeline run only
                            (scoped — not the whole harness session).
                            In chronological order across all stages.
      * ``artifacts``     — artifacts saved by THIS pipeline run only.
                            Each ``ArtifactRef.minio_key`` =
                            ``local/<run_id>/<artifact_id>_<name>``;
                            actual bytes at
                            ``harness.artifact_dir/<run_id>/...``.
      * ``failed_stage``  — ``None`` on full success.
                            ``(stage_name, EngineResult)`` on first failure.
    """

    run_id: str
    outputs: dict[str, Any] = field(default_factory=dict)
    stage_results: dict[str, _EngineResult] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[_ArtifactRef] = field(default_factory=list)
    failed_stage: tuple[str, _EngineResult] | None = None

    @property
    def succeeded(self) -> bool:
        """True iff every stage in the pipeline returned ``EngineStatus.SUCCESS``."""
        return self.failed_stage is None


class _RoutedTransport(httpx.AsyncBaseTransport):
    """httpx transport that routes requests to either an in-process ASGI app
    or the real network, based on URL host. Used so the engine's outbound
    callbacks (to harness virtual host) stay in-process while tool URLs
    (real localhost ports) go through real TCP."""

    def __init__(self, *, harness_host: str, harness_app: Any) -> None:
        self._harness_host = harness_host
        self._asgi = httpx.ASGITransport(app=harness_app)
        self._real = httpx.AsyncHTTPTransport()

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        if request.url.host == self._harness_host:
            return await self._asgi.handle_async_request(request)
        return await self._real.handle_async_request(request)

    async def aclose(self) -> None:
        await self._real.aclose()


class DevHarness:
    """Local mini-core for engine dev / integration testing.

    Stands up a FastAPI app exposing the three callback routes core normally
    serves (events / tools / artifacts), then runs the engine's invoke()
    against a synthesized envelope. Engine code is unchanged — RealRunContext
    POSTs callbacks to this in-process app instead of api-gateway.

    What this harness does NOT exercise (deliberate trade-off, not bug):
      * The engine's own FastAPI ``/invoke`` wrapper. ``run_once`` calls
        ``engine_app.invoke()`` directly — same EngineResult, but skips
        ``ENGINE_SHARED_SECRET`` Bearer auth + the ``error_code → HTTP
        status`` mapping the prod /invoke route applies. Both are covered
        by other SDK tests (``test_engine_invoke.py``); going through HTTP
        here would just add another ASGI transport for negligible gain.

    Scope, event-kind, and artifact upload routes use logic shared with
    real core (``trustchain_contracts.check_request_scope`` /
    ``ENGINE_ALLOWED_KINDS`` / ``ArtifactRef`` construction) so engines
    can't accidentally ship "works locally, fails on lab" bugs in those
    surfaces.

    Usage:

        from trustchain_sdk.testing import DevHarness
        from trustchain_contracts import TargetRef

        async with DevHarness(
            engine_app=MyEngine(),
            tool_urls={"nmap": "http://localhost:9211"},
            authorized_scope=["scanme.nmap.org"],
            artifact_dir="./artifacts",
            secrets={"openai": "sk-...", "exa": "..."},
        ) as harness:
            target = TargetRef(
                id="t1", url="https://scanme.nmap.org/",
                target_type="web", authorized_scope=["scanme.nmap.org"],
            )
            result = await harness.run_once(target=target, config={"mode": "basic"})
            print(result.output)
    """

    def __init__(
        self,
        *,
        engine_app: Any = None,
        tool_urls: dict[str, str] | None = None,
        authorized_scope: list[str] | None = None,
        artifact_dir: str | Path = "./artifacts",
        events_path: str | Path | None = "./events.jsonl",
        secrets: dict[str, str] | None = None,
        openai_api_key: str | None = None,
        llm_default_model: str = "gpt-4o-mini",
    ) -> None:
        # engine_app is optional — pipeline-only sessions (run_pipeline with
        # per-stage engines) don't need a default. run_once requires either
        # this constructor arg or the per-call engine_app= override.
        self.engine_app = engine_app
        self.tool_urls = dict(tool_urls or {})
        self._scope = list(authorized_scope or [])
        self.artifact_dir = Path(artifact_dir)
        self.events_path = (
            Path(events_path) if events_path is not None else None
        )
        # Pluggable secrets for any engine that needs more than openai
        # (exa / nvd / etc.). openai_api_key kwarg kept as ergonomic shortcut
        # for the common case; explicit secrets dict wins on conflict.
        self._secrets = dict(secrets or {})
        if openai_api_key:
            self._secrets.setdefault("openai", openai_api_key)
        self._llm_default_model = llm_default_model

        # In-memory mirrors for test introspection. Always populated even when
        # events_path is None (so tests don't need to write a file).
        self._captured_events: list[dict[str, Any]] = []
        self._captured_artifacts: list[_ArtifactRef] = []

        self._app: Any = None
        # Outgoing client used by the harness itself to forward tool calls to
        # real tool services. Separate from the routed client so it doesn't
        # loop back through ASGI for tool URLs.
        self._tool_client: httpx.AsyncClient | None = None
        # Routed client installed onto the SDK's process-wide test slot.
        self._routed_client: httpx.AsyncClient | None = None
        # Saved on start(), restored on stop() — composes cleanly with any
        # pre-existing test client (e.g. thin_slice tests, nested harnesses).
        # Sentinel _UNSET distinguishes "not yet started" from "started with
        # None as the previous value".
        self._prev_test_client: Any = _UNSET
        self._started = False

    async def start(self) -> None:
        """Boot the harness: create FastAPI app, install routed httpx client
        as the SDK's process-wide test client. Idempotent.

        Saves the previously installed test client (if any) so stop() can
        restore it. Lets DevHarness compose with thin_slice fixtures or
        nested harness use without losing the outer caller's client.
        """
        if self._started:
            return

        # Bring up filesystem state first; cheap + can fail with clear errors
        # before we touch any process-wide state.
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        if self.events_path is not None:
            self.events_path.parent.mkdir(parents=True, exist_ok=True)
            # Truncate prior runs so each harness session is its own log.
            self.events_path.write_text("")

        # Build the harness app + httpx clients with rollback on partial
        # failure so we never leave half-initialized resources behind
        # (Codex P1.4).
        self._app = self._build_app()
        self._tool_client = httpx.AsyncClient(timeout=60.0)
        try:
            self._routed_client = httpx.AsyncClient(
                transport=_RoutedTransport(
                    harness_host=_HARNESS_HOST, harness_app=self._app
                )
            )
        except Exception:
            await self._tool_client.aclose()
            self._tool_client = None
            raise

        # Save whatever was previously installed (thin_slice tests / outer
        # harness / None) BEFORE we overwrite it (Codex P3).
        from .context import _test_http_client as _current

        self._prev_test_client = _current
        _install_test_http_client(self._routed_client)
        self._started = True

    async def stop(self) -> None:
        """Tear down harness: restore previous test client slot, close httpx."""
        if not self._started:
            return

        # Restore the SDK test slot to whatever it was before start() — None
        # if no outer caller had installed anything (Codex P3).
        if self._prev_test_client is _UNSET:
            _install_test_http_client(None)
        else:
            _install_test_http_client(self._prev_test_client)
        self._prev_test_client = _UNSET

        if self._routed_client is not None:
            await self._routed_client.aclose()
            self._routed_client = None
        if self._tool_client is not None:
            await self._tool_client.aclose()
            self._tool_client = None
        self._started = False

    async def __aenter__(self) -> "DevHarness":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    async def run_once(
        self,
        *,
        target: TargetRef | None = None,
        targets: list[TargetRef] | None = None,
        config: dict[str, Any] | None = None,
        upstream_outputs: dict[str, Any] | None = None,
        engine_app: Any = None,
        run_id: str | None = None,
        deadline_seconds: float = 300.0,
    ) -> _EngineResult:
        """Build a synthetic RunContextEnvelope and call engine.invoke()
        directly. Returns the EngineResult exactly as core would receive it
        from a real /invoke.

        ``engine_app`` (optional) overrides the constructor's default for
        this call. Required at SOME level — either the constructor or here.
        ``run_id`` (optional) lets ``run_pipeline`` share one ID across
        every stage (mirrors prod where one Run = one ``run_id`` + N
        stage_attempt_ids). Defaults to a fresh UUID when omitted.
        """
        if not self._started:
            await self.start()

        engine = engine_app if engine_app is not None else self.engine_app
        if engine is None:
            raise ValueError(
                "no engine_app available — pass DevHarness(engine_app=...) "
                "or run_once(engine_app=...)"
            )

        if targets is None:
            if target is None:
                raise ValueError(
                    "run_once requires `target=` or `targets=`"
                )
            targets = [target]

        # If a target's authorized_scope is empty but harness has a default
        # scope, propagate so SDK's host_in_scope works on bare-host targets.
        # Use model_copy so we don't mutate the caller's TargetRef in place
        # (Codex P1.3 — re-running with the same TargetRef otherwise leaves
        # the first run's scope on it, surprising and hard to debug).
        targets = [
            t.model_copy(update={"authorized_scope": list(self._scope)})
            if not t.authorized_scope and self._scope
            else t
            for t in targets
        ]

        ts = datetime.now(timezone.utc)
        rid = run_id or f"r_{uuid.uuid4().hex[:12]}"
        attempt_id = f"sa_{uuid.uuid4().hex[:12]}"

        # Discover engine's stage / engine_id / capabilities from the EngineApp
        # instance (same fields the registry would read from engine.yaml).
        stage = getattr(engine, "stage", "recon") or "recon"
        engine_id = (
            getattr(engine, "engine_id", "") or "dev-harness-engine"
        )
        caps = getattr(engine, "capabilities", None)
        uses_llm = bool(getattr(caps, "uses_llm", False))

        envelope = _RunContextEnvelope(
            run_id=rid,
            project_id="dev-harness-project",
            stage=stage,
            stage_attempt_id=attempt_id,
            attempt_number=1,
            engine_id=engine_id,
            deadline=ts + timedelta(seconds=deadline_seconds),
            targets=targets,
            upstream_outputs=upstream_outputs or {},
            config=config or {},
            secrets=dict(self._secrets),
            llm_config=(
                _LLMConfig(default_model=self._llm_default_model)
                if uses_llm
                else None
            ),
            callbacks=_CallbackConfig(
                events_url=f"{_HARNESS_BASE_URL}/api/v1/runs/{rid}/events",
                tools_url=f"{_HARNESS_BASE_URL}/api/v1/tools",
                token=_HARNESS_TOKEN,
            ),
            run_metadata=_RunMetadata(
                initiated_by="dev-harness", triggered_at=ts
            ),
        )

        return await engine.invoke(envelope)

    # ---------- multi-stage: run_pipeline ----------

    async def run_pipeline(
        self,
        *,
        target: TargetRef | None = None,
        targets: list[TargetRef] | None = None,
        stages: list[tuple[Any, dict[str, Any]]],
        upstream_outputs: dict[str, Any] | None = None,
        deadline_seconds: float = 300.0,
    ) -> "PipelineResult":
        """Chain multiple engines as a pipeline. Each stage's output is
        auto-injected as the next stage's ``upstream_outputs[<prev_stage>]``.

        ``stages`` is a list of ``(engine_app_instance, config_dict)`` tuples.
        Stages run in order; the first failed stage halts the pipeline
        (later stages are not executed and appear absent from the result's
        outputs / stage_results). Use ``upstream_outputs={...}`` to seed
        canned upstream data — useful for skipping early stages and
        debugging a single downstream stage in isolation.

        Returns a ``PipelineResult`` with everything: per-stage EngineResult,
        flat outputs view, events / artifacts produced by THIS pipeline only
        (scoped — not the entire harness session), and the shared run_id
        every stage's envelope used.

        Critical detail (mirrors prod core): all stages of a single pipeline
        share ONE ``run_id``; ``stage_attempt_id`` stays fresh per stage.
        Engines that namespace artifacts by ``ctx.run_id`` would silently
        produce different layout locally vs. lab without this.
        """
        if not self._started:
            await self.start()

        if not stages:
            raise ValueError("run_pipeline requires a non-empty `stages=` list")

        # Shared run_id across every stage. stage_attempt_id stays fresh per
        # stage (run_once generates one per call — correct prod behavior).
        pipeline_run_id = f"r_{uuid.uuid4().hex[:12]}"

        # Scope events/artifacts to THIS pipeline only — without this slice,
        # a second run_pipeline (or interleaved run_once) in the same harness
        # session would leak into the result's events/artifacts list.
        events_idx_start = len(self._captured_events)
        artifacts_idx_start = len(self._captured_artifacts)

        outputs: dict[str, Any] = dict(upstream_outputs or {})
        stage_results: dict[str, _EngineResult] = {}
        failed_stage: tuple[str, _EngineResult] | None = None

        for engine_app, config in stages:
            stage_name = (
                getattr(engine_app, "stage", "") or "dev-harness-engine"
            )
            if stage_name in stage_results:
                # Hard-fail on duplicate stage names rather than silently
                # overwriting prior stage's output dict. If cross-validation
                # (two engines, same stage name) becomes a real ask later,
                # add an optional explicit-rename kwarg per tuple.
                raise ValueError(
                    f"duplicate stage name {stage_name!r} in pipeline "
                    f"(already produced by {sorted(stage_results)}); "
                    "each pipeline stage must declare a unique engine.yaml "
                    "stage value (or be wired with an explicit override "
                    "when that feature lands)"
                )

            result = await self.run_once(
                engine_app=engine_app,
                target=target,
                targets=targets,
                config=config,
                upstream_outputs=dict(outputs),  # snapshot to prior stages
                run_id=pipeline_run_id,
                deadline_seconds=deadline_seconds,
            )
            stage_results[stage_name] = result

            # Lazy import here to avoid pulling EngineStatus into the
            # module's top-level imports just for this comparison.
            from trustchain_contracts import EngineStatus as _EngineStatus

            if result.status != _EngineStatus.SUCCESS:
                failed_stage = (stage_name, result)
                break

            outputs[stage_name] = result.output

        return PipelineResult(
            run_id=pipeline_run_id,
            outputs=outputs,
            stage_results=stage_results,
            events=list(self._captured_events[events_idx_start:]),
            artifacts=list(self._captured_artifacts[artifacts_idx_start:]),
            failed_stage=failed_stage,
        )

    # ---------- introspection (for tests / pretty-printing) ----------

    def captured_events(self) -> list[dict[str, Any]]:
        """Every event the engine emitted during run_once (post-scrub)."""
        return list(self._captured_events)

    def captured_artifacts(self) -> list[_ArtifactRef]:
        """Every artifact the engine saved during run_once. The actual bytes
        are at `self.artifact_dir/<run_id>/<artifact_id>_<name>`."""
        return list(self._captured_artifacts)

    # ---------- internal: harness FastAPI app ----------

    def _build_app(self) -> Any:
        app = FastAPI(title="trustchain-dev-harness")

        def _check_token(req: "Request") -> None:
            # Read the header directly off the Starlette request rather than
            # via FastAPI's Header() dependency — the latter doesn't play
            # well with `from __future__ import annotations` + lazy imports.
            token = req.headers.get("x-callback-token")
            if token != _HARNESS_TOKEN:
                raise HTTPException(401, "INVALID_CALLBACK_TOKEN")

        @app.post("/api/v1/runs/{run_id}/events")
        async def post_events(run_id: str, request: Request) -> Response:
            _check_token(request)
            body = await request.json()
            # Mirror prod core's whitelist (routes_ingestion.py): engine
            # MUST NOT emit lifecycle / orchestrator-only kinds (stage_*,
            # run_*, decision_*). Local-passing-but-lab-failing was Codex
            # P0 — exactly the bug DevHarness exists to prevent.
            kind_raw = body.get("kind", "")
            try:
                kind = _EventKind(kind_raw)
            except ValueError:
                raise HTTPException(
                    400, f"unknown event kind: {kind_raw!r}"
                )
            if kind not in _ENGINE_ALLOWED_KINDS:
                raise HTTPException(
                    400,
                    f"engine may not emit kind={kind.value!r} (orchestrator-only)",
                )
            self._captured_events.append(body)
            if self.events_path is not None:
                with self.events_path.open("a") as f:
                    f.write(json.dumps(body, default=str) + "\n")
            return Response(status_code=204)

        @app.post("/api/v1/tools/{tool_id}/invoke")
        async def proxy_tool(tool_id: str, request: Request) -> JSONResponse:
            _check_token(request)
            base = self.tool_urls.get(tool_id)
            if base is None:
                # Mirror core's "unknown tool" → 502 → engine sees ToolUnavailable.
                raise HTTPException(
                    502,
                    f"tool {tool_id!r} not configured in DevHarness "
                    f"(known: {sorted(self.tool_urls)})",
                )

            body = await request.json()
            inner_request = body.get("request", {}) or {}
            timeout_s = float(body.get("timeout_s", 30.0))

            # Single source of truth with prod core: same dispatcher decides
            # which scope matcher (target_in_scope for nmap CIDR / url_in_scope
            # for URL tools / host_in_scope for bare host literals). Codex P2
            # caught the previous DevHarness shortcut that always used
            # url_in_scope after http:// prefixing — wrong for nmap super-CIDR.
            scope_check = _check_request_scope(
                tool_id=tool_id,
                request_payload=inner_request,
                authorized_scope=self._scope,
            )
            if not scope_check.passed:
                raise HTTPException(
                    403,
                    f"scope violation: tool={tool_id!r} field={scope_check.field!r} "
                    f"value={scope_check.value!r} outside {sorted(set(self._scope))}",
                )

            assert self._tool_client is not None
            try:
                forwarded = await self._tool_client.post(
                    f"{base.rstrip('/')}/invoke",
                    json=inner_request,
                    timeout=timeout_s + 5.0,
                )
            except httpx.HTTPError as exc:
                raise HTTPException(
                    502, f"tool {tool_id!r} unreachable: {exc}"
                ) from exc

            try:
                tool_result = forwarded.json()
            except Exception:
                tool_result = {"raw": forwarded.text}

            # Mirror core's response shape: {"result": <tool body>}.
            # SDK's call_tool unwraps `data.get("result", data)`.
            return JSONResponse(
                {"result": tool_result}, status_code=forwarded.status_code
            )

        @app.post("/api/v1/tools/_artifact/put")
        async def upload_artifact(request: Request) -> JSONResponse:
            # Parse multipart manually via Starlette's request.form() so this
            # route doesn't need UploadFile/File/Form annotations (which break
            # under `from __future__ import annotations` when FastAPI imports
            # are lazy).
            _check_token(request)
            form = await request.form()
            upload = form.get("file")
            if upload is None or not hasattr(upload, "read"):
                raise HTTPException(400, "missing 'file' part in multipart")

            run_id = str(form.get("run_id") or "")
            stage = str(form.get("stage") or "")
            stage_attempt_id = str(form.get("stage_attempt_id") or "")
            kind = str(form.get("kind") or "")
            name = str(form.get("name") or upload.filename or "artifact")

            data = await upload.read()
            artifact_id = f"a_{uuid.uuid4().hex[:12]}"
            run_dir = self.artifact_dir / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            out_path = run_dir / f"{artifact_id}_{name}"
            out_path.write_bytes(data)

            ref = _ArtifactRef(
                id=artifact_id,
                kind=kind,
                mime_type=(
                    getattr(upload, "content_type", None)
                    or "application/octet-stream"
                ),
                # No MinIO in dev — use a local-fs key that downstream code
                # can recognize via the `local/` prefix if it cares.
                minio_key=f"local/{run_id}/{artifact_id}_{name}",
                size_bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                created_at=datetime.now(timezone.utc),
                run_id=run_id,
                stage=stage,
                stage_attempt_id=stage_attempt_id,
            )
            self._captured_artifacts.append(ref)
            return JSONResponse(ref.model_dump(mode="json"))

        return app


# Public surface. install_test_http_client is exported because thin_slice
# tests use it directly; DevHarness wraps it for the higher-level case.
__all__ = [
    "MockContext",
    "DevHarness",
    "PipelineResult",
    "install_test_http_client",
    "SecretRequirement",
    "TargetRef",
]
