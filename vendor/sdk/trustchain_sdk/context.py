"""
RunContext — the engine's view of a single /invoke call.

Per-invoke lifecycle (see spec §6.2):
    1. POST /invoke envelope arrives at the EngineApp router
    2. SDK constructs RunContext from envelope + engine metadata
    3. engine.run(ctx, config) executes
    4. On return, SDK assembles EngineResult from ctx accumulators
    5. RunContext is discarded — no cross-invoke state
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from trustchain_contracts import (
    ENGINE_ALLOWED_KINDS,
    ENGINE_USER_EMITTABLE_KINDS,
    ArtifactKind,
    ArtifactRef,
    Capabilities,
    EngineMetrics,
    EventIn,
    EventKind,
    EventLevel,
    FindingCandidate,
    FindingCandidateDraft,
    FindingDiscoveredPayload,
    HttpFetchRequest,
    HttpFetchResult,
    RunContextEnvelope,
    SecretRequirement,
    ToolInvokedPayload,
    compute_signature,
    url_in_scope,
)

from ._errors import (
    CallbackAuthzFailed,
    ScopeViolation,
    SecretMissing,
    StageSuperseded,
    TargetUnreachable,
    ToolUnavailable,
)
from .llm import LLMClient
from .secrets import SecretsProxy

logger = logging.getLogger(__name__)


# -----------------------------------------------------------
# Test-only: shared httpx client for in-process integration tests.
#
# When set, every RunContext (and thus every engine's callback traffic) uses
# this shared client. Enables monorepo tests to route engine callbacks back
# to the in-process core via httpx.ASGITransport without touching network.
# Production code MUST leave this None.
# -----------------------------------------------------------

_test_http_client: "httpx.AsyncClient | None" = None


def _install_test_http_client(client: "httpx.AsyncClient | None") -> None:
    """Install / clear the process-wide test-only http client."""
    global _test_http_client
    _test_http_client = client


# Used by emit_event's outgoing-payload scrubber. Conservative patterns; we
# prefer false positives (over-redaction) to false negatives (leaked key).
_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),  # OpenAI-style
    re.compile(r"xoxb-[A-Za-z0-9-]{20,}"),  # Slack bot token
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),  # GitHub PAT
    re.compile(r"AKIA[A-Z0-9]{16}"),  # AWS access key id
]


class RunContext:
    """Engine's handle to the platform for one /invoke call.

    Engine code uses these public members:
        run_id, project_id, stage, stage_attempt_id, attempt_number,
        engine_id, deadline, targets, upstream_outputs, secrets, llm, logger

    And these public methods:
        await ctx.emit_event(kind, payload, level=...)
        await ctx.emit_finding(draft)          # preview event + EngineResult
        await ctx.call_tool(tool_id, request, timeout_s=...)
        await ctx.fetch(url, method=..., headers=..., body=..., timeout_s=...)
        await ctx.save_artifact(name, data, kind=...)
        await ctx.check_cancelled()            # True if orchestrator asked to stop
        ctx.time_remaining()                   # seconds until deadline
    """

    # ---------- construction ----------

    def __init__(
        self,
        envelope: RunContextEnvelope,
        *,
        engine_id: str,
        capabilities: Capabilities,
        secret_requirements: list[SecretRequirement],
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        # --- Identity / timing (straight from envelope) ---
        self.run_id: str = envelope.run_id
        self.project_id: str = envelope.project_id
        self.stage: str = envelope.stage
        self.stage_attempt_id: str = envelope.stage_attempt_id
        self.attempt_number: int = envelope.attempt_number
        self.engine_id: str = envelope.engine_id
        self.deadline: datetime = envelope.deadline

        # --- Inputs ---
        self.targets = envelope.targets
        self.upstream_outputs: dict[str, Any] = envelope.upstream_outputs

        # --- Auth plane ---
        declared = frozenset(s.name for s in secret_requirements)
        self.secrets = SecretsProxy(envelope.secrets, allowed=declared)

        # Upfront check: every secret declared `required=True` must be present.
        # Failing here (instead of on first access) gives a deterministic
        # SECRET_MISSING at invoke boundary, as engine-contract §2.4 mandates.
        missing_required = [
            s.name
            for s in secret_requirements
            if s.required and not self.secrets._has(s.name)
        ]
        if missing_required:
            raise SecretMissing(
                f"required secrets missing from envelope: {sorted(missing_required)}"
            )

        # --- Network plane ---
        # Preference order: explicit http_client arg > test-installed shared
        # client > fresh new client we own.
        if http_client is not None:
            self._http = http_client
            self._owns_http = False
        elif _test_http_client is not None:
            self._http = _test_http_client
            self._owns_http = False
        else:
            self._http = httpx.AsyncClient()
            self._owns_http = True
        self._callbacks = envelope.callbacks

        # --- Scope ---
        self._scope_patterns: list[str] = sorted(
            {pat for t in envelope.targets for pat in t.authorized_scope}
        )

        # --- LLM plane ---
        # LLMClient uses the INTERNAL emit path (not ctx.emit_event) because
        # llm_call is an SDK-auto-emitted kind; engine code cannot emit it
        # directly (see spec §7.2 + ENGINE_USER_EMITTABLE_KINDS).
        self.llm = LLMClient(
            config=envelope.llm_config,
            uses_llm=capabilities.uses_llm,
            secrets=self.secrets,
            emit_event=self._emit_internal_event,
        )

        # --- Logging ---
        self.logger = logging.getLogger(
            f"engine.{engine_id}.{envelope.run_id}.{envelope.stage_attempt_id}"
        )

        # --- Accumulators (read back by EngineApp.invoke when run() returns) ---
        self._finding_drafts: list[FindingCandidateDraft] = []
        self._artifact_refs: list[ArtifactRef] = []
        self._tool_call_count = 0
        self._cancelled = False

    async def close(self) -> None:
        """Close the HTTP client if we own it. Called by EngineApp on /invoke exit."""
        if self._owns_http:
            await self._http.aclose()

    # ---------- event emission ----------

    async def emit_event(
        self,
        kind: EventKind | str,
        payload: dict[str, Any] | None = None,
        *,
        level: EventLevel | str = EventLevel.INFO,
    ) -> None:
        """Engine-emitted event. Kind must be in ENGINE_USER_EMITTABLE_KINDS.

        Engines can emit: progress / log / finding_discovered / artifact_produced.
        They CANNOT emit tool_invoked or llm_call (SDK auto-emits those when it
        actually invokes a tool / LLM — so engines can't fake metrics).
        They CANNOT emit lifecycle kinds (orchestrator-owned, see spec §7.2).

        Payload is scrubbed for secrets before sending. POST to ingestion is
        fire-and-forget on transient network failures.
        """
        if isinstance(kind, str):
            kind = EventKind(kind)
        if kind not in ENGINE_USER_EMITTABLE_KINDS:
            raise PermissionError(
                f"engine cannot emit event kind {kind.value!r} directly; "
                f"user-emittable: {sorted(k.value for k in ENGINE_USER_EMITTABLE_KINDS)}. "
                f"(tool_invoked / llm_call are auto-emitted by SDK; "
                f"run_* / stage_* / decision_* are orchestrator-owned, see spec §7.2.)"
            )
        await self._emit_internal_event(kind, payload, level=level)

    async def _emit_internal_event(
        self,
        kind: EventKind | str,
        payload: dict[str, Any] | None = None,
        *,
        level: EventLevel | str = EventLevel.INFO,
    ) -> None:
        """SDK-internal emit. Accepts any kind in ENGINE_ALLOWED_KINDS (the
        superset including tool_invoked / llm_call). Used by LLMClient + tool
        wrappers. Engine code must not call this — use emit_event."""
        if isinstance(kind, str):
            kind = EventKind(kind)
        if kind not in ENGINE_ALLOWED_KINDS:
            # Defense-in-depth: even internal callers can't emit lifecycle.
            raise PermissionError(
                f"internal emit: kind {kind.value!r} not allowed for engine-side"
            )

        scrubbed = self._scrub(payload or {})

        event = EventIn(
            client_ts=datetime.now(timezone.utc),
            run_id=self.run_id,
            stage_attempt_id=self.stage_attempt_id,
            stage=self.stage,
            engine=self.engine_id,
            kind=kind,
            level=EventLevel(level) if isinstance(level, str) else level,
            payload=scrubbed,
        )

        try:
            resp = await self._http.post(
                self._callbacks.events_url,
                json=event.model_dump(mode="json"),
                headers={"X-Callback-Token": self._callbacks.token},
                timeout=5.0,
            )
            if resp.status_code == 401:
                raise CallbackAuthzFailed(
                    "callback token rejected by orchestrator on events_url"
                )
            if resp.status_code == 409:
                self._cancelled = True
                raise StageSuperseded(
                    "orchestrator marked this stage_attempt superseded"
                )
        except (CallbackAuthzFailed, StageSuperseded):
            raise
        except httpx.HTTPError as exc:
            # Fire-and-forget semantics on transient network failures —
            # log but do not fail engine.
            logger.debug("event emit failed (non-fatal): %s", exc)

    async def emit_finding(self, draft: FindingCandidateDraft) -> None:
        """Two-channel emit: preview event now + accumulate for EngineResult.

        See spec §7.2.1. The preview event is non-authoritative and only
        feeds UI realtime; the authoritative source is EngineResult.finding_candidates
        (which is built from accumulated drafts by EngineApp).
        """
        # Channel 1: preview event for UI realtime.
        preview = FindingDiscoveredPayload(
            vuln_type=draft.vuln_type,
            severity=draft.severity.value,
            preview=(
                draft.affected_endpoint
                or draft.signature_evidence.url
                or draft.vuln_type
            )[:200],
        )
        try:
            await self.emit_event(EventKind.FINDING_DISCOVERED, preview.model_dump())
        except StageSuperseded:
            raise

        # Channel 2: accumulator for EngineResult authoritative path.
        self._finding_drafts.append(draft)

    # ---------- fetch / call_tool (scope-checked) ----------

    async def call_tool(
        self,
        tool_id: str,
        request: dict[str, Any],
        *,
        timeout_s: float = 30.0,
    ) -> dict[str, Any]:
        """Invoke a named tool (nmap / nuclei / hydra / http_fetch / ...) via
        the orchestrator's tools side channel. Scope enforcement happens
        server-side; for http_fetch, SDK pre-checks to fail fast.

        Auto-emits a ``tool_invoked`` event on both success and failure paths
        so the UI can show tool activity + so audit has a record. Engines
        MUST NOT emit ``tool_invoked`` themselves (spec §7.2 whitelist).

        Returns the tool's result dict (tool-specific shape).
        """
        import time as _time

        url = f"{self._callbacks.tools_url.rstrip('/')}/{tool_id}/invoke"
        body = {
            "run_id": self.run_id,
            "stage_attempt_id": self.stage_attempt_id,
            "tool_id": tool_id,
            "request": request,
            "timeout_s": timeout_s,
        }
        started = _time.monotonic()
        try:
            resp = await self._http.post(
                url,
                json=body,
                headers={"X-Callback-Token": self._callbacks.token},
                timeout=timeout_s + 5.0,
            )
        except httpx.HTTPError as exc:
            await self._emit_tool_invoked(tool_id, started, success=False, error_code="TARGET_UNREACHABLE")
            raise ToolUnavailable(f"tool {tool_id!r} call failed: {exc}") from exc

        if resp.status_code == 401:
            await self._emit_tool_invoked(tool_id, started, success=False, error_code="AUTHZ_FAILED")
            raise CallbackAuthzFailed(
                f"callback token rejected by orchestrator on tools_url/{tool_id}"
            )
        if resp.status_code == 403:
            # Scope violation or unsupported tool. Raise structured error.
            await self._emit_tool_invoked(tool_id, started, success=False, error_code="SCOPE_VIOLATION")
            detail = _safe_json(resp)
            raise ScopeViolation(
                url=str(detail.get("url") or request.get("url") or ""),
                authorized_scope=self._scope_patterns,
            )
        if resp.status_code == 409:
            self._cancelled = True
            # Don't emit tool_invoked on supersede — the event stream for this
            # attempt is already being ignored.
            raise StageSuperseded("stage attempt superseded during tool call")
        if resp.status_code >= 500:
            await self._emit_tool_invoked(tool_id, started, success=False, error_code="TOOL_UNAVAILABLE")
            raise ToolUnavailable(f"tool {tool_id!r} returned {resp.status_code}")
        if resp.status_code >= 400:
            await self._emit_tool_invoked(tool_id, started, success=False, error_code="TOOL_UNAVAILABLE")
            raise ToolUnavailable(
                f"tool {tool_id!r} returned {resp.status_code}: {resp.text[:200]}"
            )

        self._tool_call_count += 1
        data = resp.json()
        await self._emit_tool_invoked(tool_id, started, success=True, error_code=None)
        return data.get("result", data) if isinstance(data, dict) else data

    async def _emit_tool_invoked(
        self,
        tool_id: str,
        started_monotonic: float,
        *,
        success: bool,
        error_code: str | None,
    ) -> None:
        """SDK-auto emission of `tool_invoked` (spec §7.2)."""
        import time as _time

        duration_ms = int((_time.monotonic() - started_monotonic) * 1000)
        payload = ToolInvokedPayload(
            tool_id=tool_id,
            duration_ms=duration_ms,
            success=success,
            error_code=error_code,
        ).model_dump()
        try:
            await self._emit_internal_event(EventKind.TOOL_INVOKED, payload)
        except Exception as exc:
            # Never let an event emit failure mask a tool error — just log.
            logger.debug("tool_invoked emit failed (non-fatal): %s", exc)

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: Any = None,
        timeout_s: float = 30.0,
    ) -> HttpFetchResult:
        """HTTP fetch against target. The ONLY legal way for an engine to
        make outbound HTTP requests (see spec §5.2 R6).

        SDK pre-validates the URL against authorized_scope and fails fast with
        ScopeViolation; also emits a `tool_invoked` event via the built-in
        `http_fetch` tool route.
        """
        if not self._host_in_scope(url):
            raise ScopeViolation(url=url, authorized_scope=self._scope_patterns)

        req = HttpFetchRequest(
            url=url,
            method=method,  # type: ignore[arg-type]
            headers=headers or {},
            body=body,
        )
        try:
            result_dict = await self.call_tool(
                "http_fetch", req.model_dump(mode="json"), timeout_s=timeout_s
            )
        except ToolUnavailable as exc:
            raise TargetUnreachable(f"http_fetch to {url}: {exc}") from exc
        return HttpFetchResult.model_validate(result_dict)

    # ---------- artifacts ----------

    async def save_artifact(
        self,
        name: str,
        data: bytes,
        *,
        kind: ArtifactKind,
        mime_type: str = "application/octet-stream",
    ) -> ArtifactRef:
        """Upload an artifact via the orchestrator's artifact endpoint. Returns
        an ArtifactRef tagged with (run_id, stage, stage_attempt_id) so retry
        semantics stay correct (see spec §7.5.5).

        0.1-alpha implementation: HTTP multipart to `{tools_url}/_artifact/put`.
        0.1-beta may switch to presigned MinIO PUT for large blobs.
        """
        url = f"{self._callbacks.tools_url.rstrip('/')}/_artifact/put"
        try:
            resp = await self._http.post(
                url,
                headers={"X-Callback-Token": self._callbacks.token},
                files={"file": (name, data, mime_type)},
                data={
                    "run_id": self.run_id,
                    "stage": self.stage,
                    "stage_attempt_id": self.stage_attempt_id,
                    "kind": kind,
                    "name": name,
                },
                timeout=60.0,
            )
        except httpx.HTTPError as exc:
            raise ToolUnavailable(f"artifact upload failed: {exc}") from exc

        if resp.status_code == 401:
            raise CallbackAuthzFailed(
                "callback token rejected by orchestrator on artifact upload"
            )
        if resp.status_code == 409:
            self._cancelled = True
            raise StageSuperseded("stage attempt superseded during artifact save")
        if resp.status_code >= 400:
            raise ToolUnavailable(
                f"artifact upload returned {resp.status_code}: {resp.text[:200]}"
            )

        ref = ArtifactRef.model_validate(resp.json())
        self._artifact_refs.append(ref)
        return ref

    # ---------- cancellation / deadline ----------

    def time_remaining(self) -> float:
        """Seconds until deadline. Negative = already past deadline."""
        return (self.deadline - datetime.now(timezone.utc)).total_seconds()

    async def check_cancelled(self) -> bool:
        """True if orchestrator has asked this attempt to stop (e.g. superseded).

        0.1-alpha: checks a local flag set by callbacks that returned 409.
        0.1-beta may add active polling against /runs/{id}/attempts/{sa_id}.
        """
        await asyncio.sleep(0)  # cooperative yield
        return self._cancelled

    # ---------- internals used by EngineApp ----------

    def _drain_findings(self) -> list[FindingCandidate]:
        """Called by EngineApp after run() returns. Converts accumulated
        Drafts into wire-form Candidates (signatures computed, target_id
        resolved, evidence passed through). Drafts are cleared so the ctx
        can't leak them into a later call.

        Target resolution rules (spec §2.3 + multi-target correctness):
            * Draft has target_id set → use as-is
            * Draft has target_id=None and ctx.targets has EXACTLY ONE target
              → auto-fill from that target
            * Draft has target_id=None and ctx.targets is empty or has >1
              → raise; ambiguous assignment would silently mis-attribute
                findings and corrupt the dedup key
        """
        out: list[FindingCandidate] = []
        for draft in self._finding_drafts:
            resolved_target_id = self._resolve_draft_target_id(draft)
            sig = compute_signature(draft.vuln_type, draft.signature_evidence)
            out.append(
                FindingCandidate(
                    vuln_type=draft.vuln_type,
                    severity=draft.severity,
                    confidence=draft.confidence,
                    target_id=resolved_target_id,
                    location_signature=sig,
                    signature_evidence=draft.signature_evidence,
                    evidence_artifact_refs=draft.evidence_artifact_refs,
                    cwe=draft.cwe,
                    cvss_score=draft.cvss_score,
                    cvss_vector=draft.cvss_vector,
                    owasp_category=draft.owasp_category,
                    affected_endpoint=draft.affected_endpoint,
                    affected_parameter=draft.affected_parameter,
                    remediation=draft.remediation,
                    references=draft.references,
                )
            )
        self._finding_drafts = []
        return out

    def _resolve_draft_target_id(self, draft: FindingCandidateDraft) -> str:
        if draft.target_id:
            # Optional sanity: if the engine named a target, it should be one
            # of the Run's targets. Log rather than reject (engines may
            # legitimately track discovered sub-targets — future 0.2 feature).
            if self.targets and not any(t.id == draft.target_id for t in self.targets):
                logger.warning(
                    "finding draft target_id=%r not in ctx.targets %s",
                    draft.target_id,
                    [t.id for t in self.targets],
                )
            return draft.target_id
        if len(self.targets) == 1:
            return self.targets[0].id
        # Empty or ambiguous — refuse silently-wrong behavior.
        raise ValueError(
            f"FindingCandidateDraft.target_id is required when ctx.targets has "
            f"{len(self.targets)} entries (must name which target this finding "
            f"belongs to). Set draft.target_id explicitly."
        )

    def _drain_artifacts(self) -> list[ArtifactRef]:
        refs = self._artifact_refs
        self._artifact_refs = []
        return refs

    def _current_metrics(self) -> EngineMetrics:
        return EngineMetrics(
            llm_tokens_input=self.llm.total_input_tokens,
            llm_tokens_output=self.llm.total_output_tokens,
            llm_cost_usd=self.llm.total_cost_usd,
            tool_calls_total=self._tool_call_count,
            duration_ms=0,  # filled by EngineApp on exit
        )

    # ---------- helpers ----------

    def _host_in_scope(self, url: str) -> bool:
        """Thin wrapper around contracts.url_in_scope so SDK and core use the
        SAME matcher — avoids client/server divergence (see spec §8.1.1)."""
        return url_in_scope(url, self._scope_patterns)

    def _scrub(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Walk payload; replace secret-like strings with [REDACTED].

        Also substitutes any *known* secret value from the whitelist (exact
        match), since engine might accidentally include a declared secret in
        an event field.
        """
        declared_values = self.secrets._values()
        return _scrub_value(payload, declared_values)  # type: ignore[return-value]


# -------------- module helpers (not on class) --------------


def _scrub_value(value: Any, declared_values: frozenset[str]) -> Any:
    if isinstance(value, str):
        # Exact-match known secret values first (cheap).
        for v in declared_values:
            if v and v in value:
                value = value.replace(v, "[REDACTED]")
        # Pattern-based fallback.
        for pat in _SECRET_PATTERNS:
            value = pat.sub("[REDACTED]", value)
        return value
    if isinstance(value, dict):
        return {k: _scrub_value(v, declared_values) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_value(v, declared_values) for v in value]
    return value


def _safe_json(resp: httpx.Response) -> dict[str, Any]:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}
