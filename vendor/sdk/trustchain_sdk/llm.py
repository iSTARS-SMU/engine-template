"""
LLMClient — unified LLM entry point for engine code.

Usage in engine.run():
    result = await ctx.llm.chat(
        messages=[{"role": "user", "content": "..."}],
        purpose="attack_plan_synthesis",
    )
    plan = result.content

Provider is chosen from Task-level LLMConfig (envelope.llm_config). Engine does
NOT pick provider or model; it asks for them only when overriding per-call.

0.1-alpha supports:
    openai  — requires ``pip install openai``
    others  — NotImplementedError (Anthropic is 0.1-final Should per spec §11)
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from trustchain_contracts import (
    EventKind,
    LLMCallPayload,
    LLMConfig,
)

from ._errors import LLMConfigMissing, LLMUnavailable, StageSuperseded
from .secrets import SecretsProxy

# Rough per-1M-token pricing for cost estimate. Source of truth is dev docs;
# these are approximations for Run cost display. Kept liberal — users see "≈$X".
_OPENAI_PRICING_PER_1M = {
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
}


@dataclass
class LLMResult:
    content: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    model: str
    provider: str
    finish_reason: str | None = None


# Type of the event-emitter callback the LLMClient uses. Kept as a callable so
# LLMClient doesn't need a full RunContext reference (avoids circular imports
# with context.py).
EventEmitter = Callable[[EventKind, dict[str, Any]], Awaitable[None]]


class LLMClient:
    """Shared by all engines. Always instantiated per-invoke via RunContext.

    Responsibilities:
        * Validate envelope.llm_config presence when engine declares uses_llm
        * Route to the configured provider adapter
        * Emit an `llm_call` event for every chat() call (with redacted excerpts)
        * Track cumulative metrics for EngineResult.metrics
    """

    def __init__(
        self,
        *,
        config: LLMConfig | None,
        uses_llm: bool,
        secrets: SecretsProxy,
        emit_event: EventEmitter,
    ) -> None:
        if uses_llm and config is None:
            raise LLMConfigMissing(
                "engine.yaml capabilities.uses_llm=true but envelope.llm_config is None"
            )
        self._config = config
        self._uses_llm = uses_llm
        self._secrets = secrets
        self._emit_event = emit_event

        # Cumulative metrics (read by RunContext.metrics for EngineResult)
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost_usd = 0.0
        self.total_calls = 0

    async def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str | None = None,
        temperature: float | None = None,
        purpose: str | None = None,
    ) -> LLMResult:
        """Send a chat completion. Auto-emits llm_call event.

        `purpose` is a free-form tag for cost attribution (shown in UI event
        stream). Example: "recon_stack_detection", "exploit_script_synthesis".
        """

        if not self._uses_llm:
            raise RuntimeError(
                "LLMClient.chat() called but engine.yaml capabilities.uses_llm=false; "
                "declare uses_llm=true to enable LLM access"
            )
        assert self._config is not None  # narrowed by uses_llm check

        resolved_model = model or self._config.default_model
        resolved_temp = (
            temperature if temperature is not None else self._config.default_temperature
        )
        provider = self._config.provider.lower()

        start = time.monotonic()
        try:
            if provider == "openai":
                result = await self._call_openai(messages, resolved_model, resolved_temp)
            elif provider == "anthropic":
                raise NotImplementedError(
                    "Anthropic adapter is Should for 0.1-final (see spec §11); "
                    "0.1-alpha only ships OpenAI."
                )
            else:
                raise NotImplementedError(
                    f"LLM provider {provider!r} is not supported in 0.1-alpha"
                )
        except LLMUnavailable:
            raise
        except NotImplementedError:
            raise
        except StageSuperseded:
            # Cancellation MUST propagate — wrapping it as LLMUnavailable would
            # let engines swallow it via their soft-fail catch and continue
            # burning more LLM calls after the user clicked Cancel.
            raise
        except (KeyboardInterrupt, asyncio.CancelledError):
            raise
        except Exception as exc:
            raise LLMUnavailable(f"LLM call failed: {exc}") from exc

        duration_ms = int((time.monotonic() - start) * 1000)

        # Update cumulative metrics
        self.total_input_tokens += result.input_tokens
        self.total_output_tokens += result.output_tokens
        self.total_cost_usd += result.cost_usd
        self.total_calls += 1

        # Emit event (preview-only payload; full content never on the wire)
        await self._emit_call_event(messages, result, purpose, duration_ms)
        return result

    # --- Provider adapters ----------------------------------------------

    async def _call_openai(
        self, messages: list[dict[str, Any]], model: str, temperature: float
    ) -> LLMResult:
        try:
            from openai import AsyncOpenAI  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "OpenAI provider requires the 'openai' package. "
                "Install with: pip install 'trustchain-sdk[openai]'"
            ) from exc

        api_key = self._secrets.openai  # SecretNotDeclared / SecretMissing bubble up

        client = AsyncOpenAI(api_key=api_key)
        response = await client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
        )

        choice = response.choices[0]
        usage = response.usage
        input_tokens = usage.prompt_tokens if usage else 0
        output_tokens = usage.completion_tokens if usage else 0

        return LLMResult(
            content=choice.message.content or "",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=_estimate_openai_cost(model, input_tokens, output_tokens),
            model=model,
            provider="openai",
            finish_reason=choice.finish_reason,
        )

    # --- Event emission -------------------------------------------------

    async def _emit_call_event(
        self,
        messages: list[dict[str, Any]],
        result: LLMResult,
        purpose: str | None,
        duration_ms: int,
    ) -> None:
        """Emit `llm_call` with redacted excerpts.

        Design: don't put the full prompt or response on the event stream
        (could leak data through UI / audit). Put the first 200 chars and a
        sha256 of the full payload so engineers can correlate with the full
        artifact (if saved).
        """
        _ = duration_ms  # reserved for future emit if needed

        prompt_text = _flatten_messages(messages)
        prompt_excerpt = _excerpt(prompt_text)
        response_excerpt = _excerpt(result.content)

        payload = LLMCallPayload(
            provider=result.provider,
            model=result.model,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cost_usd=result.cost_usd,
            purpose=purpose,
            prompt_excerpt=prompt_excerpt,
            response_excerpt=response_excerpt,
        )
        await self._emit_event(EventKind.LLM_CALL, payload.model_dump())


# ---- helpers ---------------------------------------------------------


def _flatten_messages(messages: list[dict[str, Any]]) -> str:
    """Turn OpenAI-style messages into a plain string for excerpting."""
    parts: list[str] = []
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if isinstance(content, list):
            # Multi-part content; flatten text parts.
            content = " ".join(
                part.get("text", "") for part in content if part.get("type") == "text"
            )
        parts.append(f"{role}: {content}")
    return "\n".join(parts)


def _excerpt(text: str, max_chars: int = 200) -> str:
    """First N chars + sha256 of the full text — helps correlate with stored artifacts."""
    if len(text) <= max_chars:
        return text
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return f"{text[:max_chars]}...[truncated; sha256:{digest}]"


def _estimate_openai_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Rough cost estimate. Real billing should come from the provider bill, not this."""
    pricing = _OPENAI_PRICING_PER_1M.get(model)
    if pricing is None:
        return 0.0
    in_rate, out_rate = pricing
    return (input_tokens * in_rate + output_tokens * out_rate) / 1_000_000
