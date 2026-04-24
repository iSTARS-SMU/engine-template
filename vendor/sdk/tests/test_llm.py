"""Tests for LLMClient — provider routing, excerpt / metrics, NotImplemented paths.

Real-provider happy path (calling OpenAI) isn't tested here — the openai
SDK is an opaque dependency we don't want to mock at a low level in unit
tests. Integration tests covering real API calls would live elsewhere.

What IS tested here:
  * uses_llm=True + config=None → LLMConfigMissing at construction
  * uses_llm=False + chat() called → RuntimeError (misconfig surfaces early)
  * Provider dispatch: anthropic / unknown → NotImplementedError for alpha
  * Default model/temperature resolution from LLMConfig
  * Metrics accumulation across multiple chat() calls
  * llm_call event payload shape (excerpt truncation + hash suffix)
  * Cost estimate math for the pricing table
"""

from __future__ import annotations

import hashlib

import pytest
from trustchain_contracts import LLMConfig

from trustchain_sdk._errors import LLMConfigMissing
from trustchain_sdk.llm import LLMClient, _estimate_openai_cost, _excerpt, _flatten_messages
from trustchain_sdk.secrets import SecretsProxy


# ============================================================
# Helpers
# ============================================================


def _make_client(
    *,
    uses_llm: bool = True,
    provider: str = "openai",
    model: str = "gpt-4o",
    temperature: float = 0.2,
    secrets: dict[str, str] | None = None,
) -> tuple[LLMClient, list]:
    """Build a client and an event-sink list. The sink collects (kind, payload)
    tuples emitted by the client."""
    events: list = []

    async def sink(kind, payload):
        events.append((kind, payload))

    proxy = SecretsProxy(
        raw=secrets or {"openai": "sk-test"},
        allowed={"openai", "anthropic"},
    )
    client = LLMClient(
        config=LLMConfig(provider=provider, default_model=model, default_temperature=temperature)
        if uses_llm
        else None,
        uses_llm=uses_llm,
        secrets=proxy,
        emit_event=sink,
    )
    return client, events


# ============================================================
# Construction-time validation
# ============================================================


def test_uses_llm_true_without_config_raises_llm_config_missing():
    """The whole point of the check: engine.yaml says uses_llm=true but
    envelope lacked llm_config. Fail at construction so the error maps to
    LLM_CONFIG_MISSING in invoke()."""

    async def noop(*a, **k):
        pass

    proxy = SecretsProxy(raw={}, allowed=set())
    with pytest.raises(LLMConfigMissing):
        LLMClient(config=None, uses_llm=True, secrets=proxy, emit_event=noop)


def test_uses_llm_false_with_no_config_is_ok():
    """If the engine declares uses_llm=false, we don't need a config — ctx.llm
    exists but chat() refuses to run."""

    async def noop(*a, **k):
        pass

    proxy = SecretsProxy(raw={}, allowed=set())
    # Must NOT raise.
    LLMClient(config=None, uses_llm=False, secrets=proxy, emit_event=noop)


# ============================================================
# Runtime refusals
# ============================================================


@pytest.mark.asyncio
async def test_chat_on_non_llm_engine_raises_runtime_error():
    """Engine.yaml capabilities.uses_llm=false → ctx.llm.chat() must refuse.
    Prevents an engine from sneakily bypassing the capability declaration."""
    client, _ = _make_client(uses_llm=False)
    # Need to override config=None from _make_client's helper for uses_llm=False
    # — actually helper already passes config=None when uses_llm=False.

    with pytest.raises(RuntimeError, match="uses_llm=false"):
        await client.chat([{"role": "user", "content": "hi"}])


@pytest.mark.asyncio
async def test_chat_with_anthropic_raises_not_implemented_in_alpha():
    """Anthropic adapter is Should-for-0.1-final per spec §11. Today's SDK
    must refuse rather than silently skip the call."""
    client, _ = _make_client(provider="anthropic")
    with pytest.raises(NotImplementedError, match="Anthropic"):
        await client.chat([{"role": "user", "content": "hi"}])


@pytest.mark.asyncio
async def test_chat_with_unknown_provider_raises_not_implemented():
    client, _ = _make_client(provider="gemini")
    with pytest.raises(NotImplementedError):
        await client.chat([{"role": "user", "content": "hi"}])


# ============================================================
# Provider routing — openai adapter exercised via MockLLMClient
# ============================================================


@pytest.mark.asyncio
async def test_openai_adapter_routing_via_mock_subclass():
    """The real openai SDK is opaque in unit tests. _MockLLMClient (used by
    MockContext) subclasses LLMClient and overrides _call_openai. We exercise
    it here to verify the base class's chat() flow — metrics accumulation
    and event emission — without a real network call."""
    from trustchain_sdk.testing import _MockLLMClient  # test-only subclass

    events: list = []

    async def sink(kind, payload):
        events.append((kind, payload))

    proxy = SecretsProxy(raw={"openai": "sk-test"}, allowed={"openai"})
    client = _MockLLMClient(
        config=LLMConfig(provider="openai", default_model="gpt-4o"),
        uses_llm=True,
        secrets=proxy,
        emit_event=sink,
    )
    client.queue("response one")

    result = await client.chat([{"role": "user", "content": "hello"}], purpose="recon")
    assert result.content == "response one"
    assert result.model == "gpt-4o"

    # Metrics accumulated.
    assert client.total_calls == 1
    assert client.total_output_tokens > 0

    # llm_call event emitted.
    llm_events = [e for e in events if e[0].value == "llm_call"]
    assert len(llm_events) == 1
    payload = llm_events[0][1]
    assert payload["provider"] == "openai"
    assert payload["model"] == "gpt-4o"
    assert payload["purpose"] == "recon"


# ============================================================
# Default model / temperature resolution
# ============================================================


@pytest.mark.asyncio
async def test_default_model_used_when_chat_does_not_override():
    """If engine calls chat() without model= kwarg, LLMClient uses
    config.default_model. Tests rely on this so contract tests don't have
    to thread model names through."""
    from trustchain_sdk.testing import _MockLLMClient

    events: list = []

    async def sink(kind, payload):
        events.append((kind, payload))

    proxy = SecretsProxy(raw={"openai": "x"}, allowed={"openai"})
    client = _MockLLMClient(
        config=LLMConfig(provider="openai", default_model="gpt-4o-mini", default_temperature=0.5),
        uses_llm=True,
        secrets=proxy,
        emit_event=sink,
    )
    client.queue("ok")

    result = await client.chat([{"role": "user", "content": "x"}])
    assert result.model == "gpt-4o-mini"


@pytest.mark.asyncio
async def test_chat_override_beats_config_default():
    """Engine can override per-call — e.g. use a cheaper model for a simple
    step. Per-call kwargs win over config default."""
    from trustchain_sdk.testing import _MockLLMClient

    async def sink(kind, payload):
        pass

    proxy = SecretsProxy(raw={"openai": "x"}, allowed={"openai"})
    client = _MockLLMClient(
        config=LLMConfig(provider="openai", default_model="gpt-4o"),
        uses_llm=True,
        secrets=proxy,
        emit_event=sink,
    )
    client.queue("ok")

    result = await client.chat(
        [{"role": "user", "content": "x"}],
        model="gpt-4o-mini",  # override
    )
    assert result.model == "gpt-4o-mini"


# ============================================================
# Metrics accumulation
# ============================================================


@pytest.mark.asyncio
async def test_metrics_accumulate_across_multiple_calls():
    from trustchain_sdk.testing import _MockLLMClient

    async def sink(kind, payload):
        pass

    proxy = SecretsProxy(raw={"openai": "x"}, allowed={"openai"})
    client = _MockLLMClient(
        config=LLMConfig(provider="openai", default_model="gpt-4o"),
        uses_llm=True,
        secrets=proxy,
        emit_event=sink,
    )
    client.set_default("hello")

    # MockLLMClient approximates input_tokens as len(content)//4, so we
    # need prompts long enough to round up above zero.
    prompt = "this is a prompt long enough to produce nonzero token count"
    await client.chat([{"role": "user", "content": prompt}])
    await client.chat([{"role": "user", "content": prompt}])
    await client.chat([{"role": "user", "content": prompt}])

    assert client.total_calls == 3
    # Total tokens strictly positive and summed.
    assert client.total_input_tokens > 0
    assert client.total_output_tokens > 0


# ============================================================
# Excerpt + hash — privacy guarantee on event payloads
# ============================================================


class TestExcerpt:
    def test_short_text_unmodified(self):
        assert _excerpt("short") == "short"

    def test_long_text_truncated_with_sha_suffix(self):
        """Over 200 chars: keep first 200, append [...; sha256:HEX] so audit
        can correlate with the full artifact (saved separately) without
        putting the full content on the event stream."""
        text = "a" * 500
        ex = _excerpt(text, max_chars=200)
        # First 200 chars present.
        assert ex.startswith("a" * 200)
        # Truncation marker + short sha prefix of the full text.
        expected_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        assert expected_sha in ex
        assert "truncated" in ex

    def test_excerpt_boundary_exactly_max(self):
        """Text exactly at boundary — should be returned unmodified."""
        text = "a" * 200
        assert _excerpt(text, max_chars=200) == text


class TestFlattenMessages:
    def test_flatten_simple_messages(self):
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hello"},
        ]
        flat = _flatten_messages(msgs)
        assert "system" in flat
        assert "user" in flat
        assert "hello" in flat

    def test_flatten_multipart_content(self):
        """OpenAI vision-style messages with list content — we flatten only
        the text parts into the excerpt."""
        msgs = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "describe this"},
                    {"type": "image_url", "image_url": {"url": "..."}},
                ],
            }
        ]
        flat = _flatten_messages(msgs)
        assert "describe this" in flat


# ============================================================
# Cost estimate
# ============================================================


class TestOpenAICostEstimate:
    def test_known_model_gpt4o(self):
        """gpt-4o pricing (per the local pricing table): 2.50/1M input,
        10.00/1M output. 1M input tokens → $2.50."""
        assert _estimate_openai_cost("gpt-4o", 1_000_000, 0) == pytest.approx(2.50)
        assert _estimate_openai_cost("gpt-4o", 0, 1_000_000) == pytest.approx(10.00)

    def test_known_model_gpt4o_mini(self):
        """gpt-4o-mini: 0.15/1M input, 0.60/1M output."""
        assert _estimate_openai_cost("gpt-4o-mini", 1_000_000, 0) == pytest.approx(0.15)
        assert _estimate_openai_cost("gpt-4o-mini", 0, 1_000_000) == pytest.approx(0.60)

    def test_unknown_model_returns_zero(self):
        """No entry → 0, not crash. Pricing is a nice-to-have display value,
        not a billing mechanism."""
        assert _estimate_openai_cost("not-a-real-model", 100, 100) == 0.0

    def test_small_call_cost_proportional(self):
        """1000 input tokens with gpt-4o: 1000/1M * 2.50 = $0.0025"""
        cost = _estimate_openai_cost("gpt-4o", 1000, 0)
        assert cost == pytest.approx(0.0025)


# ============================================================
# Event payload — prompt excerpt included
# ============================================================


@pytest.mark.asyncio
async def test_llm_call_event_carries_excerpt_not_full_prompt():
    """Privacy: event payload must carry a 200-char excerpt, not the full
    prompt — full goes elsewhere if at all. This is spec §8.5 (artifact
    sensitive data) applied to LLM prompts."""
    from trustchain_sdk.testing import _MockLLMClient

    events: list = []

    async def sink(kind, payload):
        events.append((kind, payload))

    proxy = SecretsProxy(raw={"openai": "x"}, allowed={"openai"})
    client = _MockLLMClient(
        config=LLMConfig(provider="openai", default_model="gpt-4o"),
        uses_llm=True,
        secrets=proxy,
        emit_event=sink,
    )
    client.queue("resp")

    long_prompt = "SENSITIVE " * 200  # ~1800 chars
    await client.chat([{"role": "user", "content": long_prompt}])

    llm_evt = [e for e in events if e[0].value == "llm_call"][0][1]
    excerpt = llm_evt["prompt_excerpt"]
    # Full prompt must NOT be on the event stream in full.
    assert len(excerpt) < len(long_prompt)
    # Excerpt contains the truncation suffix.
    assert "truncated" in excerpt
