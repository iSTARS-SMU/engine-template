"""Fixture-driven LLM responses for zero-cost demo runs.

Designed for the dev_pipeline.py "demo" path: when env var
`TRUSTCHAIN_FIXTURE_DIR` points at a directory of curated responses
(e.g. `trustchain/fixtures/juice-shop/`), all `ctx.llm.chat()` calls
across all 5 example engines route to the matching fixture file
instead of a real provider call.

Lookup convention:

    purpose=<name>                 → <FIXTURE_DIR>/<name>.{txt,json}

If both extensions exist, .json wins (engines that expect structured
output read JSON; free-text responses use .txt).

If a purpose has no matching file, the interceptor logs a warning and
falls through to the wrapped real client. Engines with required-secret
"openai" still need OPENAI_API_KEY in env (any value works — the real
provider is never actually called when fixtures cover all purposes).

Why a separate module (not inline in dev_pipeline):

    1. dev_pipeline.py lives in engine-template/, which is a student-
       facing scaffold. Fixture support is a platform feature → SDK.
    2. Future UI / core-side "demo run" can install the same hook via
       a clean SDK import.

Install via `install_fixture_hook(ctx, fixture_dir)` after RunContext
construction but before engine.run() is called. The hook persists for
the rest of the ctx's lifetime (one Run).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from .llm import LLMClient, LLMResult

logger = logging.getLogger(__name__)


_PURPOSE_FILE_EXTS = (".json", ".txt")


_ORIGINAL_CHAT = None  # set by install_fixture_hook on first call


def install_fixture_hook(fixture_dir: str | Path) -> None:
    """Class-level monkey-patch of `LLMClient.chat`. Affects every
    LLMClient instance constructed from this point forward — so every
    engine in a DevHarness pipeline gets fixture routing without any
    per-engine wiring.

    Why class-level not instance-level: DevHarness calls
    ``engine.invoke(envelope)`` which constructs RunContext (and its
    LLMClient) inside the engine. A caller can't reach ctx.llm before
    the run starts. Patching the class method lets the fixture take
    effect inside engine.run() transparently.

    Idempotent: re-installation reuses the same wrapped function.
    Use ``uninstall_fixture_hook()`` to revert (mostly for tests).
    """
    global _ORIGINAL_CHAT
    fixture_dir = Path(fixture_dir).resolve()
    if not fixture_dir.is_dir():
        raise FileNotFoundError(f"fixture dir not found: {fixture_dir}")

    if _ORIGINAL_CHAT is not None:
        logger.debug("fixture hook already installed; skipping")
        return

    _ORIGINAL_CHAT = LLMClient.chat

    async def fixture_chat(
        self: LLMClient,
        messages: list[dict[str, Any]],
        *,
        model: str | None = None,
        temperature: float | None = None,
        purpose: str | None = None,
    ) -> LLMResult:
        if purpose:
            content = _load_fixture(fixture_dir, purpose)
            if content is not None:
                # Track as a "0-cost LLM" hit so engines that gate on
                # ctx.llm.total_calls (e.g. "did the LLM run?") see it.
                self.total_calls += 1
                logger.info(
                    "fixture hit: purpose=%s → %d chars", purpose, len(content)
                )
                model_name = (
                    self._config.default_model
                    if self._config and self._config.default_model
                    else "fixture"
                )
                return LLMResult(
                    content=content,
                    input_tokens=0,
                    output_tokens=len(content) // 4,
                    cost_usd=0.0,
                    model=model_name,
                    provider="fixture",
                    finish_reason="stop",
                )
            logger.warning(
                "fixture miss: no file for purpose=%s in %s; falling through to real LLM",
                purpose,
                fixture_dir,
            )
        return await _ORIGINAL_CHAT(
            self, messages, model=model, temperature=temperature, purpose=purpose
        )

    LLMClient.chat = fixture_chat  # type: ignore[method-assign]
    logger.info("class-level fixture hook installed; dir=%s", fixture_dir)


def uninstall_fixture_hook() -> None:
    """Revert install_fixture_hook. Mostly for unit tests that want to
    isolate fixture state. No-op if hook not installed."""
    global _ORIGINAL_CHAT
    if _ORIGINAL_CHAT is None:
        return
    LLMClient.chat = _ORIGINAL_CHAT  # type: ignore[method-assign]
    _ORIGINAL_CHAT = None
    logger.info("fixture hook uninstalled")


def install_fixture_hook_from_env() -> bool:
    """Convenience: read TRUSTCHAIN_FIXTURE_DIR + install if set.
    Returns True if installed, False if env not set."""
    raw = os.environ.get("TRUSTCHAIN_FIXTURE_DIR")
    if not raw:
        return False
    install_fixture_hook(raw)
    return True


def _load_fixture(fixture_dir: Path, purpose: str) -> str | None:
    """Look for <purpose>.json then <purpose>.txt in fixture_dir.
    Return file content as string (json gets minified), or None on miss."""
    for ext in _PURPOSE_FILE_EXTS:
        path = fixture_dir / f"{purpose}{ext}"
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            if ext == ".json":
                # Round-trip through json.loads/dumps to (a) validate it
                # parses and (b) emit a stable single-line form so engines
                # with strict regex parsers see canonical JSON.
                try:
                    parsed = json.loads(text)
                    return json.dumps(parsed, ensure_ascii=False)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "fixture %s is not valid JSON: %s; returning raw text",
                        path,
                        exc,
                    )
            return text
    return None
