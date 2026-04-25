"""
trustchain-sdk — Python SDK for TrustChain Pentest engines.

Quick start:

    from trustchain_sdk import EngineApp, RunContext
    from trustchain_contracts import Capabilities, SecretRequirement

    class MyEngine(EngineApp):
        engine_id = "my-engine"
        version = "0.1.0"
        stage = "recon"
        capabilities = Capabilities(uses_llm=False)

        async def run(self, ctx: RunContext, config: dict):
            await ctx.emit_event("progress", {"percentage": 50})
            return {"status": "ok"}

    app = MyEngine().build_app()    # FastAPI

See doc/engine-author-guide.md and doc/engine-contract.md.
"""

__version__ = "0.1.0"

from ._errors import (
    CallbackAuthzFailed,
    ConfigInvalid,
    ContextInvalid,
    DeadlineExceeded,
    LLMConfigMissing,
    LLMUnavailable,
    ScopeViolation,
    SecretMissing,
    SecretNotDeclared,
    StageSuperseded,
    TargetUnreachable,
    ToolUnavailable,
    TrustchainSDKError,
)
from .context import RunContext
from .engine import EngineApp
from .fixture_llm import install_fixture_hook, install_fixture_hook_from_env
from .llm import LLMClient, LLMResult
from .secrets import SecretsProxy

__all__ = [
    # Core
    "EngineApp",
    "RunContext",
    "SecretsProxy",
    "LLMClient",
    "LLMResult",
    # Errors
    "TrustchainSDKError",
    "CallbackAuthzFailed",
    "ConfigInvalid",
    "ContextInvalid",
    "DeadlineExceeded",
    "LLMConfigMissing",
    "LLMUnavailable",
    "ScopeViolation",
    "SecretMissing",
    "SecretNotDeclared",
    "StageSuperseded",
    "TargetUnreachable",
    "ToolUnavailable",
    # Version
    "__version__",
]
