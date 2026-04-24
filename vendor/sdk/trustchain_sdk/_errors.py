"""SDK-defined exceptions.

Engine code catches these for specific recovery. Anything else → INTERNAL_ERROR.
"""

from trustchain_contracts import ErrorCode


class TrustchainSDKError(Exception):
    """Base for all SDK errors."""

    error_code: ErrorCode = ErrorCode.INTERNAL_ERROR


class CallbackAuthzFailed(TrustchainSDKError):
    """Orchestrator rejected a callback (event / tool / artifact) with 401.
    Usually bad ``callbacks.token`` on the envelope, or the attempt rotated.
    Not retryable from engine side."""

    error_code = ErrorCode.AUTHZ_FAILED


class SecretMissing(TrustchainSDKError):
    """Engine code accessed a secret that was declared in engine.yaml but not
    provided by the envelope. Usually orchestrator's fault; not retryable by
    engine."""

    error_code = ErrorCode.SECRET_MISSING


class SecretNotDeclared(TrustchainSDKError, AttributeError):
    """Engine code accessed a secret that wasn't declared in engine.yaml.
    Developer bug. Shows up as AttributeError for idiomatic handling."""


class LLMConfigMissing(TrustchainSDKError):
    """engine.yaml capabilities.uses_llm=true but envelope had no llm_config."""

    error_code = ErrorCode.LLM_CONFIG_MISSING


class ScopeViolation(TrustchainSDKError):
    """Engine tried to reach a host outside its targets' authorized_scope.
    Hard-fail; never retryable."""

    error_code = ErrorCode.SCOPE_VIOLATION

    def __init__(self, url: str, authorized_scope: list[str]):
        super().__init__(
            f"URL {url!r} is outside authorized_scope {sorted(authorized_scope)}"
        )
        self.url = url
        self.authorized_scope = authorized_scope


class ConfigInvalid(TrustchainSDKError):
    """Config didn't validate against engine.yaml config_schema."""

    error_code = ErrorCode.CONFIG_INVALID


class ContextInvalid(TrustchainSDKError):
    """Upstream outputs missing or malformed."""

    error_code = ErrorCode.CONTEXT_INVALID


class DeadlineExceeded(TrustchainSDKError):
    """Engine wall-clock exceeded envelope.deadline."""

    error_code = ErrorCode.DEADLINE_EXCEEDED


class StageSuperseded(TrustchainSDKError):
    """Orchestrator returned 409 on an event/tool callback — means this
    stage_attempt was already superseded by a newer attempt. Engine should
    wind down cleanly."""

    error_code = ErrorCode.STAGE_SUPERSEDED


class ToolUnavailable(TrustchainSDKError):
    error_code = ErrorCode.TOOL_UNAVAILABLE


class LLMUnavailable(TrustchainSDKError):
    error_code = ErrorCode.LLM_UNAVAILABLE


class TargetUnreachable(TrustchainSDKError):
    error_code = ErrorCode.TARGET_UNREACHABLE
