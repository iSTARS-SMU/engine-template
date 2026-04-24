"""
SecretsProxy — per-invoke, attribute-based, whitelist-enforced access to
secrets provided in RunContextEnvelope.secrets.

Implementation note: this is NOT static-typed ("typed" in the TypeScript sense).
It's runtime ``__getattr__`` + a whitelist derived from engine.yaml
``secret_requirements``. IDE autocomplete will NOT work on ``ctx.secrets.*`` —
that's the 0.1 tradeoff for zero codegen. 0.2 may add a scaffold-time ``.pyi``
stub generator if teams want it (see spec §6.2).

Per-invoke lifecycle:
    1. /invoke request arrives with envelope.secrets (raw dict from orchestrator)
    2. SDK builds a SecretsProxy filtered by the engine's declared whitelist
    3. Proxy is attached to RunContext as ctx.secrets for that invocation
    4. When run() returns, the proxy is discarded — no cross-invoke leakage
"""

from ._errors import SecretMissing, SecretNotDeclared


class SecretsProxy:
    """Attribute-based, whitelist-enforced secret access.

    Construction:
        proxy = SecretsProxy(
            raw={"openai": "sk-...", "exa": "exa-...", "stripe": "..."},
            allowed={"openai", "exa"},    # from engine.yaml secret_requirements
        )
        proxy.openai   # returns "sk-..."
        proxy.exa      # returns "exa-..."
        proxy.stripe   # raises SecretNotDeclared (not in allowed)
        proxy.gemini   # raises SecretNotDeclared

    Filtered behavior:
        Any key in ``raw`` that isn't in ``allowed`` is dropped at construction
        time — not just hidden. Engine process memory never contains undeclared
        secrets, even via reflection.
    """

    __slots__ = ("_allowed", "_secrets")

    def __init__(self, raw: dict[str, str], allowed: frozenset[str] | set[str]) -> None:
        self._allowed = frozenset(allowed)
        # Filter: engine process *never* holds secrets it didn't declare.
        self._secrets = {k: v for k, v in raw.items() if k in self._allowed}

    def __getattr__(self, name: str) -> str:
        # __getattr__ is only called when normal attribute lookup fails.
        # For __slots__ attrs (_allowed, _secrets) this won't trigger.
        if name.startswith("_"):
            raise AttributeError(name)

        if name not in self._allowed:
            raise SecretNotDeclared(
                f"secret {name!r} is not declared in engine.yaml "
                f"secret_requirements; declared: {sorted(self._allowed)}"
            )

        if name not in self._secrets:
            # Declared but not provided — this is usually an orchestrator fault
            # (envelope.secrets was missing the key).
            raise SecretMissing(
                f"secret {name!r} is declared in engine.yaml but was not "
                f"provided in the /invoke envelope"
            )

        return self._secrets[name]

    def __contains__(self, name: str) -> bool:
        return name in self._secrets

    def __repr__(self) -> str:
        # Never expose values. Show declared names only.
        return f"SecretsProxy(declared={sorted(self._allowed)!r}, present={sorted(self._secrets)!r})"

    # --- Internal helpers used by the SDK / tests (prefixed to stay off __getattr__) ---

    def _declared(self) -> frozenset[str]:
        return self._allowed

    def _has(self, name: str) -> bool:
        return name in self._secrets

    def _values(self) -> frozenset[str]:
        """All secret values currently held. Used by the redactor to scrub
        outgoing payloads."""
        return frozenset(self._secrets.values())
