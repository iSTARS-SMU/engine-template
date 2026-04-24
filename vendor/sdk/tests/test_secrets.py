"""Unit tests for trustchain_sdk.secrets.SecretsProxy.

Why this matters: SecretsProxy is the only legal path for an engine to read a
secret, and the whitelist-at-construction behavior is what makes engines
actually isolated from each other at the memory level. If undeclared secrets
leak into proxy._secrets — even as "inaccessible" dict entries — a buggy
`__getattr__` or a sneaky introspection path could still read them. These
tests lock the filter, the attribute gate, and the repr sanitization.
"""

from __future__ import annotations

import pytest

from trustchain_sdk._errors import SecretMissing, SecretNotDeclared
from trustchain_sdk.secrets import SecretsProxy


# ============================================================
# Construction filter — undeclared secrets never enter proxy memory
# ============================================================


def test_undeclared_secrets_dropped_at_construction():
    """Secrets not in the allowed whitelist must not appear in `_secrets` at
    all — not even as private-named entries an engine could introspect."""
    proxy = SecretsProxy(
        raw={"openai": "sk-A", "stripe": "sk-B", "exa": "exa-C"},
        allowed={"openai", "exa"},
    )
    # _values() is the redactor's view of "what values do we know".
    # It must NOT contain sk-B.
    assert "sk-B" not in proxy._values()
    assert proxy._values() == frozenset({"sk-A", "exa-C"})


def test_allowed_accepts_set_or_frozenset():
    """Construction must accept either — callers may pass engine-yaml-derived
    allowed names as either form."""
    p1 = SecretsProxy(raw={"openai": "x"}, allowed={"openai"})
    p2 = SecretsProxy(raw={"openai": "x"}, allowed=frozenset({"openai"}))
    assert p1.openai == p2.openai == "x"


# ============================================================
# Attribute access — the happy path
# ============================================================


def test_access_declared_and_present_returns_value():
    proxy = SecretsProxy(
        raw={"openai": "sk-live"},
        allowed={"openai"},
    )
    assert proxy.openai == "sk-live"


def test_contains_operator_reflects_presence():
    proxy = SecretsProxy(raw={"openai": "x"}, allowed={"openai", "exa"})
    assert "openai" in proxy
    # "exa" declared but not provided — contains should report False.
    assert "exa" not in proxy


# ============================================================
# Attribute access — error paths
# ============================================================


def test_access_undeclared_raises_secret_not_declared():
    """Engine code accessing a secret name not in engine.yaml is a bug the
    SDK must surface loudly — not silently return None or falsy."""
    proxy = SecretsProxy(raw={"stripe": "sk-B"}, allowed={"openai"})
    with pytest.raises(SecretNotDeclared) as exc_info:
        _ = proxy.stripe
    # Error message should reference the declared set so the engine author
    # can fix their engine.yaml quickly.
    assert "stripe" in str(exc_info.value)


def test_secret_not_declared_is_attribute_error_compatible():
    """SecretNotDeclared subclasses AttributeError so idiomatic
    `getattr(obj, name, default)` and `hasattr()` work on proxies — engines
    that probe optional secrets this way need the AttributeError shape."""
    proxy = SecretsProxy(raw={}, allowed={"openai"})
    assert hasattr(proxy, "stripe") is False  # uses __getattr__ → AttributeError
    assert getattr(proxy, "stripe", "fallback") == "fallback"


def test_access_declared_but_missing_raises_secret_missing():
    """Declared in engine.yaml but not present in the envelope — orchestrator
    fault. Engine must see a distinct error from "not declared" so it
    surfaces differently in logs / error codes."""
    proxy = SecretsProxy(raw={}, allowed={"openai"})
    with pytest.raises(SecretMissing) as exc_info:
        _ = proxy.openai
    assert "openai" in str(exc_info.value)


def test_secret_missing_not_conflated_with_secret_not_declared():
    """SecretMissing is deliberately NOT a subclass of AttributeError. A
    declared-but-missing secret is an orchestrator fault — it should raise
    loudly and propagate through hasattr(), rather than silently returning
    False the way SecretNotDeclared does. This distinction lets engines use
    hasattr() for optional probes (SecretNotDeclared → False), while still
    failing fast on required-but-not-injected secrets."""
    proxy = SecretsProxy(raw={}, allowed={"openai"})

    # SecretNotDeclared IS AttributeError → hasattr swallows to False.
    # (Engine can probe optional secret names this way.)
    assert hasattr(proxy, "stripe") is False

    # SecretMissing is NOT AttributeError → propagates out of hasattr.
    # This is the guarantee: declared-but-missing never silently looks
    # like "not declared".
    with pytest.raises(SecretMissing):
        hasattr(proxy, "openai")


# ============================================================
# Privacy of representation
# ============================================================


def test_repr_does_not_expose_secret_values():
    """`str(proxy)` ends up in logs and stack traces. Must never include
    the raw secret value."""
    proxy = SecretsProxy(
        raw={"openai": "sk-live-REALSECRET-do-not-leak"},
        allowed={"openai"},
    )
    assert "REALSECRET" not in repr(proxy)
    assert "REALSECRET" not in str(proxy)
    # Declared names are fine to show.
    assert "openai" in repr(proxy)


def test_repr_shows_declared_and_present_separately():
    """The repr distinguishes "declared" (from engine.yaml) vs "actually
    provided in envelope" — useful for debugging secret-injection issues
    without leaking values."""
    proxy = SecretsProxy(
        raw={"openai": "sk-A"},  # provided
        allowed={"openai", "exa"},  # declared (exa is declared-but-missing)
    )
    r = repr(proxy)
    assert "openai" in r
    assert "exa" in r


# ============================================================
# Dunder / private name access — shouldn't leak internals
# ============================================================


def test_underscore_prefixed_access_raises_attribute_error():
    """`proxy._secrets` and similar dunders must not fall into __getattr__
    with weird behavior. __slots__ protects declared internals, but the
    engine might ask for `_anything`; the proxy should reject cleanly."""
    proxy = SecretsProxy(raw={"openai": "x"}, allowed={"openai"})
    # _secrets is a __slots__ entry — normal attribute lookup finds it.
    # We're testing that ACCESSING ARBITRARY _-prefixed names via __getattr__
    # doesn't accidentally succeed. `_bogus` is NOT in __slots__, so
    # Python falls through to __getattr__, which rejects _-prefixed names.
    with pytest.raises(AttributeError):
        _ = proxy._bogus  # type: ignore[attr-defined]


# ============================================================
# Cross-invocation isolation (smoke — reinforces per-invoke contract)
# ============================================================


def test_two_proxies_do_not_share_state():
    """Per-invoke contract: each /invoke gets its own SecretsProxy. Mutating
    one must never affect another. This is a property of the class, not
    of the RunContext wrapper."""
    p1 = SecretsProxy(raw={"openai": "sk-A"}, allowed={"openai"})
    p2 = SecretsProxy(raw={"openai": "sk-B"}, allowed={"openai"})
    assert p1.openai == "sk-A"
    assert p2.openai == "sk-B"
    # Internal store isolation.
    assert p1._secrets is not p2._secrets  # type: ignore[attr-defined]


# ============================================================
# _has(): presence check used by RunContext upfront validation
# ============================================================


def test_has_returns_true_only_when_both_declared_and_provided():
    proxy = SecretsProxy(
        raw={"openai": "sk-A"},
        allowed={"openai", "exa"},
    )
    assert proxy._has("openai") is True
    assert proxy._has("exa") is False       # declared, not provided
    assert proxy._has("stripe") is False    # not declared at all


# ============================================================
# _values(): what the event scrubber sees
# ============================================================


def test_values_reflects_only_declared_and_present():
    proxy = SecretsProxy(
        raw={"openai": "sk-A", "exa": "exa-B", "undeclared": "leak"},
        allowed={"openai", "exa"},
    )
    values = proxy._values()
    assert "sk-A" in values
    assert "exa-B" in values
    # Undeclared value must never be visible to the scrubber —
    # it was dropped at construction.
    assert "leak" not in values


def test_values_returns_frozenset():
    """Callers expect a frozenset (immutable). Hand-back a regular set would
    let the scrubber accidentally mutate the proxy's internal view."""
    proxy = SecretsProxy(raw={"openai": "x"}, allowed={"openai"})
    assert isinstance(proxy._values(), frozenset)
