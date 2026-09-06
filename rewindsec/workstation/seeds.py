"""Where a brand-new session's root seed comes from.

The root seed is the one value that must be *unpredictable in production* and
*fixed in a test*, so it is the one thing in this layer that is injected
rather than computed. Once a session exists, every subsequent random draw
comes from :class:`~rewindsec.core.rng.SeededRandom` derived from this seed;
nothing else in the simulation may reach for ambient randomness.

This module is deliberately the only place under ``rewindsec/`` outside the
RNG itself that touches :mod:`secrets`, and it sits in the application layer
rather than the domain precisely because "ask the operating system for
entropy" is infrastructure, not simulation.
"""

import secrets

__all__ = ["SeedSource", "SystemSeedSource", "FixedSeedSource",
           "CountingSeedSource", "MAX_ROOT_SEED"]

#: Seeds stay inside the JSON-safe integer range, because they are persisted
#: in the session snapshot and read back by ``json.loads``.
MAX_ROOT_SEED = 2 ** 53 - 1


class SeedSource(object):
    """The contract: produce a root seed for one new session."""

    def next_seed(self):
        raise NotImplementedError


class SystemSeedSource(SeedSource):
    """Cryptographically strong seeds from the operating system.

    The default in production. ``secrets`` rather than ``random`` because a
    guessable root seed would make a whole session's future predictable to
    anyone who could guess it, and because this call happens exactly once per
    session -- outside the deterministic simulation entirely.
    """

    def next_seed(self):
        return secrets.randbelow(MAX_ROOT_SEED) + 1


class FixedSeedSource(SeedSource):
    """Always the same seed. For a test that wants two identical sessions."""

    def __init__(self, seed):
        self._seed = _validate_seed(seed)

    def next_seed(self):
        return self._seed


class CountingSeedSource(SeedSource):
    """Deterministic but distinct seeds: ``start``, ``start + step``, ...

    For a test that needs several sessions that are each reproducible but not
    identical to one another.
    """

    def __init__(self, start=1, step=1):
        self._next = _validate_seed(start)
        self._step = int(step)

    def next_seed(self):
        seed = self._next
        self._next = (self._next + self._step) % MAX_ROOT_SEED or 1
        return seed


def _validate_seed(value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("root seed must be an int, got %s" % type(value).__name__)
    if not 0 <= value <= MAX_ROOT_SEED:
        raise ValueError("root seed %d is outside the JSON-safe range" % value)
    return value
