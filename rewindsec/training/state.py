"""Persisted engine state, and the only vocabulary for reading or writing it.

Where it lives, and why
-----------------------
Engine state is stored in the session's own :class:`WorldState`, under one
dedicated namespace, :data:`NS_ENGINE`. The alternative -- extending
:class:`~rewindsec.domain.session.SimulationSession` with a new top-level
field -- was rejected deliberately:

* ``SimulationSession.capture_state`` validates its key set exactly and
  refuses an unknown field, so a new top-level slot means bumping the Batch 1
  session state version and invalidating every stored session. Batch 3 has no
  business doing that to Batch 2 data.
* The world already gives, for free, every property engine state needs:
  it is persisted with the session, it is restored atomically with it, and
  every write goes through ``mutate_world`` and therefore lands in the audit
  trail with a causal event. Engine state written any other way would be the
  only state in the system with no provenance.
* :mod:`rewindsec.workstation.projection` is an allowlist over named
  namespaces. A namespace it does not name cannot reach a browser, so hiding
  engine truth is structural rather than remembered.

What is *not* acceptable, and what this module exists to prevent, is engine
state living in ad-hoc world keys with no schema and no version. Everything
here is namespaced, shaped and versioned: :data:`KEY_META` always carries the
engine and catalogue versions that wrote it.

Nothing here reads a wall clock, draws a random value or decides anything. It
is storage vocabulary.
"""

from rewindsec.training import policy

__all__ = [
    "NS_ENGINE", "KEY_META", "engine_is_active", "bootstrap", "meta",
    "set_meta", "family_state", "set_family_state", "candidate_state",
    "bump_candidate", "record_trace", "trace", "family_key", "candidate_key",
    "is_isolated", "set_isolated", "suppressed_steps", "latch_suppressed_step",
]

#: The one world namespace the training engine owns. Never projected.
NS_ENGINE = "training_engine"

KEY_META = "meta"
KEY_TRACE = "trace"


def family_key(family):
    return "family.%s" % family


def candidate_key(candidate_id):
    return "candidate.%s" % candidate_id


# ---------------------------------------------------------------------------
# Activation and compatibility
# ---------------------------------------------------------------------------

def engine_is_active(session):
    """Whether this session is driven by the training engine.

    False for every session created before Batch 3. Those sessions have a
    fixed authored timeline half-played and pending Batch 2 events in their
    scheduler; switching them to a different event universe mid-attempt would
    silently change what the learner is being asked to do. They keep the
    timeline they started with, and the service branches on this predicate.
    """
    return session.world.has(NS_ENGINE, KEY_META)


def bootstrap(session, cause_event_id=None):
    """Install initial engine state on a brand-new session. Idempotent."""
    if engine_is_active(session):
        return
    session.mutate_world(NS_ENGINE, KEY_META, {
        "engine_version": policy.ENGINE_VERSION,
        "catalog_version": policy.CATALOG_VERSION,
        # The number of evaluation pulses this session has executed. The
        # engine's own logical time, distinct from simulation milliseconds.
        "step": 0,
        # The candidate the learner is currently expected to be dealing with,
        # or None. Practice will not select a new primary while this is set.
        "active_primary": None,
        # Simulation time at which the learner took the workstation off the
        # network, or None. Never cleared by reconnecting: it is a fact about
        # what happened, and later suppression decisions are latched, not
        # re-derived.
        "isolated_at_ms": None,
        # ``"chain:step"`` identities whose network-dependent effect was
        # cancelled because isolation was already in force. Latched, so
        # reconnecting cannot resurrect a consequence that was contained.
        "suppressed_steps": [],
    }, cause_event_id=cause_event_id)
    for family in policy.FAMILIES:
        session.mutate_world(NS_ENGINE, family_key(family), {
            "pressure": 0,
            "starved": 0,
            "cooldown_until_ms": 0,
            "occurrences": 0,
            "last_fired_ms": None,
        }, cause_event_id=cause_event_id)
    session.mutate_world(NS_ENGINE, KEY_TRACE, [], cause_event_id=cause_event_id)


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------

def meta(session):
    return dict(session.world.get(NS_ENGINE, KEY_META) or {})


def set_meta(session, cause_event_id=None, **changes):
    current = meta(session)
    current.update(changes)
    return session.mutate_world(NS_ENGINE, KEY_META, current,
                                cause_event_id=cause_event_id)


def engine_version(session):
    return meta(session).get("engine_version")


# ---------------------------------------------------------------------------
# Per-family state
# ---------------------------------------------------------------------------

_FAMILY_DEFAULT = {"pressure": 0, "starved": 0, "cooldown_until_ms": 0,
                   "occurrences": 0, "last_fired_ms": None}


def family_state(session, family):
    stored = session.world.get(NS_ENGINE, family_key(family))
    if not isinstance(stored, dict):
        return dict(_FAMILY_DEFAULT)
    merged = dict(_FAMILY_DEFAULT)
    merged.update(stored)
    return merged


def set_family_state(session, family, cause_event_id=None, **changes):
    current = family_state(session, family)
    current.update(changes)
    return session.mutate_world(NS_ENGINE, family_key(family), current,
                                cause_event_id=cause_event_id)


# ---------------------------------------------------------------------------
# Per-candidate state
# ---------------------------------------------------------------------------

def candidate_state(session, candidate_id):
    stored = session.world.get(NS_ENGINE, candidate_key(candidate_id))
    if not isinstance(stored, dict):
        return {"occurrences": 0, "last_fired_ms": None}
    return {"occurrences": int(stored.get("occurrences", 0)),
            "last_fired_ms": stored.get("last_fired_ms")}


def bump_candidate(session, candidate_id, cause_event_id=None):
    current = candidate_state(session, candidate_id)
    return session.mutate_world(NS_ENGINE, candidate_key(candidate_id), {
        "occurrences": current["occurrences"] + 1,
        "last_fired_ms": session.now_ms,
    }, cause_event_id=cause_event_id)


# ---------------------------------------------------------------------------
# Network isolation
# ---------------------------------------------------------------------------

def is_isolated(session):
    """Whether the workstation is currently off the network.

    Reads the authoritative session flag rather than an engine copy of it, so
    there is exactly one answer to the question and the engine cannot drift
    from what the learner's screen says.
    """
    from rewindsec.workstation.bootstrap import NS_SESSION
    return bool(session.world.get(NS_SESSION, "network_disconnected", False))


def set_isolated(session, isolated, cause_event_id=None):
    """Record *when* isolation first happened. Never cleared by reconnecting."""
    from rewindsec.workstation import worldops
    worldops.set_session_flag(session, "network_disconnected", bool(isolated),
                              cause_event_id=cause_event_id)
    if isolated and engine_is_active(session) \
            and meta(session).get("isolated_at_ms") is None:
        set_meta(session, cause_event_id=cause_event_id,
                 isolated_at_ms=session.now_ms)


def suppressed_steps(session):
    return list(meta(session).get("suppressed_steps") or [])


def latch_suppressed_step(session, chain_id, step_id, cause_event_id=None):
    """Record that this chain step will never be applied.

    Latched rather than recomputed at fire time: a learner who isolates and
    later reconnects has not undone the containment that was in force when the
    step would have run. Bounded by the number of authored steps.
    """
    identity = "%s:%s" % (chain_id, step_id)
    current = suppressed_steps(session)
    if identity in current:
        return None
    current.append(identity)
    return set_meta(session, cause_event_id=cause_event_id,
                    suppressed_steps=sorted(current))


# ---------------------------------------------------------------------------
# Internal audit trail
# ---------------------------------------------------------------------------

def trace(session):
    """The last few evaluation records. Internal; never projected."""
    stored = session.world.get(NS_ENGINE, KEY_TRACE)
    return list(stored) if isinstance(stored, (list, tuple)) else []


def record_trace(session, record, cause_event_id=None):
    """Append one bounded evaluation record to the internal audit trail."""
    entries = trace(session)
    entries.append(record)
    if len(entries) > policy.TRACE_DEPTH:
        entries = entries[-policy.TRACE_DEPTH:]
    return session.mutate_world(NS_ENGINE, KEY_TRACE, entries,
                                cause_event_id=cause_event_id)
