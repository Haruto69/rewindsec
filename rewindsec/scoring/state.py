"""Persisted scoring state: versioning at creation, finalization once, ever.

Mirrors the pattern :mod:`rewindsec.training.state` already established for
the training engine: rather than adding a new top-level field to
:class:`~rewindsec.domain.session.SimulationSession` (which would bump its
state version and invalidate every stored Batch 1-3 session), scoring state
lives in the session's own :class:`~rewindsec.domain.world.WorldState`, under
one dedicated namespace. Every write goes through ``mutate_world`` and
therefore carries a causal event and lands in the audit trail like every
other fact about the session.

Two world keys
--------------
``meta``
    Written once, at session creation (see :func:`bootstrap`), stamping the
    session with the scoring/rubric/evidence-model versions it will be
    scored under. A session with no ``meta`` key was created before this
    module existed -- unambiguously legacy, regardless of when it happens to
    complete.

``result``
    Written at most once, when the session completes (see :func:`finalize`).
    Ending a session twice, or any other repeated call, is a no-op: the
    first finalization under the session's declared versions is the one that
    is kept, forever, for that session.
"""

from rewindsec.scoring.evaluator import evaluate
from rewindsec.scoring.result import ScoringResult, legacy_view
from rewindsec.scoring.versions import (EVIDENCE_MODEL_VERSION, RUBRIC_VERSION,
                                        SCORING_VERSION)

__all__ = ["NS_SCORING", "KEY_META", "KEY_RESULT", "is_versioned_session",
           "bootstrap", "finalize", "is_finalized", "get_result",
           "learner_view", "meta"]

#: The one world namespace this module owns. Never named in
#: :mod:`rewindsec.workstation.projection`'s allowlist, so it can never reach
#: an active learner's browser -- see the leakage tests for the assertion.
NS_SCORING = "scoring"

KEY_META = "meta"
KEY_RESULT = "result"


def is_versioned_session(session):
    """Whether this session was stamped with scoring versions at creation.

    ``False`` for every session created before this module existed. Those
    sessions are legacy for scoring purposes for their entire lifetime,
    independent of when -- or whether -- they are ever completed.
    """
    return session.world.has(NS_SCORING, KEY_META)


def bootstrap(session, cause_event_id=None):
    """Stamp a brand-new session with the scoring/rubric/evidence versions
    it will (eventually) be scored under. Idempotent."""
    if is_versioned_session(session):
        return
    session.mutate_world(NS_SCORING, KEY_META, {
        "scoring_version": SCORING_VERSION,
        "rubric_version": RUBRIC_VERSION,
        "evidence_model_version": EVIDENCE_MODEL_VERSION,
    }, cause_event_id=cause_event_id)


def meta(session):
    return dict(session.world.get(NS_SCORING, KEY_META) or {})


def is_finalized(session):
    return session.world.has(NS_SCORING, KEY_RESULT)


def finalize(session):
    """Compute and persist the immutable final result, at most once.

    A no-op -- returning the already-stored result -- on every call after
    the first, which is what makes ending a session twice safe: no evidence
    is duplicated, no id is regenerated, and the score cannot change because
    the rubric code on disk later changed. A session with no scoring stamp
    (legacy) is never scored at all; :func:`learner_view` is how that shows
    up to a caller.
    """
    if not is_versioned_session(session):
        return None
    if is_finalized(session):
        return get_result(session)
    result = evaluate(session)
    session.mutate_world(NS_SCORING, KEY_RESULT, result.to_state())
    return result


def get_result(session):
    """The persisted result, or ``None`` if this session was never finalized."""
    stored = session.world.get(NS_SCORING, KEY_RESULT)
    if stored is None:
        return None
    return ScoringResult.from_state(stored)


def learner_view(session):
    """The permitted learner/debrief projection of this session's score.

    Three states, and only three: a real, versioned, finalized result; a
    versioned session that has not (yet) been finalized -- active sessions
    never reach this, since the debrief route itself refuses to run before
    completion, but a defensive fallback is still explicit rather than an
    exception; or a legacy session that predates scoring altogether.
    """
    if not is_versioned_session(session):
        return legacy_view()
    result = get_result(session)
    if result is None:
        return {
            "available": False, "legacy": False,
            "scoring_version": SCORING_VERSION, "rubric_version": RUBRIC_VERSION,
            "evidence_model_version": EVIDENCE_MODEL_VERSION, "overall": None,
            "dimensions": [],
            "note": "Scoring has not been finalized for this session yet.",
        }
    return result.to_learner_view()
