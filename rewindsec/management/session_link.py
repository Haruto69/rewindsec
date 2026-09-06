"""The attempt stamp a TrainingSession carries, and where it lives.

Mirrors exactly the pattern :mod:`rewindsec.training.state` and
:mod:`rewindsec.scoring.state` already established, for the same three
reasons:

* :meth:`~rewindsec.domain.session.SimulationSession.capture_state` validates
  its key set exactly and refuses an unknown top-level field, so adding one
  would bump the Batch 1 session state version and invalidate every session
  stored by Batches 1-4. Batch 5 has no business doing that.
* The world gives, for free, everything this stamp needs: it is persisted
  with the session, restored atomically with it, and every write goes through
  ``mutate_world`` and therefore lands in the mutation audit trail with a
  causal event, like every other fact about the session.
* :mod:`rewindsec.workstation.projection` reads a fixed list of named
  namespaces. :data:`NS_ASSESSMENT` is not on it, so the stamp cannot reach a
  learner's browser -- structurally, not by remembering to filter it.

Determinism
-----------
Writing this stamp draws nothing from any RNG stream, schedules nothing and
advances no clock. :func:`rewindsec.scoring.opportunities.build_opportunities`
walks the same mutation log but looks only at the mail, auth-request and
incident namespaces, so a stamp in this namespace is invisible to scoring as
well. Two sessions with the same seed and the same learner inputs replay
identically whether or not one of them is an assessment attempt.
"""

__all__ = ["NS_ASSESSMENT", "KEY_ATTEMPT", "KEY_BOUNDARY", "STAMP_VERSION",
           "BOUNDARY_VERSION", "stamp_attempt", "attempt_stamp",
           "is_attempt_session", "required_interactions",
           "close_boundary", "boundary", "boundary_reached",
           "admitted_scored_resolutions"]

#: The one world namespace this module owns. Never projected to a learner.
NS_ASSESSMENT = "assessment_attempt"

KEY_ATTEMPT = "attempt"

#: The assessment completion boundary. See :func:`close_boundary`.
KEY_BOUNDARY = "boundary"

#: Bumped only if the stamp's own persisted shape changes incompatibly.
STAMP_VERSION = "rewindsec-attempt-stamp/v1"

#: Bumped only if the boundary record's persisted shape changes.
BOUNDARY_VERSION = "rewindsec-assessment-boundary/v2"


def stamp_attempt(session, attempt_id, assessment_id, student_id,
                  assignment_id=None, assignment_source=None,
                  assignment_group_id=None, required_interactions=None,
                  attempt_number=None, cause_event_id=None):
    """Record which attempt this session *is*. Written once, at creation.

    Idempotent: a second call on a session that already carries a stamp does
    nothing, so replaying creation cannot mint a second identity for the same
    session. The stamp is the session's own copy of the attempt link -- the
    authoritative row lives in
    :mod:`rewindsec.persistence.management_adapter`, and the two are checked
    against each other whenever an attempt is resumed, so neither can drift
    into claiming a session the other does not.
    """
    if session.world.has(NS_ASSESSMENT, KEY_ATTEMPT):
        return attempt_stamp(session)
    payload = {
        "stamp_version": STAMP_VERSION,
        "attempt_id": attempt_id,
        "assessment_id": assessment_id,
        "student_id": student_id,
        "assignment_id": assignment_id,
        "assignment_source": assignment_source,
        "assignment_group_id": assignment_group_id,
        "required_interactions": required_interactions,
        "attempt_number": attempt_number,
    }
    session.mutate_world(NS_ASSESSMENT, KEY_ATTEMPT, payload,
                         cause_event_id=cause_event_id)
    return attempt_stamp(session)


def attempt_stamp(session):
    """This session's attempt stamp, or ``None`` if it is not an attempt."""
    stored = session.world.get(NS_ASSESSMENT, KEY_ATTEMPT)
    if stored is None:
        return None
    return dict(stored)


def is_attempt_session(session):
    return session.world.has(NS_ASSESSMENT, KEY_ATTEMPT)


def required_interactions(session):
    """The required scored-interaction count this session was started under.

    Read from the session's own stamp rather than from the assessment
    definition, so a definition edited after an attempt began cannot move the
    goalposts of an attempt already in progress. ``None`` when the session is
    not an attempt.
    """
    stamp = attempt_stamp(session)
    if stamp is None:
        return None
    value = stamp.get("required_interactions")
    return None if value is None else int(value)


def close_boundary(session, scored_resolutions, closed_by_action_id=None,
                   cause_event_id=None):
    """Close this attempt's assessment boundary. Written once, idempotently.

    What "closing the boundary" means, exactly
    ------------------------------------------
    The boundary is reached the moment a learner action resolves the
    ``required_interactions``-th scored interaction. From that point the
    attempt has satisfied the assessment definition, and every *further*
    scored opportunity the environment might introduce is, by definition, not
    part of what this assessment asked for. Two attempts at the same
    assessment that differ by an arbitrary number of extra opportunities are
    not comparable, and nothing in Batch 4's rubric would notice.

    The record admits exactly the first N resolved opportunity/decision pairs
    as the attempt's complete scoreable opportunity set.
    :func:`rewindsec.scoring.evidence` consults that immutable list, so an
    already-visible N+1 opportunity contributes neither a later decision nor
    an ignored-opportunity penalty to the final result. Its delivery and later
    action remain factual history. The training engine also stops new
    unrelated primary arrivals.

    What it deliberately does **not** do:

    * It does not end the session, stop the clock, or cancel the scheduler.
      Terminating exactly at the Nth resolution would cut off consequence
      chains the learner's own earlier decisions had already set in motion --
      a redirected payment that has not landed yet, an encryption sweep that
      has not spread yet -- and a training system that hides the consequence
      of a decision because a counter reached a threshold has removed the one
      thing the simulation exists to show. Anything already scheduled still
      fires, at the simulation time it was scheduled for.
    * It does not delete, rewind, or create a second score. Batch 4 still owns
      finalization and produces the one authoritative result; its existing
      evidence resolver simply respects this persisted attempt boundary.
    * It does not stop the learner acting. A later action remains in immutable
      history and may produce natural world consequences, but it is outside
      this attempt's admitted scored-interaction set.

    The exact opportunity id, decision record id, simulation time, revision
    and closing learner action are stored so the cutoff is auditable without
    re-deriving a mutable interpretation later.
    """
    if session.world.has(NS_ASSESSMENT, KEY_BOUNDARY):
        return boundary(session)
    stamp = attempt_stamp(session)
    admitted = []
    for row in scored_resolutions:
        admitted.append({
            "opportunity_id": str(row["opportunity_id"]),
            "decision_record_id": str(row["decision_record_id"]),
        })
    required = required_interactions(session)
    if required is None or len(admitted) != required:
        raise ValueError(
            "an assessment boundary must admit exactly its required count")
    payload = {
        "boundary_version": BOUNDARY_VERSION,
        "attempt_id": None if stamp is None else stamp.get("attempt_id"),
        "required_interactions": required,
        "completed_at_boundary": len(admitted),
        "scored_resolutions": admitted,
        "at_sim_time_ms": session.now_ms,
        "cutoff_revision": session.revision,
        "closed_by_action_id": closed_by_action_id,
    }
    session.mutate_world(NS_ASSESSMENT, KEY_BOUNDARY, payload,
                         cause_event_id=cause_event_id)
    return boundary(session)


def boundary(session):
    """This attempt's boundary record, or ``None`` if it is still open."""
    stored = session.world.get(NS_ASSESSMENT, KEY_BOUNDARY)
    return None if stored is None else dict(stored)


def boundary_reached(session):
    """Whether this session's assessment boundary has been closed.

    ``False`` for every session that is not an assessment attempt, which is
    what makes this safe to consult from the training engine on every pulse:
    a Practice or Simulation run has no boundary and never will.
    """
    return session.world.has(NS_ASSESSMENT, KEY_BOUNDARY)


def admitted_scored_resolutions(session):
    """``{opportunity_id: decision_record_id}`` at the exact cutoff.

    ``None`` means no exact v2 cutoff exists (an active attempt before its
    boundary, a non-attempt session, or a legacy v1 boundary).  An empty dict
    is never valid because Assessment requirements start at one.
    """
    record = boundary(session)
    if record is None or record.get("boundary_version") != BOUNDARY_VERSION:
        return None
    rows = record.get("scored_resolutions")
    if not isinstance(rows, list):
        return None
    return {row.get("opportunity_id"): row.get("decision_record_id")
            for row in rows if isinstance(row, dict)}
