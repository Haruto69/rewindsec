"""The deterministic training engine: what happens next, and why.

This is the module Batch 3 exists to write. Batch 2 delivered a fixed authored
list in a fixed order and called it scaffolding, which it was. What replaces
it is a context-conditioned deterministic scheduler: at each evaluation pulse
the engine reads the world and the Context Ledger, resolves every candidate to
ELIGIBLE or LOCKED *before* touching randomness, updates per-family pressure,
draws from named streams, and either produces one piece of workplace activity
or produces nothing at all.

The evaluation pulse
--------------------
The engine schedules its own successor on the session's
:class:`~rewindsec.core.scheduler.EventScheduler`, as an ordinary event of
type :data:`EVALUATION_EVENT_TYPE`, at a simulation time drawn from the timing
stream. When that event fires, :func:`evaluate` runs and schedules the next
one. Consequently:

* simulation time is the only thing that drives the engine. Waiting in real
  time with no explicit advancement does nothing at all, because no pulse
  comes due;
* the engine's state survives a restart for free, because a pending pulse is a
  pending scheduler entry and the scheduler is part of the persisted session;
* a long advance and a sequence of short ones produce the same history, since
  the service walks the clock to each due time in turn and every pulse fires
  at the simulation time it was scheduled for;
* every pulse moves strictly forward -- the interval floor in
  :mod:`rewindsec.training.policy` is not advisory -- so no advance, however
  large, can loop here.

What the engine will not do
---------------------------
It does not read a wall clock; there is no ``time`` import in this package and
a boundary test enforces it. It does not evaluate on a GET, on an SSE
connection, on a reconnect or on a projection: nothing in this module is
reachable from a read path. It does not select while a blocking safer-
alternative comparison is waiting, because piling an unrelated arrival onto a
learner who is being shown an explanation is neither realistic nor kind. And
it does not run at all for a session created before Batch 3 -- see
:func:`rewindsec.training.state.engine_is_active`.
"""

from rewindsec.core.events import EventSource, EventVisibility
from rewindsec.core.rng import (STREAM_BACKGROUND, STREAM_THREAT_SELECTION,
                                STREAM_TIMING)
from rewindsec.training import delivery, eligibility, policy, selection
from rewindsec.training import state as engine_state
from rewindsec.training.catalog import all_candidates, by_id
from rewindsec.workstation.bootstrap import NS_SESSION
# Leaf module: imports nothing, so reading the assessment boundary here
# cannot create a cycle between the engine and the management package.
from rewindsec.management import session_link

__all__ = ["EVALUATION_EVENT_TYPE", "ARRIVAL_EVENT_TYPE", "start",
           "schedule_next_evaluation", "evaluate", "force_candidate",
           "note_resolved", "pending_evaluation", "engine_summary"]

#: The engine's own pulse. Internal: it is bookkeeping, not something that
#: happened to the learner, and a learner-visible event named "evaluate" would
#: tell a reader of the event stream exactly when to expect an arrival.
EVALUATION_EVENT_TYPE = "engine.evaluate"

#: The event that represents one selected arrival. Behavioural and
#: deliberately uninformative -- the same type whether ordinary work or an
#: attack just arrived.
ARRIVAL_EVENT_TYPE = "world.activity"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def start(session, cause_event_id=None):
    """Install engine state and queue the first pulse. Called once, at create."""
    engine_state.bootstrap(session, cause_event_id=cause_event_id)
    schedule_next_evaluation(session)


def pending_evaluation(session):
    """The queued pulse, or ``None``. Cancelled entries do not count."""
    for entry in session.scheduler.pending():
        if not entry.cancelled and entry.spec.type == EVALUATION_EVENT_TYPE:
            return entry
    return None


def schedule_next_evaluation(session, delay_ms=None, cause_event_id=None):
    """Queue the next pulse, unless one is already queued.

    One at a time, for the same reason Batch 2 queued one arrival at a time:
    Practice has to be able to bring the next evaluation forward when the
    learner finishes with the item in front of them, and a fully pre-scheduled
    queue cannot be nudged without cancelling a pile of entries.
    """
    if pending_evaluation(session) is not None:
        return None
    if delay_ms is None:
        delay_ms = policy.evaluation_delay_ms(
            session.mode.value, session.rng.stream(STREAM_TIMING))
    delay_ms = max(policy.MIN_EVALUATION_INTERVAL_MS, int(delay_ms))
    return session.schedule_event(
        EVALUATION_EVENT_TYPE, delay_ms=delay_ms,
        payload={"step": int(engine_state.meta(session).get("step", 0)) + 1},
        source=EventSource.SCHEDULER, visibility=EventVisibility.INTERNAL,
        scheduling_cause_event_id=cause_event_id)


def note_resolved(session, ref):
    """The learner has finished with the arrival the engine was waiting on.

    In Practice this is what makes the mode learner-paced: the pending pulse
    is cancelled -- with a reason, so the audit log says why -- and replaced
    with a short one, so the day moves at the speed the learner reads. In the
    other modes it simply clears the marker; the cadence is the cadence.
    """
    if not engine_state.engine_is_active(session):
        return
    meta = engine_state.meta(session)
    active = meta.get("active_primary") or {}
    if not active or active.get("ref") != ref:
        return
    engine_state.set_meta(session, active_primary=None)
    if not policy.mode_policy(session.mode.value)["gate_on_active_primary"]:
        return
    pending = pending_evaluation(session)
    if pending is not None:
        session.cancel_scheduled(
            pending.schedule_id,
            reason="learner resolved the current item")
    schedule_next_evaluation(session, delay_ms=policy.MIN_EVALUATION_INTERVAL_MS * 4)


# ---------------------------------------------------------------------------
# One evaluation
# ---------------------------------------------------------------------------

def evaluate(session, event):
    """Run one pulse: eligibility, pressure, selection, delivery, reschedule.

    Returns a record of what happened, which the service uses for nothing and
    the tests use for everything. The same record, trimmed, is appended to the
    session's internal engine trace.
    """
    meta = engine_state.meta(session)
    step = int(meta.get("step", 0)) + 1
    now_ms = session.now_ms
    focus_id = session.focus.value
    mode_id = session.mode.value
    mode = policy.mode_policy(mode_id)

    record = {"step": step, "at_ms": now_ms,
              "engine_version": meta.get("engine_version"),
              "selected": None, "family": None, "reason": None,
              "eligible": [], "pressure": {}}

    # A blocking comparison is a pedagogical pause, not a pause in the world:
    # consequences already scheduled still fire, and nothing already recorded
    # is lost. What stops is the arrival of *new, unrelated* primary activity.
    if session.world.get(NS_SESSION, "pending_comparison"):
        record["reason"] = "blocked_by_comparison"
        return _finish(session, event, record, step)

    # An assessment attempt that has already satisfied its required scored
    # interactions is past its boundary. Same shape as the pause above, and
    # for a related reason: the world is not stopped -- consequences already
    # in flight still fire and the learner can still act on what is in front
    # of them -- but the environment stops handing out *new, unrelated*
    # scored opportunities. Without this an attempt could accumulate an
    # arbitrary number of extra interactions purely by being left open, and
    # two attempts at the same assessment would stop being comparable.
    # Non-attempt sessions never carry a boundary, so nothing changes for
    # Practice or Simulation.
    if session_link.boundary_reached(session):
        record["reason"] = "assessment_boundary_reached"
        return _finish(session, event, record, step)

    active_primary = meta.get("active_primary")
    gate = bool(mode["gate_on_active_primary"])

    verdicts = _verdicts(session, now_ms, focus_id, active_primary, gate)
    record["eligible"] = sorted(v.candidate_id for v in verdicts.values()
                                if v.eligible)
    record["locked"] = {v.candidate_id: list(v.reasons)
                        for v in sorted(verdicts.values(),
                                        key=lambda item: item.candidate_id)
                        if not v.eligible}

    # -- threats -----------------------------------------------------------
    fired = _run_lottery(session, policy.THREAT_FAMILIES, verdicts,
                         STREAM_THREAT_SELECTION, focus_id, mode_id, mode,
                         step, event, record)

    # -- ordinary work -----------------------------------------------------
    #
    # Only when no threat fired, so two things never arrive in the same pulse,
    # and always from its own stream, so the number of background draws cannot
    # move a threat draw. The reverse coupling -- a threat outcome deciding
    # whether background draws at all -- is real and deliberate: the point of
    # the partition is that *content* changes cannot perturb *selection*, not
    # that the two halves never observe each other.
    if not fired:
        _run_lottery(session, (policy.BACKGROUND_FAMILY,), verdicts,
                     STREAM_BACKGROUND, focus_id, mode_id, mode, step, event,
                     record)

    return _finish(session, event, record, step)


def _verdicts(session, now_ms, focus_id, active_primary, gate):
    """Eligibility for every candidate, keyed by id. Consumes no randomness."""
    family_states = {family: engine_state.family_state(session, family)
                     for family in policy.FAMILIES}
    out = {}
    for candidate in all_candidates():
        out[candidate.candidate_id] = eligibility.evaluate(
            session, candidate,
            family_states.get(candidate.family, {}),
            now_ms, focus_id, active_primary, gate)
    return out


def _run_lottery(session, families, verdicts, stream_name, focus_id, mode_id,
                 mode, step, event, record):
    """Pressure, occurrence, family, candidate -- in that order, on one stream.

    Returns whether something was actually delivered. Nothing is drawn when no
    family in *families* holds an eligible candidate: there is no decision to
    make, so making one would consume randomness for nothing and two sessions
    with the same seed would diverge the first time their eligibility differed
    by a single candidate.
    """
    stream = session.rng.stream(stream_name)

    eligible = {}
    for family in families:
        options = [c for c in _family_candidates(family)
                   if verdicts[c.candidate_id].eligible]
        if options:
            eligible[family] = options

    # Freeze the families that have nothing eligible: no increment, no decay,
    # and starvation reset to zero so a family cannot bank selection pressure
    # for a period during which it could not have been selected anyway.
    for family in families:
        if family not in eligible:
            current = engine_state.family_state(session, family)
            if current["starved"]:
                engine_state.set_family_state(session, family, starved=0)

    if not eligible:
        return False

    # -- pressure ----------------------------------------------------------
    pressures = {}
    for family in sorted(eligible):
        current = engine_state.family_state(session, family)
        raw = stream.randint(policy.PRESSURE_INCREMENT_MIN,
                             policy.PRESSURE_INCREMENT_MAX)
        scaled = (raw * policy.focus_percent(focus_id, family)
                  * mode["pressure_percent"]) // 10000
        starvation = min(policy.STARVATION_CAP,
                         int(current["starved"]) * policy.STARVATION_STEP)
        value = min(policy.FAMILY_PRESSURE_CAP,
                    int(current["pressure"]) + max(1, scaled) + starvation)
        engine_state.set_family_state(session, family, pressure=value)
        pressures[family] = value
    record["pressure"].update(pressures)

    # -- occurrence --------------------------------------------------------
    total = min(policy.HAZARD_CAP, sum(pressures.values()))
    if not selection.roll_percent(stream, total):
        for family in sorted(eligible):
            current = engine_state.family_state(session, family)
            engine_state.set_family_state(session, family,
                                          starved=int(current["starved"]) + 1)
        record["reason"] = record["reason"] or "no_occurrence"
        return False

    # -- family, then candidate -------------------------------------------
    family = selection.weighted_choice(
        stream, [(name, pressures[name]) for name in sorted(eligible)])
    if family is None:
        record["reason"] = "no_family"
        return False

    candidate = selection.weighted_choice(
        stream, [(c, c.weight) for c in eligible[family]])
    if candidate is None:
        record["reason"] = "no_candidate"
        return False

    delivered = _deliver(session, candidate, event, step)
    if not delivered:
        # The world already held this. Not an occurrence: pressure and
        # cooldown stay where they are, so the family gets another chance
        # rather than being penalised for a no-op.
        record["reason"] = "no_effect"
        return False

    _after_selection(session, family, candidate, eligible, mode_id)
    record["selected"] = candidate.candidate_id
    record["family"] = family
    record["reason"] = "selected"
    return True


def _family_candidates(family):
    from rewindsec.training.catalog import for_family
    return for_family(family)


def _deliver(session, candidate, event, step):
    """Record the arrival event, then materialise it through world operations.

    The arrival event is recorded *first* so every world mutation the delivery
    produces can name it as their cause: an arrival with no causal parent
    would be a message that appeared from nowhere, which is exactly what the
    causal graph exists to make impossible.
    """
    arrival = session.record_immediate_event(
        ARRIVAL_EVENT_TYPE,
        payload={"activity": candidate.activity, "step": step},
        source=EventSource.SCHEDULER,
        visibility=EventVisibility.LEARNER_VISIBLE,
        causes=(event.event_id,) if event is not None else ())
    return delivery.deliver(session, candidate,
                            cause_event_id=arrival.event_id)


def _after_selection(session, family, candidate, eligible, mode_id):
    """Reset the winner, cool it down, and starve everyone who lost."""
    engine_state.bump_candidate(session, candidate.candidate_id)
    current = engine_state.family_state(session, family)
    engine_state.set_family_state(
        session, family,
        pressure=policy.PRESSURE_AFTER_SELECTION,
        starved=0,
        cooldown_until_ms=session.now_ms + policy.cooldown_ms(family, mode_id),
        occurrences=int(current["occurrences"]) + 1,
        last_fired_ms=session.now_ms)
    for other in sorted(eligible):
        if other == family:
            continue
        other_state = engine_state.family_state(session, other)
        engine_state.set_family_state(session, other,
                                      starved=int(other_state["starved"]) + 1)
    if candidate.is_primary:
        engine_state.set_meta(session, active_primary={
            "candidate": candidate.candidate_id,
            "ref": candidate.content_ref,
            "activity": candidate.activity,
        })


def _finish(session, event, record, step):
    """Persist the step counter and the trace, and queue the next pulse."""
    engine_state.set_meta(session, step=step)
    engine_state.record_trace(session, {
        "step": record["step"],
        "at_ms": record["at_ms"],
        "selected": record["selected"],
        "family": record["family"],
        "reason": record["reason"],
        "eligible": list(record["eligible"]),
        "pressure": dict(record["pressure"]),
    })
    schedule_next_evaluation(
        session, cause_event_id=event.event_id if event is not None else None)
    record["next_evaluation_at_ms"] = (
        pending_evaluation(session).fire_at_ms
        if pending_evaluation(session) is not None else None)
    return record


# ---------------------------------------------------------------------------
# Development tooling
# ---------------------------------------------------------------------------

def force_candidate(session, candidate_id, cause_event_id=None):
    """Deliver one named candidate immediately, bypassing the lottery.

    Development and test tooling only, reached through the ``/api/dev/``
    prefix and never through a learner action. It bypasses *probability*, not
    causality: the delivery goes through the same adapters, the same world
    operations and the same causal event as a selected arrival, and the world
    it produces is one the engine could have produced on its own.

    It draws nothing from the threat or background streams, so forcing an
    arrival in a test does not shift the selection any later pulse would make.
    """
    candidate = by_id(candidate_id)
    if candidate is None:
        return False
    event = session.record_immediate_event(
        ARRIVAL_EVENT_TYPE,
        payload={"activity": candidate.activity, "forced": True},
        source=EventSource.SCHEDULER,
        visibility=EventVisibility.LEARNER_VISIBLE,
        causes=(cause_event_id,) if cause_event_id else ())
    if not delivery.deliver(session, candidate, cause_event_id=event.event_id):
        return False
    engine_state.bump_candidate(session, candidate_id)
    current = engine_state.family_state(session, candidate.family)
    engine_state.set_family_state(
        session, candidate.family,
        occurrences=int(current["occurrences"]) + 1,
        last_fired_ms=session.now_ms)
    if candidate.is_primary:
        engine_state.set_meta(session, active_primary={
            "candidate": candidate.candidate_id,
            "ref": candidate.content_ref,
            "activity": candidate.activity,
        })
    return True


def engine_summary(session):
    """Internal engine state, for tests and the development endpoint.

    Learner-hidden by construction: it is returned from here, it is never
    merged into a projection, and the namespace it reads is not one the
    projection names.
    """
    meta = engine_state.meta(session)
    pending = pending_evaluation(session)
    return {
        "engine_version": meta.get("engine_version"),
        "catalog_version": meta.get("catalog_version"),
        "step": meta.get("step"),
        "active_primary": meta.get("active_primary"),
        "isolated_at_ms": meta.get("isolated_at_ms"),
        "suppressed_steps": list(meta.get("suppressed_steps") or []),
        "families": {family: engine_state.family_state(session, family)
                     for family in policy.FAMILIES},
        "next_evaluation_at_ms": pending.fire_at_ms if pending else None,
        "trace": engine_state.trace(session),
    }
