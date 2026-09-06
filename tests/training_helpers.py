"""Scaffolding for the Batch 3 training-engine suites.

Two ways to drive the engine, and the suites use both deliberately.

*In memory*, through :func:`fresh_session` and :func:`pulse`: a
:class:`~rewindsec.domain.session.SimulationSession` with no repository, no
service and no HTTP, on which one evaluation pulse can be fired and its record
inspected. This is how the selection rule itself is tested -- eligibility,
pressure, cooldown, starvation, which stream was drawn from -- because at that
level a database is noise.

*Through the service*, using the Batch 2 ``Driver``: how the engine behaves as
part of a real session that persists, resumes and projects. This is how
resume, determinism across a rebuilt process and leakage are tested, because
at that level the database is the point.
"""

from rewindsec.domain.enums import Focus, Mode
from rewindsec.domain.session import SimulationSession
from rewindsec.training import engine as training_engine
from rewindsec.training import state as engine_state
from rewindsec.workstation import bootstrap, consequences
from rewindsec.workstation.content import index as ix

__all__ = ["fresh_session", "pulse", "pulses", "run_pulses", "selections",
           "family_state", "set_family", "engine_of"]


def fresh_session(focus="mixed", mode="simulation", seed=4242,
                  session_id="ws-engine-test", learner_ref="learner-test-1"):
    """A seeded, engine-started session with nothing persisting it.

    Identical in every respect to one the service would create -- the service
    calls exactly these three things, in this order -- minus the repository.
    """
    session = SimulationSession.create(
        session_id=session_id, learner_ref=learner_ref,
        focus=Focus(focus), mode=Mode(mode), root_seed=seed)
    start_event = bootstrap.seed_session(session)
    training_engine.start(session, cause_event_id=start_event.event_id)
    return session


def pulse(session):
    """Advance to the next evaluation pulse and run it. Returns its record.

    Consequence steps that come due on the way are applied, exactly as the
    service applies them, so a test that takes a decision and then keeps
    pulsing sees the same world the product would build.
    """
    entry = training_engine.pending_evaluation(session)
    assert entry is not None, "the engine has no pulse queued"
    mode_flags = ix.mode_flags(session.mode.value)
    record = None
    for event in session.advance_time(entry.fire_at_ms - session.now_ms):
        if event.type == training_engine.EVALUATION_EVENT_TYPE:
            record = training_engine.evaluate(session, event)
        elif event.type == consequences.CONSEQUENCE_EVENT_TYPE:
            consequences.apply_step_event(session, event, mode_flags)
    assert record is not None, "the pulse did not fire"
    return record


def pulses(session, count):
    """Run *count* consecutive pulses; return their records."""
    return [pulse(session) for _ in range(count)]


def run_pulses(session, count):
    """``pulses``, but returning only the records where something arrived."""
    return [record for record in pulses(session, count) if record["selected"]]


def selections(records):
    """``(family, candidate_id)`` for every record that produced an arrival."""
    return [(r["family"], r["selected"]) for r in records if r["selected"]]


def family_state(session, family):
    return engine_state.family_state(session, family)


def set_family(session, family, **changes):
    """Force one family's engine state. Test scaffolding, never product code."""
    engine_state.set_family_state(session, family, **changes)


def engine_of(session):
    return training_engine.engine_summary(session)
