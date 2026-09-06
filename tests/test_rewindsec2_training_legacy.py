"""Sessions that were already running when the training engine arrived.

A learner who was halfway through a Batch 2 session when this batch was
deployed has a half-played authored timeline and pending arrivals sitting in
their scheduler. Switching them to the engine mid-attempt would change what
they were being asked to do without telling them: different messages, a
different order, and a debrief describing a session they did not have.

So Batch 3 draws a line rather than a migration. A session carries the engine
state that created it, or it does not, and
:func:`rewindsec.training.state.engine_is_active` is the one predicate that
decides which world it lives in:

* **created before Batch 3** -- no engine namespace. The authored timeline
  keeps running exactly as it did, the engine never evaluates, no engine
  candidate is ever selected, and no consequence is suppressed. The session
  finishes the way it started.
* **created since** -- the engine drives everything, and the timeline is not
  consulted.

There is deliberately no third case. What must never happen is half of one and
half of the other: a session with an authored queue still draining while the
engine also delivers, which would give the learner two overlapping
simulations and a causal graph that explains neither.
"""

import pytest

from rewindsec.training import engine as training_engine
from rewindsec.training import progression
from rewindsec.training import state as engine_state
from rewindsec.workstation import service as service_module
from rewindsec.workstation.bootstrap import NS_SESSION
from rewindsec.workstation.content import index as ix
from rewindsec.workstation.errors import InvalidRequestError
from tests.workstation_helpers import (Driver, build_service, incident,
                                       message, sqlite_uri)


def legacy_session(tmp_path, name="legacy.db", focus="phishing",
                   mode="simulation"):
    """A session shaped exactly like one Batch 2 would have created.

    Built by starting a real session and then removing the engine's world
    namespace and its queued pulse, and restoring the authored timeline
    bookkeeping in their place. That is precisely the difference between a
    Batch 2 row and a Batch 3 one, so the result is the row a Batch 2 build
    would have written -- not an approximation of it.
    """
    uri = sqlite_uri(tmp_path, name)
    service, repository = build_service(uri, ids=["ws-%s" % name])
    session_id = service.start_session("learner-test-1", focus, mode)

    session = repository.load(session_id)
    expected = session.revision

    for entry in list(session.scheduler.pending()):
        if entry.spec.type == training_engine.EVALUATION_EVENT_TYPE:
            session.cancel_scheduled(entry.schedule_id, reason="legacy fixture")
    state = session.capture_state()
    state["world"]["components"].pop(engine_state.NS_ENGINE, None)
    session.restore_state(state)

    # The Batch 2 bookkeeping, and one authored arrival queued the way Batch 2
    # queued them.
    session.mutate_world(NS_SESSION, "queue_index", 0)
    session.mutate_world(NS_SESSION, "awaiting", None)
    session.schedule_event(
        service_module.DELIVERY_EVENT_TYPE, delay_ms=10000,
        payload={"index": 0})
    repository.update(session, expected_revision=expected)
    return service, repository, session_id


# ===========================================================================
# The predicate
# ===========================================================================

def test_a_new_session_is_engine_driven(tmp_path):
    service, repository = build_service(sqlite_uri(tmp_path, "new.db"),
                                        ids=["ws-new"])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    assert engine_state.engine_is_active(driver.session())


def test_a_legacy_session_is_not_engine_driven(tmp_path):
    service, repository, session_id = legacy_session(tmp_path)
    assert not engine_state.engine_is_active(repository.load(session_id))


# ===========================================================================
# A legacy session keeps the world it started in
# ===========================================================================

def test_a_legacy_session_still_walks_its_authored_timeline(tmp_path):
    service, repository, session_id = legacy_session(tmp_path)
    driver = Driver(service, session_id)
    driver.advance(120000)

    timeline = ix.timeline_for("phishing")
    delivered = {m["id"] for m in driver.snapshot()["mail"]["messages"]}
    assert timeline[0]["ref"] in delivered


def test_a_legacy_session_never_receives_an_engine_candidate(tmp_path):
    """The failure this whole design exists to prevent.

    An engine arrival in a legacy session would be the two event universes
    mixing: an authored queue still draining while the engine also delivers.
    """
    from rewindsec.training import catalog

    service, repository, session_id = legacy_session(tmp_path)
    driver = Driver(service, session_id)
    driver.advance(600000)

    session = repository.load(session_id)
    assert not engine_state.engine_is_active(session)
    # No candidate occurrence was ever recorded, because no engine state
    # exists to record one in.
    assert engine_state.NS_ENGINE not in session.capture_state()["world"]["components"]
    for candidate in catalog.all_candidates():
        assert engine_state.candidate_state(
            session, candidate.candidate_id)["occurrences"] == 0


def test_no_evaluation_pulse_is_ever_scheduled_for_a_legacy_session(tmp_path):
    service, repository, session_id = legacy_session(tmp_path)
    driver = Driver(service, session_id)
    driver.advance(600000)

    session = repository.load(session_id)
    assert training_engine.pending_evaluation(session) is None
    assert not [event for event in session.event_log.events()
                if event.type == training_engine.EVALUATION_EVENT_TYPE]


def test_a_legacy_session_still_applies_its_consequences_unsuppressed(tmp_path):
    """Containment semantics are Batch 3's. A legacy session does not get them.

    Not because suppression would be wrong, but because it would be a change
    to a simulation that was already running: a learner mid-attempt would see
    a consequence they were expecting simply not arrive.
    """
    service, repository, session_id = legacy_session(tmp_path,
                                                     name="legacy-cons.db",
                                                     focus="ransomware")
    driver = Driver(service, session_id)
    driver.deliver_until("m-rate-card")
    driver.act("mail.open", "m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.open", "f-dl-m-rate-card-0")
    driver.act("browser.support_action", params={"choice": "isolate"})
    driver.advance(600000)

    session = repository.load(session_id)
    assert engine_state.suppressed_steps(session) == []
    assert progression.should_apply(session, "chain-file-incident", "s-file-3")


def test_a_legacy_session_still_persists_resumes_and_projects(tmp_path):
    service, repository, session_id = legacy_session(tmp_path,
                                                     name="legacy-resume.db")
    driver = Driver(service, session_id)
    driver.advance(60000)
    before = driver.snapshot()

    rebuilt, rebuilt_repo = build_service(sqlite_uri(tmp_path,
                                                     "legacy-resume.db"))
    resumed = Driver(rebuilt, session_id)
    assert resumed.snapshot() == before


def test_the_engine_only_operations_refuse_a_legacy_session_gracefully(tmp_path):
    """Deliberate and legible, not a stack trace three layers down."""
    service, repository, session_id = legacy_session(tmp_path,
                                                     name="legacy-refuse.db")
    with pytest.raises(InvalidRequestError):
        service.dev_force_candidate(session_id, "cand-phish-payroll-lure",
                                    "learner-test-1")

    summary = service.dev_engine_state(session_id, "learner-test-1")
    assert summary == {"engine_version": None, "legacy_session": True}


# ===========================================================================
# The two worlds do not mix in either direction
# ===========================================================================

def test_an_engine_session_schedules_no_authored_timeline_arrival(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path, "engine-only.db"),
                               ids=["ws-engine-only"])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    driver.advance(600000)

    session = driver.session()
    assert session.world.get(NS_SESSION, "queue_index", 0) == 0
    # ``world.activity`` is the shared arrival type -- both universes use it,
    # deliberately, so it tells a reader nothing. What distinguishes them is
    # the engine pulse, which a legacy session never has.
    assert [e for e in session.event_log.events()
            if e.type == training_engine.EVALUATION_EVENT_TYPE]


def test_the_engine_is_never_bootstrapped_onto_an_existing_session(tmp_path):
    """Bootstrapping is idempotent, and it is only ever called at creation."""
    service, repository, session_id = legacy_session(tmp_path,
                                                     name="legacy-boot.db")
    driver = Driver(service, session_id)
    for _ in range(20):
        driver.tick()
    driver.advance(600000)
    driver.snapshot()
    assert not engine_state.engine_is_active(repository.load(session_id))


def test_bootstrap_is_idempotent_on_a_session_that_already_has_it(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path, "idem.db"), ids=["ws-idem"])
    driver = Driver.start(service, focus="mixed", mode="simulation")
    session = driver.session()
    before = session.capture_state()
    engine_state.bootstrap(session)
    assert session.capture_state() == before
