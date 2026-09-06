"""Real time must not be able to reach a single fact in the simulation.

The workstation used to advance its clock by however much wall time the server
had measured since the last request. That is a quiet but serious dependency:
the moment a consequence lands becomes a function of machine speed, request
latency, how long a tab spent in the background and whether the process had
been restarted -- none of which are simulation inputs, and none of which are
reproducible.

So the rule this suite enforces is narrow and total. Simulation time moves
**only** when an application operation explicitly says so, and by an amount
that is *stated*:

* ``tick`` advances exactly ``TICK_QUANTUM_MS`` -- a constant, on the server,
  with no parameter through which a caller could name a different one;
* ``dev_advance`` and ``dev_deliver_next`` advance by an amount the caller
  names, and they are prototype tooling.

Everything else -- reading, waiting, streaming, sleeping, being slow, being
fast, being restarted -- moves nothing.

The tests are adversarial about it. Two sessions are given the same seed, the
same identity and the same sequence of application inputs, and are then run
under wildly different real time: one with the process clocks pinned to zero
and no delay at all, one with real sleeps between every step and every clock
in :mod:`time` racing forward at a million seconds a call. Their captured
state must be identical, byte for byte.
"""

import json
import time

import pytest

from rewindsec.workstation.service import TICK_QUANTUM_MS
from tests.workstation_helpers import Driver, build_service, incident, sqlite_uri

CSRF_META = __import__("re").compile(rb'name="csrf-token" content="([^"]+)"')

WORKSTATION = "/prototype/workstation"
SESSION = "/prototype/api/session"
TICK = "/prototype/api/session/tick"
EVENTS = "/prototype/api/events"


# ===========================================================================
# Scaffolding
# ===========================================================================

def credential_run(uri, sleeper, session_id="ws-time"):
    """Take the phishing credential decision, then heartbeat for a while.

    The same script every time: the same seed, the same session id, the same
    actions, the same number of ticks. Only the real time around it differs.
    """
    service, repository = build_service(uri, ids=[session_id])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    sleeper()
    driver.deliver_until("m-payroll-restructure")
    sleeper()
    followed = driver.act("mail.open_link", "m-payroll-restructure",
                          {"index": 0})
    driver.act("browser.sign_in", params={"url": followed.notice["url"]})
    sleeper()
    for _ in range(30):
        driver.tick()
        sleeper()
    return driver, repository


def no_sleep():
    pass


class RacingClock(object):
    """Every call returns a number a million seconds later than the last.

    Deliberately absurd. If any simulation decision were still reading a real
    clock, a clock behaving like this could not possibly produce the same
    session as one pinned to zero.
    """

    def __init__(self, start=0.0, step=1000000.0):
        self.value = start
        self.step = step

    def __call__(self, *args, **kwargs):
        self.value += self.step
        return self.value


def state_of(repository, session_id):
    return repository.load(session_id).capture_state()


# ===========================================================================
# The step is a constant
# ===========================================================================

def test_a_tick_advances_exactly_one_authored_quantum(tmp_path):
    service, repository = build_service(sqlite_uri(tmp_path, "quantum.db"),
                                        ids=["ws-quantum"])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    before = repository.load(driver.session_id).now_ms

    driver.tick()
    assert repository.load(driver.session_id).now_ms == before + TICK_QUANTUM_MS

    driver.tick(times=4)
    assert (repository.load(driver.session_id).now_ms
            == before + TICK_QUANTUM_MS * 5)


def test_the_size_of_a_tick_does_not_depend_on_how_long_the_caller_waited(tmp_path):
    """A slow client must not earn more simulation time than a fast one."""
    service, repository = build_service(sqlite_uri(tmp_path, "slow.db"),
                                        ids=["ws-slow"])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    before = repository.load(driver.session_id).now_ms

    driver.tick()
    time.sleep(0.4)
    driver.tick()

    assert (repository.load(driver.session_id).now_ms
            == before + TICK_QUANTUM_MS * 2)


def test_a_tick_cannot_be_handed_a_duration(tmp_path):
    """There is no parameter for it, so this is a TypeError, not a policy."""
    service, _ = build_service(sqlite_uri(tmp_path, "duration.db"),
                               ids=["ws-duration"])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    with pytest.raises(TypeError):
        service.tick(driver.session_id, driver.learner_ref, 600000)


# ===========================================================================
# The adversarial comparison
# ===========================================================================

def test_wildly_different_real_time_produces_an_identical_session(tmp_path,
                                                                  monkeypatch):
    """The property the whole batch rests on, tested by trying to break it."""
    with monkeypatch.context() as pinned:
        pinned.setattr(time, "monotonic", lambda: 0.0)
        pinned.setattr(time, "perf_counter", lambda: 0.0)
        pinned.setattr(time, "time", lambda: 0.0)
        fast_driver, fast_repo = credential_run(
            sqlite_uri(tmp_path, "fast.db"), no_sleep)

    with monkeypatch.context() as racing:
        racing.setattr(time, "monotonic", RacingClock())
        racing.setattr(time, "perf_counter", RacingClock(step=7919.0))
        racing.setattr(time, "time", RacingClock(start=1.7e9, step=86400.0))
        slow_driver, slow_repo = credential_run(
            sqlite_uri(tmp_path, "slow-run.db"), lambda: time.sleep(0.02))

    fast = state_of(fast_repo, fast_driver.session_id)
    slow = state_of(slow_repo, slow_driver.session_id)

    # Not a vacuous comparison: the chain really did run in both.
    assert incident(fast_driver.snapshot(), "inc-account") is not None
    assert incident(slow_driver.snapshot(), "inc-account") is not None

    assert fast["clock"] == slow["clock"]
    assert json.dumps(fast, sort_keys=True) == json.dumps(slow, sort_keys=True)


def test_the_learner_facing_projection_is_identical_too(tmp_path, monkeypatch):
    """Same inputs, different real time, same thing on the screen."""
    with monkeypatch.context() as pinned:
        pinned.setattr(time, "monotonic", lambda: 0.0)
        first, _ = credential_run(sqlite_uri(tmp_path, "p1.db"), no_sleep)
        first_snapshot = first.snapshot()

    with monkeypatch.context() as racing:
        racing.setattr(time, "monotonic", RacingClock())
        second, _ = credential_run(sqlite_uri(tmp_path, "p2.db"),
                                   lambda: time.sleep(0.01))
        second_snapshot = second.snapshot()

    assert json.dumps(first_snapshot, sort_keys=True) == json.dumps(
        second_snapshot, sort_keys=True)


def test_a_rebuilt_service_continues_the_same_session(tmp_path):
    """Proof there is no per-process timing state left to lose.

    The old anchor lived in the process, so a restart silently changed
    behaviour: the next tick advanced by nothing. Now everything a session
    needs is in the database, and a service built from scratch half way
    through the run reaches exactly the state an uninterrupted one does.
    """
    uri = sqlite_uri(tmp_path, "restart.db")
    service, repository = build_service(uri, ids=["ws-restart"])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    driver.deliver_until("m-payroll-restructure")
    followed = driver.act("mail.open_link", "m-payroll-restructure",
                          {"index": 0})
    driver.act("browser.sign_in", params={"url": followed.notice["url"]})
    for _ in range(15):
        driver.tick()

    # Throw the whole object graph away and build another one on the same data.
    rebuilt_service, rebuilt_repository = build_service(uri, ids=["ws-unused"])
    rebuilt = Driver(rebuilt_service, driver.session_id, driver.learner_ref)
    for _ in range(15):
        rebuilt.tick()

    straight, straight_repo = credential_run(
        sqlite_uri(tmp_path, "straight.db"), no_sleep, session_id="ws-restart")

    assert (state_of(rebuilt_repository, driver.session_id)
            == state_of(straight_repo, straight.session_id))


# ===========================================================================
# Waiting is not an input
# ===========================================================================

def test_waiting_in_real_time_mutates_nothing(tmp_path):
    """No clock, no scheduler, no world, no ledger, no sequence, no revision."""
    service, repository = build_service(sqlite_uri(tmp_path, "wait.db"),
                                        ids=["ws-wait"])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    driver.deliver_until("m-payroll-restructure")
    followed = driver.act("mail.open_link", "m-payroll-restructure",
                          {"index": 0})
    driver.act("browser.sign_in", params={"url": followed.notice["url"]})

    before = state_of(repository, driver.session_id)
    session_before = repository.load(driver.session_id)

    time.sleep(0.6)

    after = state_of(repository, driver.session_id)
    session_after = repository.load(driver.session_id)

    assert after == before
    assert session_after.now_ms == session_before.now_ms
    assert session_after.revision == session_before.revision
    assert ([(e.spec.type, e.fire_at_ms, e.cancelled)
             for e in session_after.scheduler.pending()]
            == [(e.spec.type, e.fire_at_ms, e.cancelled)
                for e in session_before.scheduler.pending()])
    assert (len(list(session_after.event_log.events()))
            == len(list(session_before.event_log.events())))
    assert (len(list(session_after.incidents.consequences()))
            == len(list(session_before.incidents.consequences())))
    assert (len(list(session_after.world.mutations()))
            == len(list(session_before.world.mutations())))


def test_reading_repeatedly_over_real_time_mutates_nothing(tmp_path):
    service, repository = build_service(sqlite_uri(tmp_path, "reads.db"),
                                        ids=["ws-reads"])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    before = state_of(repository, driver.session_id)
    for _ in range(5):
        driver.snapshot()
        time.sleep(0.05)
    assert state_of(repository, driver.session_id) == before


def test_a_consequence_comes_due_only_through_explicit_advancement(tmp_path):
    """Waiting is not how a chain arrives. Asking is."""
    service, repository = build_service(sqlite_uri(tmp_path, "due.db"),
                                        ids=["ws-due"])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    driver.deliver_until("m-payroll-restructure")
    followed = driver.act("mail.open_link", "m-payroll-restructure",
                          {"index": 0})
    driver.act("browser.sign_in", params={"url": followed.notice["url"]})

    pending = [e for e in repository.load(driver.session_id).scheduler.pending()
               if not e.cancelled]
    assert pending, "the chain must actually be scheduled"

    time.sleep(0.5)
    assert incident(driver.snapshot(), "inc-account") is None

    for _ in range(30):
        driver.tick()
    assert incident(driver.snapshot(), "inc-account") is not None


def test_ticks_and_one_long_advance_agree(tmp_path):
    """However the steps are sized, the history that results is the same."""
    stepped, stepped_repo = credential_run(sqlite_uri(tmp_path, "stepped.db"),
                                           no_sleep)

    service, repository = build_service(sqlite_uri(tmp_path, "lump.db"),
                                        ids=["ws-time"])
    lump = Driver.start(service, focus="phishing", mode="simulation")
    lump.deliver_until("m-payroll-restructure")
    followed = lump.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    lump.act("browser.sign_in", params={"url": followed.notice["url"]})
    lump.advance(TICK_QUANTUM_MS * 30)

    assert (state_of(repository, lump.session_id)
            == state_of(stepped_repo, stepped.session_id))


# ===========================================================================
# Through the real HTTP path
# ===========================================================================

def headers(client):
    match = CSRF_META.search(client.get(WORKSTATION).data)
    assert match
    return {"X-CSRF-Token": match.group(1).decode(),
            "Content-Type": "application/json", "Accept": "application/json"}


def start(client, focus="phishing", mode="simulation"):
    response = client.post("/prototype/api/session/start",
                           data=json.dumps({"focus": focus, "mode": mode}),
                           headers=headers(client))
    assert response.status_code == 201
    return response.get_json()["snapshot"]


def stored_state(flask_app, client):
    import app as app_module

    from rewindsec.prototype.api import SESSION_KEY

    with client.session_transaction() as flask_session:
        session_id = flask_session[SESSION_KEY]
    with flask_app.app_context():
        return app_module.workstation_repository().load(
            session_id).capture_state()


def test_a_slow_client_gains_nothing_over_the_wire(client, flask_app):
    snapshot = start(client)
    at_start = snapshot["session"]["sim_time_ms"]

    client.post(TICK, data="{}", headers=headers(client))
    time.sleep(0.5)
    body = client.post(TICK, data="{}", headers=headers(client)).get_json()

    assert (body["snapshot"]["session"]["sim_time_ms"]
            == at_start + TICK_QUANTUM_MS * 2)


def test_leaving_the_session_alone_over_http_changes_nothing(client, flask_app):
    start(client)
    before = stored_state(flask_app, client)
    time.sleep(0.5)
    client.get(SESSION)
    time.sleep(0.2)
    client.get(SESSION)
    assert stored_state(flask_app, client) == before


def test_holding_a_stream_open_does_not_move_the_clock(client, flask_app):
    """Already true of the projection; now it is true of the clock as well."""
    start(client)
    before = stored_state(flask_app, client)
    response = client.get(EVENTS)
    buffer = b""
    for chunk in response.response:
        buffer += chunk
        if b"\n\n" in buffer or len(buffer) >= 4096:
            break
    response.close()
    time.sleep(0.3)
    assert stored_state(flask_app, client) == before
