"""Refresh, resume, and the equivalence of the continuous and restored paths.

This is the suite that decides whether Batch 2 actually happened. If the
browser were still the authority for anything factual, a refresh would lose it
-- and the way to prove the browser is *not* the authority is to throw the
browser away, throw the server's in-memory objects away, and check that the
world comes back byte-for-byte.

Two levels:

* **Through the real HTTP path**, so what is exercised is the thing a learner
  touches: the same routes, the same signed cookie, the same repository. The
  refresh is a second ``GET`` of the session; the process restart is the
  application's repository and service being rebuilt from nothing against the
  same database.
* **Through the service directly**, for the scheduler equivalence: an authored
  delayed consequence must fire at the same simulation time, in the same
  order, with the same event id, whether the session stayed in memory the
  whole time or was persisted, discarded and rebuilt half way through.

Nothing here uses a browser timer, and nothing here can depend on real
elapsed time: the service reads no real clock at all, so simulation time moves
only where a test explicitly says so.
"""

import json

import pytest

from tests.workstation_helpers import (Driver, build_service, contact,
                                       file_row, incident, message,
                                       sqlite_uri)
from tests.management_helpers import enroll_http_client

CSRF_META = __import__("re").compile(rb'name="csrf-token" content="([^"]+)"')

WORKSTATION = "/prototype/workstation"
SESSION = "/prototype/api/session"
ACTIONS = "/prototype/api/actions"
DELIVER = "/prototype/api/dev/deliver-next"
DELIVER_CANDIDATE = "/prototype/api/dev/deliver-candidate"
ADVANCE = "/prototype/api/dev/advance"


# ===========================================================================
# Through the real HTTP path
# ===========================================================================

def headers(client):
    match = CSRF_META.search(client.get(WORKSTATION).data)
    assert match
    return {"X-CSRF-Token": match.group(1).decode(),
            "Content-Type": "application/json", "Accept": "application/json"}


def post(client, path, payload):
    response = client.post(path, data=json.dumps(payload), headers=headers(client))
    assert response.status_code in (200, 201), (path, response.status_code,
                                                response.data[:400])
    return response.get_json()


def snapshot(client):
    response = client.get(SESSION, headers={"Accept": "application/json"})
    assert response.status_code == 200, response.data[:400]
    return response.get_json()["snapshot"]


def act(client, action, target=None, params=None):
    payload = {"action": action, "revision": snapshot(client)["session"]["revision"]}
    if target is not None:
        payload["target"] = target
    if params is not None:
        payload["params"] = params
    return post(client, ACTIONS, payload)


#: Which engine candidate delivers which message. Only the ids these suites
#: actually need; the engine's own selection is tested in
#: ``tests/test_rewindsec2_training_engine.py``, without this.
CANDIDATE_FOR_MAIL = {"m-payroll-restructure": "cand-phish-payroll-lure",
                      "m-rate-card": "cand-ransom-rate-card",
                      "m-invoice-amend": "cand-bec-account-change"}


def deliver_until(client, mail_id, limit=8):
    """Put *mail_id* in the mailbox over HTTP.

    Batch 2 walked the authored timeline until this message came up. The
    timeline no longer drives a session, and an engine pulse may legitimately
    select nothing, so the message is asked for by name through the
    development endpoint -- which bypasses probability and nothing else.
    """
    if message(snapshot(client), mail_id):
        return
    candidate = CANDIDATE_FOR_MAIL.get(mail_id)
    if candidate is not None:
        post(client, DELIVER_CANDIDATE, {"candidate": candidate})
        if message(snapshot(client), mail_id):
            return
    for _ in range(limit):
        if message(snapshot(client), mail_id):
            return
        post(client, DELIVER, {})
    raise AssertionError("%s never arrived" % mail_id)


@pytest.fixture
def worked_session(client):
    """A session with real work in it, across five of the eight applications.

    Mail (read, inspect, follow a link), Browser (navigate, sign in), Files
    (inspect), Notes (write), Directory (call). Enough that "the same factual
    world" is a claim with content.
    """
    enroll_http_client(client)
    post(client, "/prototype/api/session/start",
         {"focus": "phishing", "mode": "simulation"})

    deliver_until(client, "m-payroll-restructure")

    # Mail: read it, and inspect a Context Ledger-backed detail.
    act(client, "mail.open", "m-payroll-restructure")
    act(client, "mail.inspect_headers", "m-payroll-restructure")

    # Browser: follow the link and sign in, which is the consequential act.
    followed = act(client, "mail.open_link", "m-payroll-restructure", {"index": 0})
    url = followed["notice"]["url"]
    act(client, "browser.sign_in", None, {"url": url})

    # Let the authored chain run to completion.
    post(client, ADVANCE, {"milliseconds": 120000})

    # Files: an ordinary inspection.
    act(client, "files.inspect", "f-ops-notes")

    # Directory: a call, whose result is withheld until it happens.
    act(client, "directory.call", "dir-priya-menon")

    # Notes: something the learner deliberately wrote.
    created = act(client, "notes.create")
    note_id = created["notice"]["note"]
    act(client, "notes.save", note_id,
        {"title": "Checks", "body": "payroll host is payroll.northbridge.example"})

    return {"note_id": note_id, "url": url}


def test_a_refresh_resumes_the_same_factual_world(client, worked_session):
    before = snapshot(client)

    # A refresh is a fresh page load and a fresh read. Nothing is carried over
    # from the browser: the client discarded everything it had.
    assert client.get(WORKSTATION).status_code == 200
    after = snapshot(client)

    assert after["session"]["revision"] == before["session"]["revision"]
    assert after == before


def test_a_refresh_keeps_the_note_the_learner_wrote(client, worked_session):
    client.get(WORKSTATION)
    notes = snapshot(client)["notes"]
    saved = [n for n in notes if n["id"] == worked_session["note_id"]]
    assert saved, "the note did not survive the refresh"
    assert saved[0]["title"] == "Checks"
    assert "payroll.northbridge.example" in saved[0]["body"]


def test_a_refresh_keeps_the_consequence(client, worked_session):
    """No automatic rewind. The session that opened is still open."""
    client.get(WORKSTATION)
    after = snapshot(client)
    assert incident(after, "inc-account") is not None
    assert after["mail"]["rule"], "the mailbox rule did not survive"
    security = [m for m in after["mail"]["messages"]
                if m["id"] == "m-security-followup"]
    assert security and security[0]["folder"] == "archive"


def test_a_refresh_keeps_an_observed_fact_observed(client, worked_session):
    client.get(WORKSTATION)
    after = snapshot(client)
    entry = message(after, "m-payroll-restructure")
    assert entry["headers"] is not None
    assert entry["headers"]["reply_to"] == "hr-review@nbsystems-secure.example"
    # And an unobserved one stays withheld.
    assert entry["links"][0]["href"] is None


def test_a_refresh_keeps_a_directory_call_result(client, worked_session):
    client.get(WORKSTATION)
    priya = contact(snapshot(client), "dir-priya-menon")
    assert priya["call_result"]


def test_the_world_resumes_after_the_repository_and_service_are_rebuilt(
        client, flask_app, worked_session):
    """The object graph is thrown away and rebuilt against the same database.

    This is the closest a test gets to restarting the process: the cached
    repository and service are discarded, so the next request constructs a new
    engine, a new repository and a new service, and the session is rebuilt
    from its stored snapshot alone.
    """
    import app as app_module

    before = snapshot(client)

    for attribute in ("_rewindsec2_repository", "_rewindsec2_service"):
        assert hasattr(app_module.app, attribute)
        delattr(app_module.app, attribute)

    after = snapshot(client)
    assert after == before

    # And it is still a working session, not a read-only fossil.
    act(client, "mail.open", "m-benefits")
    assert message(snapshot(client), "m-benefits")["read"] is True


def test_the_revision_stays_coherent_across_a_resume(client, worked_session):
    before = snapshot(client)["session"]["revision"]
    client.get(WORKSTATION)
    act(client, "files.inspect", "f-team-rota")
    after = snapshot(client)["session"]["revision"]
    assert after > before


def test_the_debrief_after_a_resume_reports_the_real_session(client,
                                                             worked_session):
    """The results screen reads the server's record, not a browser tally."""
    client.get(WORKSTATION)
    post(client, "/prototype/api/session/end", {})
    debrief = client.get("/prototype/api/session/debrief").get_json()["debrief"]

    assert debrief["decisions"], "no decision was recorded"
    # ``id`` is now the occurrence-scoped storage key (see
    # rewindsec.workstation.consequences); ``decisionId`` is the semantic
    # class every occurrence of a decision shares.
    assert any(d["decisionId"] == "d-phish-credentials"
              for d in debrief["decisions"])
    assert debrief["chains"], "no causal chain was recorded"
    assert debrief["chains"][0]["steps"], "the chain recorded no steps"
    assert debrief["counts"]["observed_facts"] > 0
    assert debrief["counts"]["available_facts"] >= debrief["counts"]["observed_facts"]
    assert debrief["timeline"]


# ===========================================================================
# Scheduler equivalence: continuous versus restored
# ===========================================================================

def run_chain(uri, restart_before_firing):
    """Take the credential decision, then let its chain fire.

    With ``restart_before_firing`` the whole object graph is rebuilt from the
    database between scheduling and firing, which is the case that would break
    if any part of the pending chain lived in a Python object rather than in
    the persisted session.
    """
    service, repository = build_service(uri, ids=["ws-fixed"])
    driver = Driver.start(service, focus="phishing", mode="simulation")

    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.open", "m-payroll-restructure")
    followed = driver.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    driver.act("browser.sign_in", params={"url": followed.notice["url"]})

    if restart_before_firing:
        service, repository = build_service(uri, ids=["ws-fixed"])
        driver = Driver(service, driver.session_id, driver.learner_ref)

    snapshot = driver.advance(120000)
    return snapshot, repository.load(driver.session_id)


def test_a_scheduled_consequence_fires_identically_after_a_restart(tmp_path):
    continuous, continuous_session = run_chain(
        sqlite_uri(tmp_path, "continuous.db"), restart_before_firing=False)
    restored, restored_session = run_chain(
        sqlite_uri(tmp_path, "restored.db"), restart_before_firing=True)

    # The chain actually ran, or the comparison would be vacuous.
    assert incident(continuous, "inc-account") is not None
    assert incident(restored, "inc-account") is not None

    def events(session):
        return [(e.seq, e.event_id, e.type, e.sim_time_ms)
                for e in session.event_log.events()]

    assert events(continuous_session) == events(restored_session)

    def consequences(session):
        return [(c.consequence_id, c.seq, c.sim_time_ms, c.description,
                 c.cause_event_id, c.triggering_action_id,
                 tuple(c.parent_consequence_ids))
                for c in session.incidents.consequences()]

    assert consequences(continuous_session) == consequences(restored_session)

    def mutations(session):
        return [(m.mutation_id, m.namespace, m.key, m.sim_time_ms,
                 m.cause_event_id) for m in session.world.mutations()]

    assert mutations(continuous_session) == mutations(restored_session)

    assert (continuous_session.capture_state()
            == restored_session.capture_state())
    assert json.dumps(continuous, sort_keys=True) == json.dumps(restored,
                                                                sort_keys=True)


def test_the_pending_chain_lives_in_the_persisted_session(tmp_path):
    """Proof the previous test is not passing for a trivial reason.

    Between scheduling and firing there really are pending scheduler entries,
    and they really are in the stored snapshot rather than in a live object.
    """
    uri = sqlite_uri(tmp_path, "pending.db")
    service, repository = build_service(uri, ids=["ws-pending"])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    driver.deliver_until("m-payroll-restructure")
    followed = driver.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    driver.act("browser.sign_in", params={"url": followed.notice["url"]})

    stored = repository.load(driver.session_id)
    pending = [e for e in stored.scheduler.pending()
               if e.spec.type == "consequence.step" and not e.cancelled]
    assert len(pending) == 4, [e.spec.type for e in stored.scheduler.pending()]
    assert all(entry.fire_at_ms > stored.now_ms for entry in pending)

    # And the audit log knows why each of them exists.
    scheduled = [e for e in stored.schedule_audit.entries()
                 if e.event_type == "consequence.step"]
    assert len(scheduled) == 4
    assert all(entry.scheduling_cause_event_id for entry in scheduled)


def test_the_mode_scales_the_delay_on_the_server(tmp_path):
    """Practice brings consequences forward. Decided server-side, and persisted.

    The authored delays are identical; what differs is the mode's scaling
    factor, which is applied when the chain is scheduled and is therefore part
    of what a resume restores.
    """
    def fire_times(mode):
        service, repository = build_service(
            sqlite_uri(tmp_path, "%s.db" % mode), ids=["ws-%s" % mode])
        driver = Driver.start(service, focus="phishing", mode=mode)
        driver.deliver_until("m-payroll-restructure")
        followed = driver.act("mail.open_link", "m-payroll-restructure",
                              {"index": 0})
        driver.act("browser.sign_in", params={"url": followed.notice["url"]})
        stored = repository.load(driver.session_id)
        base = stored.now_ms
        return sorted(e.fire_at_ms - base for e in stored.scheduler.pending()
                      if e.spec.type == "consequence.step" and not e.cancelled)

    practice = fire_times("practice")
    simulation = fire_times("simulation")
    assert len(practice) == len(simulation) == 4
    for soon, later in zip(practice, simulation):
        assert soon < later


def test_two_sessions_with_the_same_seed_schedule_the_same_arrivals(tmp_path):
    """Arrival timing is drawn from the seeded RNG, so it is reproducible.

    Retry Same Simulation depends on this: the same root seed has to give the
    same day, not merely a similar one.
    """
    def arrivals(name):
        service, repository = build_service(
            sqlite_uri(tmp_path, name), seed=987654, ids=["ws-%s" % name])
        driver = Driver.start(service, focus="mixed", mode="simulation")
        for _ in range(4):
            driver.deliver_next()
        stored = repository.load(driver.session_id)
        return [(e.seq, e.type, e.sim_time_ms) for e in stored.event_log.events()]

    assert arrivals("seed-a.db") == arrivals("seed-b.db")


def test_a_different_seed_gives_a_different_day(tmp_path):
    def timings(name, seed):
        service, repository = build_service(
            sqlite_uri(tmp_path, name), seed=seed, ids=["ws-%s" % name])
        driver = Driver.start(service, focus="mixed", mode="simulation")
        stored = repository.load(driver.session_id)
        return [e.fire_at_ms for e in stored.scheduler.pending()]

    assert timings("s1.db", 111) != timings("s2.db", 222)


# ===========================================================================
# Advancing time: one big step and many small ones must agree
# ===========================================================================

def credential_chain_session(tmp_path, name):
    """A session that has just taken the credential decision, chain pending."""
    service, repository = build_service(sqlite_uri(tmp_path, name),
                                        ids=["ws-%s" % name])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    driver.deliver_until("m-payroll-restructure")
    followed = driver.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    driver.act("browser.sign_in", params={"url": followed.notice["url"]})
    return driver, repository


def consequence_times(session):
    return [event.sim_time_ms for event in session.event_log.events()
            if event.type == "consequence.step"]


def test_a_chain_step_fires_at_the_time_it_was_scheduled_for(tmp_path):
    """Not at the moment somebody happened to look.

    Advancing straight to the target and firing everything that had become due
    would stamp four consequences forty seconds apart with one identical
    timestamp, and the debrief would report them as simultaneous. They were
    not; the learner was simply not watching.
    """
    driver, repository = credential_chain_session(tmp_path, "spaced.db")
    scheduled = sorted(entry.fire_at_ms for entry in driver.session().scheduler.pending()
                       if entry.spec.type == "consequence.step" and not entry.cancelled)
    assert len(scheduled) == 4

    driver.advance(120000)
    fired = consequence_times(repository.load(driver.session_id))
    assert fired == scheduled
    assert len(set(fired)) == 4, "the four steps collapsed onto one timestamp"


def test_one_long_advance_and_many_short_ones_produce_the_same_history(tmp_path):
    """The size of the step is infrastructure. It must not be visible in the world.

However the browser paces its heartbeat -- or does not beat at all --
    the session that results is the same session, because the step size is an
    authored constant and the total is just a sum of stated amounts.
    """
    one, one_repo = credential_chain_session(tmp_path, "one.db")
    one.advance(120000)

    many, many_repo = credential_chain_session(tmp_path, "many.db")
    for _ in range(20):
        many.advance(6000)

    one_session = one_repo.load(one.session_id)
    many_session = many_repo.load(many.session_id)

    assert consequence_times(one_session) == consequence_times(many_session)

    # Event *ids* legitimately differ: they are derived from the session
    # identity, and these are two different sessions. What must not differ is
    # what happened, in what order, at what simulation time.
    def history(session):
        return [(e.seq, e.type, e.sim_time_ms)
                for e in session.event_log.events()]

    assert history(one_session) == history(many_session)
    assert one_session.now_ms == many_session.now_ms


def test_a_tick_that_fires_nothing_still_persists_the_clock(tmp_path):
    """Otherwise a consequence further out than one tick could never come due.

    Moving the clock without firing anything does not change the world, so it
    does not bump the revision. It is still a change to the session, and if it
    were dropped the clock would only ever advance in the ticks that happened
    to fire something -- which is to say, never.
    """
    driver, repository = credential_chain_session(tmp_path, "clockonly.db")
    before = repository.load(driver.session_id).now_ms

    # A step far too short to reach the first scheduled step.
    driver.advance(1000)
    assert repository.load(driver.session_id).now_ms == before + 1000
    assert consequence_times(repository.load(driver.session_id)) == []

    # And enough small steps do eventually bring the chain due.
    for _ in range(40):
        driver.advance(1000)
    assert consequence_times(repository.load(driver.session_id))
