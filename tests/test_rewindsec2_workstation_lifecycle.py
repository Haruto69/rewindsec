"""A session is a record. Nothing casual gets to replace one.

A learner's session is the factual object this batch exists to protect: a
world, a Context Ledger, an action log, a chain of consequences that actually
happened. The way that record gets lost is never dramatic. It is a page that
booted twice, a bookmarked link with last week's ``?focus=`` on it, a second
tab, a refresh after a back button -- something that *reads* quietly deciding
it also gets to *write*.

So the rule here has two halves, and both are enforced on the server:

* **A GET is a GET.** Rendering the workstation page, or reading the session,
  ends nothing, starts nothing, changes no focus or mode, advances no
  revision and touches no lifecycle. Query parameters are not authority over
  a session that already exists; at most they are reconciled in the address
  bar, which is decoration.
* **Replacing a session is deliberate.** ``POST /api/session/start`` refuses
  with 409 while a live session exists. ``POST /api/session/new`` is the one
  operation allowed to supersede one, it is a POST under CSRF, and it
  *completes* the outgoing session rather than discarding it -- the old record
  stays in the database and stays readable.
"""

import json
import re

import pytest

CSRF_META = re.compile(rb'name="csrf-token" content="([^"]+)"')

WORKSTATION = "/prototype/workstation"
START = "/prototype/api/session/start"
NEW = "/prototype/api/session/new"
SESSION = "/prototype/api/session"
END = "/prototype/api/session/end"


def headers(client):
    match = CSRF_META.search(client.get(WORKSTATION).data)
    assert match
    return {"X-CSRF-Token": match.group(1).decode(),
            "Content-Type": "application/json", "Accept": "application/json"}


def start(client, focus="phishing", mode="simulation"):
    response = client.post(START, data=json.dumps({"focus": focus, "mode": mode}),
                           headers=headers(client))
    assert response.status_code == 201, response.data[:400]
    return response.get_json()["snapshot"]


def cookie_session_id(client):
    from rewindsec.prototype.api import SESSION_KEY

    with client.session_transaction() as flask_session:
        return flask_session.get(SESSION_KEY)


def stored(flask_app, session_id):
    import app as app_module

    with flask_app.app_context():
        return app_module.workstation_repository().load(session_id)


def state(flask_app, session_id):
    return stored(flask_app, session_id).capture_state()


@pytest.fixture
def worked(client, flask_app):
    """A session with real facts in it, so replacing it would cost something."""
    start(client, focus="phishing", mode="simulation")
    session_id = cookie_session_id(client)
    client.post("/prototype/api/dev/deliver-next", data="{}",
                headers=headers(client))
    snapshot = client.get(SESSION).get_json()["snapshot"]
    message_id = snapshot["mail"]["messages"][0]["id"]
    client.post("/prototype/api/actions", headers=headers(client),
                data=json.dumps({"action": "mail.open", "target": message_id,
                                 "revision": snapshot["session"]["revision"]}))
    return session_id


# ===========================================================================
# A page render changes nothing
# ===========================================================================

def test_rendering_the_workstation_page_changes_nothing(client, flask_app,
                                                        worked):
    before = state(flask_app, worked)
    for _ in range(5):
        assert client.get(WORKSTATION).status_code == 200
    assert cookie_session_id(client) == worked
    assert state(flask_app, worked) == before


def test_query_parameters_do_not_replace_the_session(client, flask_app, worked):
    """The heart of it: a different focus and mode in a URL is not an event."""
    before = state(flask_app, worked)

    for query in ("?focus=bec&mode=assessment",
                  "?focus=ransomware&mode=practice",
                  "?focus=mixed",
                  "?mode=assessment",
                  "?focus=&mode=",
                  "?focus=not-a-focus&mode=not-a-mode"):
        assert client.get(WORKSTATION + query).status_code == 200

    assert cookie_session_id(client) == worked
    session = stored(flask_app, worked)
    assert session.is_active
    assert session.focus.value == "phishing"
    assert session.mode.value == "simulation"
    assert state(flask_app, worked) == before


def test_the_session_read_is_unaffected_by_query_parameters(client, flask_app,
                                                            worked):
    before = state(flask_app, worked)
    body = client.get(SESSION + "?focus=bec&mode=assessment").get_json()
    assert body["snapshot"]["session"]["focus"] == "phishing"
    assert body["snapshot"]["session"]["mode"] == "simulation"
    assert state(flask_app, worked) == before


def test_the_root_seed_and_identity_survive_a_mismatched_link(client, flask_app,
                                                              worked):
    """Focus, mode and seed are fixed at creation. A URL cannot renegotiate them."""
    before = stored(flask_app, worked).capture_state()
    client.get(WORKSTATION + "?focus=bec&mode=practice")
    after = stored(flask_app, worked).capture_state()
    for key in ("session_id", "learner_ref", "focus", "mode", "status",
                "revision", "rng", "clock", "scheduler"):
        assert after[key] == before[key], key


# ===========================================================================
# Starting over is deliberate
# ===========================================================================

def test_starting_while_a_session_is_live_is_refused(client, flask_app, worked):
    before = state(flask_app, worked)
    response = client.post(START, headers=headers(client),
                           data=json.dumps({"focus": "bec",
                                            "mode": "simulation"}))
    assert response.status_code == 409
    assert response.get_json()["error"]["code"] == "session_active"
    assert cookie_session_id(client) == worked
    assert state(flask_app, worked) == before
    assert stored(flask_app, worked).is_active


def test_a_refused_start_leaks_no_detail(client, worked):
    response = client.post(START, headers=headers(client),
                           data=json.dumps({"focus": "bec", "mode": "practice"}))
    payload = response.get_json()["error"]
    assert set(payload) == {"code", "message"}
    assert "ws-" not in payload["message"]


def test_the_explicit_new_session_operation_creates_one(client, flask_app,
                                                        worked):
    response = client.post(NEW, headers=headers(client),
                           data=json.dumps({"focus": "bec", "mode": "practice"}))
    assert response.status_code == 201
    snapshot = response.get_json()["snapshot"]
    assert snapshot["session"]["focus"] == "bec"
    assert snapshot["session"]["mode"] == "practice"

    replacement = cookie_session_id(client)
    assert replacement != worked


def test_the_replaced_session_is_completed_not_destroyed(client, flask_app,
                                                         worked):
    """Its record is the point of the whole batch. Superseding is not deleting."""
    before = state(flask_app, worked)
    client.post(NEW, headers=headers(client),
                data=json.dumps({"focus": "bec", "mode": "practice"}))

    old = stored(flask_app, worked)
    assert not old.is_active
    assert old.status.value == "completed"
    # Every fact it recorded is still there.
    assert len(list(old.action_log.actions())) == len(
        before["action_log"]["actions"])
    # Ending the session legitimately adds exactly one more fact since
    # ``before`` was captured: the persisted, immutable Batch 4 scoring
    # result (``rewindsec.scoring.state.finalize``), which the previous
    # batch's numeric placeholder never wrote. Every mutation recorded before
    # that point is untouched -- it is genuinely one more fact added, not a
    # rewrite of history.
    old_state = old.world.capture_state()
    before_mutations = before["world"]["mutations"]
    assert old_state["mutations"][:len(before_mutations)] == before_mutations
    new_mutations = old_state["mutations"][len(before_mutations):]
    assert [m["namespace"] for m in new_mutations] == ["scoring"]
    assert new_mutations[0]["key"] == "result"


def test_a_new_session_is_a_different_session(client, flask_app, worked):
    client.post(NEW, headers=headers(client),
                data=json.dumps({"focus": "bec", "mode": "practice"}))
    fresh = stored(flask_app, cookie_session_id(client))
    assert fresh.session_id != worked
    assert fresh.is_active
    assert not list(fresh.action_log.actions())


def test_the_new_session_operation_needs_a_csrf_token(client, flask_app, worked):
    before = state(flask_app, worked)
    response = client.post(NEW, data=json.dumps({"focus": "bec"}),
                           headers={"Content-Type": "application/json"})
    assert response.status_code in (400, 403)
    assert cookie_session_id(client) == worked
    assert state(flask_app, worked) == before


def test_the_new_session_operation_is_post_only(flask_app):
    rule = [r for r in flask_app.url_map.iter_rules()
            if r.rule == "/prototype/api/session/new"][0]
    assert "GET" not in rule.methods


def test_the_new_session_operation_validates_its_body(client, worked):
    for payload, in (({"focus": "nope", "mode": "practice"},),
                     ({"focus": "bec", "mode": "nope"},),
                     ({"focus": "bec", "world": {}},)):
        response = client.post(NEW, headers=headers(client),
                               data=json.dumps(payload))
        assert response.status_code == 400, payload
        assert response.get_json()["error"]["code"] == "invalid_request"


def test_a_finished_session_may_simply_be_started_over(client, flask_app,
                                                       worked):
    """After End Training there is nothing live, so ``start`` is the plain path."""
    client.post(END, data="{}", headers=headers(client))
    assert not stored(flask_app, worked).is_active

    response = client.post(START, headers=headers(client),
                           data=json.dumps({"focus": "bec", "mode": "practice"}))
    assert response.status_code == 201
    assert cookie_session_id(client) != worked
    # And the finished attempt is still on the record.
    assert stored(flask_app, worked).status.value == "completed"


def test_starting_over_does_not_reach_into_another_learners_session(
        client, other_client, flask_app, worked):
    other = start(other_client, focus="bec", mode="practice")
    other_id = cookie_session_id(other_client)
    before = state(flask_app, other_id)

    client.post(NEW, headers=headers(client),
                data=json.dumps({"focus": "mixed", "mode": "simulation"}))

    assert state(flask_app, other_id) == before
    assert stored(flask_app, other_id).is_active
    assert other["session"]["focus"] == "bec"
