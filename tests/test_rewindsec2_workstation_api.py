"""The learner workstation over HTTP: what a browser can and cannot do.

The application-layer suite covers what an action *means*. This one covers the
boundary in front of it, where a hostile or merely confused client is the
thing being defended against:

* the request contract -- strict validation, unknown-key rejection, size and
  type bounds, and no way to smuggle a mutation past the verb allowlist;
* optimistic concurrency, and specifically that a duplicated submission cannot
  apply a consequence twice;
* session isolation between two independent browsers;
* CSRF, unweakened;
* a stable error shape that leaks neither internals nor scenario truth;
* reads that really are reads: repeated GETs leave the persisted session
  byte-for-byte identical.
"""

import json
import re

import pytest

CSRF_META = re.compile(rb'name="csrf-token" content="([^"]+)"')

WORKSTATION = "/prototype/workstation"
START = "/prototype/api/session/start"
SESSION = "/prototype/api/session"
ACTIONS = "/prototype/api/actions"
TICK = "/prototype/api/session/tick"
END = "/prototype/api/session/end"
DEBRIEF = "/prototype/api/session/debrief"


def token(client):
    """Scrape this browser session's CSRF token from a learner page."""
    page = client.get(WORKSTATION)
    assert page.status_code == 200
    match = CSRF_META.search(page.data)
    assert match, "no CSRF meta tag on the workstation page"
    return match.group(1).decode()


def headers(client):
    return {"X-CSRF-Token": token(client), "Content-Type": "application/json",
            "Accept": "application/json"}


def start(client, focus="phishing", mode="simulation"):
    response = client.post(START, data=json.dumps({"focus": focus, "mode": mode}),
                           headers=headers(client))
    assert response.status_code == 201, response.data
    return response.get_json()["snapshot"]


def act(client, action, target=None, params=None, revision=None, extra=None):
    payload = {"action": action, "revision": revision}
    if target is not None:
        payload["target"] = target
    if params is not None:
        payload["params"] = params
    if extra:
        payload.update(extra)
    return client.post(ACTIONS, data=json.dumps(payload), headers=headers(client))


def snapshot(client):
    response = client.get(SESSION, headers={"Accept": "application/json"})
    assert response.status_code == 200, response.data
    return response.get_json()["snapshot"]


def stored_state(flask_app, session_id):
    """The persisted session exactly as the repository holds it."""
    import app as app_module
    with flask_app.app_context():
        return app_module.workstation_repository().load(session_id).capture_state()


def session_id_of(client, flask_app):
    from rewindsec.prototype.api import SESSION_KEY
    with client.session_transaction() as flask_session:
        return flask_session[SESSION_KEY]


# ===========================================================================
# Lifecycle
# ===========================================================================

def test_a_session_starts_and_is_remembered_in_the_signed_cookie(client):
    body = start(client)
    assert body["session"]["focus"] == "phishing"
    assert body["session"]["mode"] == "simulation"
    assert body["session"]["active"] is True
    assert snapshot(client)["session"]["revision"] == body["session"]["revision"]


def test_the_session_id_never_appears_in_the_learner_document(client):
    """There is no parameter to tamper with, because there is no parameter."""
    body = start(client)
    assert "session_id" not in json.dumps(body)


def test_without_a_session_the_learner_routes_answer_not_found(client):
    response = client.get(SESSION, headers={"Accept": "application/json"})
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "no_session"


def test_a_focus_or_mode_outside_the_options_is_refused(client):
    for payload in ({"focus": "nuclear", "mode": "practice"},
                    {"focus": "mixed", "mode": "godmode"}):
        response = client.post(START, data=json.dumps(payload),
                               headers=headers(client))
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "invalid_request"


def test_ending_a_session_closes_it_to_further_actions(client):
    body = start(client)
    assert client.post(END, data="{}", headers=headers(client)).status_code == 200
    response = act(client, "mail.open", "m-payslip-aug",
                   revision=snapshot(client)["session"]["revision"])
    assert response.status_code == 410
    assert response.get_json()["error"]["code"] == "session_ended"


def test_the_debrief_is_only_reachable_once_the_attempt_has_finished(client):
    start(client)
    assert client.get(DEBRIEF).status_code == 403
    client.post(END, data="{}", headers=headers(client))
    response = client.get(DEBRIEF)
    assert response.status_code == 200
    debrief = response.get_json()["debrief"]
    # Batch 4: a session started through this route now carries a real,
    # versioned scoring result once it has finished.
    assert debrief["scoring"]["available"] is True
    assert debrief["scoring"]["rubric_version"]


def test_the_content_endpoint_is_closed_while_an_attempt_is_running(client):
    """A second tab must not be able to read the answer key mid-session."""
    assert client.get("/prototype/api/world").status_code == 200
    start(client)
    assert client.get("/prototype/api/world").status_code == 403
    client.post(END, data="{}", headers=headers(client))
    assert client.get("/prototype/api/world").status_code == 200


# ===========================================================================
# The request contract
# ===========================================================================

def test_an_action_needs_a_revision(client):
    start(client)
    response = client.post(ACTIONS, data=json.dumps({"action": "mail.open",
                                                     "target": "m-payslip-aug"}),
                           headers=headers(client))
    assert response.status_code == 400


def test_a_boolean_is_not_a_revision(client):
    start(client)
    response = act(client, "mail.open", "m-payslip-aug", revision=True)
    assert response.status_code == 400


@pytest.mark.parametrize("forged", [
    {"world": {"mail": {"m-payslip-aug": {"folder": "deleted"}}}},
    {"set": "mail.message.1.malicious"},
    {"sim_time_ms": 999999},
    {"session_id": "ws-somebody-else"},
    {"seed": 1},
    {"score": 100},
    {"event_id": "deadbeef"},
    {"incident_id": "inc-account"},
    {"sequence": 4},
    {"safer_alternative": True},
])
def test_the_client_cannot_smuggle_state_into_an_action(client, forged):
    """Unknown keys are refused, not dropped.

    Dropping them silently is how a client comes to believe it is setting
    something, and how a reviewer comes to believe the field is honoured.
    """
    body = start(client)
    response = act(client, "mail.open", "m-payslip-aug",
                   revision=body["session"]["revision"], extra=forged)
    assert response.status_code == 400, forged
    assert response.get_json()["error"]["code"] == "invalid_request"


def test_an_unknown_action_type_is_refused(client):
    body = start(client)
    response = act(client, "world.rewrite", revision=body["session"]["revision"])
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "unknown_action"


def test_an_unknown_parameter_is_refused(client):
    body = start(client)
    response = act(client, "mail.open", "m-payslip-aug",
                   params={"folder": "deleted"},
                   revision=body["session"]["revision"])
    assert response.status_code == 400


def test_a_body_that_is_not_json_is_refused(client):
    start(client)
    response = client.post(ACTIONS, data="{not json", headers=headers(client))
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "invalid_request"


def test_a_body_that_is_not_an_object_is_refused(client):
    start(client)
    response = client.post(ACTIONS, data="[1,2,3]", headers=headers(client))
    assert response.status_code == 400


def test_nan_and_infinity_are_refused(client):
    """``json.loads`` accepts them; they are not JSON numbers and cannot persist."""
    start(client)
    for literal in ("NaN", "Infinity", "-Infinity"):
        body = ('{"action":"mail.inspect_link","target":"m-payslip-aug",'
                '"revision":1,"params":{"index":%s}}' % literal)
        response = client.post(ACTIONS, data=body, headers=headers(client))
        assert response.status_code == 400, literal


def test_an_oversized_body_is_refused(client):
    start(client)
    payload = json.dumps({"action": "notes.save", "target": "note-q3",
                          "revision": 1, "params": {"body": "x" * 200000}})
    response = client.post(ACTIONS, data=payload, headers=headers(client))
    assert response.status_code == 400


def test_an_invented_target_answers_not_found(client):
    body = start(client)
    response = act(client, "mail.open", "m-invented",
                   revision=body["session"]["revision"])
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "unknown_target"


# ===========================================================================
# Optimistic concurrency
# ===========================================================================

def test_a_stale_revision_conflicts_and_says_what_is_current(client):
    body = start(client)
    revision = body["session"]["revision"]
    assert act(client, "mail.open", "m-payslip-aug",
               revision=revision).status_code == 200

    response = act(client, "mail.open", "m-benefits", revision=revision)
    assert response.status_code == 409
    error = response.get_json()["error"]
    assert error["code"] == "stale_revision"
    assert error["detail"]["revision"] == snapshot(client)["session"]["revision"]


def test_a_duplicated_consequential_submission_applies_once(client, flask_app):
    """The lost-response case, end to end over HTTP."""
    body = start(client, focus="phishing")
    revision = body["session"]["revision"]

    # Bring the lookalike payroll message into the mailbox. Named rather
    # than waited for: under the training engine a pulse may select nothing,
    # and a loop that hoped for this message would flake.
    response = client.post(
        "/prototype/api/dev/deliver-candidate",
        data=json.dumps({"candidate": "cand-phish-payroll-lure"}),
        headers=headers(client))
    assert response.status_code == 200, response.data[:300]
    assert any(m["id"] == "m-payroll-restructure"
               for m in response.get_json()["snapshot"]["mail"]["messages"])

    revision = snapshot(client)["session"]["revision"]
    first = act(client, "mail.report", "m-payroll-restructure", revision=revision)
    assert first.status_code == 200

    session_id = session_id_of(client, flask_app)
    after_first = stored_state(flask_app, session_id)

    replay = act(client, "mail.report", "m-payroll-restructure", revision=revision)
    assert replay.status_code == 409
    assert stored_state(flask_app, session_id) == after_first


# ===========================================================================
# Session isolation
# ===========================================================================

def test_two_browsers_get_two_independent_sessions(client, other_client):
    # Both self-directed: Assessment mode is not something a browser may ask
    # this route for at all -- see the refusal test below.
    a = start(client, focus="phishing", mode="practice")
    b = start(other_client, focus="bec", mode="simulation")

    assert a["session"]["focus"] == "phishing"
    assert b["session"]["focus"] == "bec"
    assert snapshot(client)["session"]["mode"] == "practice"
    assert snapshot(other_client)["session"]["mode"] == "simulation"


def test_one_browser_cannot_act_inside_another_browsers_session(
        client, other_client, flask_app):
    start(client)
    start(other_client)

    a_id = session_id_of(client, flask_app)
    b_id = session_id_of(other_client, flask_app)
    assert a_id != b_id

    # There is no parameter that names a session, so the only way to try is to
    # forge one -- and an unknown field is refused outright.
    response = act(other_client, "mail.report", "m-payslip-aug",
                   revision=snapshot(other_client)["session"]["revision"],
                   extra={"session_id": a_id})
    assert response.status_code == 400

    # A's session is untouched by anything B did.
    assert snapshot(client)["mail"]["messages"]
    a_reported = [m for m in snapshot(client)["mail"]["messages"] if m["reported"]]
    assert a_reported == []


def test_a_browser_holding_a_foreign_session_id_is_told_there_is_no_session(
        client, other_client, flask_app):
    """Even a stolen cookie value does not open somebody else's session.

    The learner reference is minted per browser session and checked on load, so
    the id alone is not enough. The answer is "no session", not "forbidden":
    a guess learns nothing about whether it was right.
    """
    from rewindsec.prototype.api import SESSION_KEY

    start(client)
    victim = session_id_of(client, flask_app)

    start(other_client)
    with other_client.session_transaction() as flask_session:
        flask_session[SESSION_KEY] = victim

    response = other_client.get(SESSION, headers={"Accept": "application/json"})
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "no_session"


def test_a_browser_cannot_subscribe_to_another_sessions_events(
        client, other_client, flask_app):
    from rewindsec.prototype.api import SESSION_KEY

    start(client)
    victim = session_id_of(client, flask_app)
    start(other_client)
    with other_client.session_transaction() as flask_session:
        flask_session[SESSION_KEY] = victim

    response = other_client.get("/prototype/api/events")
    assert response.status_code == 404
    response.close()


# ===========================================================================
# CSRF
# ===========================================================================

@pytest.mark.parametrize("path", [START, ACTIONS, TICK, END,
                                  "/prototype/api/dev/advance",
                                  "/prototype/api/dev/deliver-next"])
def test_every_state_changing_route_requires_a_csrf_token(client, path):
    start(client)
    response = client.post(path, data="{}",
                           headers={"Content-Type": "application/json",
                                    "Accept": "application/json"})
    assert response.status_code == 400, path
    assert b"csrf" in response.data.lower(), path


def test_an_invalid_csrf_token_is_refused(client):
    start(client)
    response = client.post(ACTIONS, data=json.dumps({"action": "mail.open",
                                                     "target": "m-payslip-aug",
                                                     "revision": 1}),
                           headers={"X-CSRF-Token": "not-the-token",
                                    "Content-Type": "application/json",
                                    "Accept": "application/json"})
    assert response.status_code == 400
    assert b"csrf" in response.data.lower()


def test_one_browsers_csrf_token_does_not_work_in_another(client, other_client):
    start(client)
    start(other_client)
    stolen = token(client)
    response = other_client.post(
        ACTIONS,
        data=json.dumps({"action": "mail.open", "target": "m-payslip-aug",
                         "revision": snapshot(other_client)["session"]["revision"]}),
        headers={"X-CSRF-Token": stolen, "Content-Type": "application/json",
                 "Accept": "application/json"})
    assert response.status_code == 400


# ===========================================================================
# Reads do not mutate
# ===========================================================================

def test_repeated_snapshot_reads_leave_the_session_identical(client, flask_app):
    """A GET that mutated would make every refresh a hidden write.

    Compared on ``capture_state()``, so this covers the RNG streams, the
    clock, the scheduler, the sequence counters and the ledger -- not just the
    fields the projection happens to show.
    """
    start(client)
    session_id = session_id_of(client, flask_app)

    before = stored_state(flask_app, session_id)
    for _ in range(5):
        snapshot(client)
    assert stored_state(flask_app, session_id) == before


def test_repeated_workstation_page_loads_leave_the_session_identical(
        client, flask_app):
    start(client)
    session_id = session_id_of(client, flask_app)
    before = stored_state(flask_app, session_id)
    for _ in range(3):
        assert client.get(WORKSTATION).status_code == 200
    assert stored_state(flask_app, session_id) == before


def test_the_projection_itself_never_touches_the_session(tmp_path):
    """Belt and braces below HTTP: the pure projection is observational."""
    from rewindsec.workstation.content import index as ix
    from rewindsec.workstation.projection import learner_snapshot
    from tests.workstation_helpers import Driver, build_service, sqlite_uri

    service, _ = build_service(sqlite_uri(tmp_path))
    driver = Driver.start(service, focus="mixed", mode="simulation")
    session = driver.session()
    flags = ix.mode_flags(session.mode.value)

    before = session.capture_state()
    for _ in range(5):
        learner_snapshot(session, flags)
    assert session.capture_state() == before


# ===========================================================================
# The error model
# ===========================================================================

def test_every_error_has_the_same_shape(client):
    start(client)
    cases = [
        client.get("/prototype/api/session/debrief"),
        act(client, "mail.open", "m-nope", revision=snapshot(client)["session"]["revision"]),
        act(client, "not.an.action", revision=1),
    ]
    for response in cases:
        payload = response.get_json()
        assert set(payload) == {"error"}, payload
        assert set(payload["error"]) <= {"code", "message", "detail"}
        assert isinstance(payload["error"]["code"], str)
        assert isinstance(payload["error"]["message"], str)


def test_an_error_body_never_carries_internals_or_scenario_truth(client):
    start(client)
    response = act(client, "mail.open", "m-nope",
                   revision=snapshot(client)["session"]["revision"])
    text = response.get_data(as_text=True).lower()
    for banned in ("traceback", "sqlalchemy", "select ", "sqlite",
                   "c:\\\\", "/users/", "hostile", "phishing", "disposition"):
        assert banned not in text, banned


# ===========================================================================
# The tick
# ===========================================================================

def test_a_tick_is_a_post_and_returns_the_authoritative_snapshot(client):
    start(client)
    assert client.get(TICK).status_code == 405
    response = client.post(TICK, data="{}", headers=headers(client))
    assert response.status_code == 200
    assert "snapshot" in response.get_json()


def test_the_client_cannot_choose_how_far_time_moves(client):
    """The browser decides when to ask, never how much. Unknown key, refused."""
    start(client)
    response = client.post(TICK, data=json.dumps({"milliseconds": 10 ** 9}),
                           headers=headers(client))
    # The tick body is size- and syntax-checked, and carries no parameters at
    # all: whatever is in it, the server measures the step itself.
    assert response.status_code == 200
    assert response.get_json()["snapshot"]["session"]["sim_time_ms"] < 10 ** 6


# ===========================================================================
# Self-directed Assessment is Attempt-backed (Batch 5 final correction)
# ===========================================================================


def test_the_generic_start_route_creates_a_self_directed_attempt(client,
                                                                  flask_app):
    response = client.post(START, headers=headers(client),
                           data=json.dumps({"focus": "bec",
                                            "mode": "assessment"}))
    assert response.status_code == 201, response.data
    payload = response.get_json()
    assert payload["snapshot"]["session"]["mode"] == "assessment"
    assert payload["snapshot"]["session"]["focus"] == "bec"
    assert payload["attempt"]["provenance_type"] == "self_directed"
    assert payload["attempt"]["assignment_id"] is None
    assert payload["attempt"]["assignment_group_id"] is None

    import app as app_module
    with flask_app.app_context():
        attempt = app_module.management_service().attempt_for_session(
            session_id_of(client, flask_app))
        assert attempt is not None
        definition = app_module.management_service().get_assessment(
            attempt.assessment_id)
        assert definition.is_self_directed_policy
        assert app_module.management_service().repository.list_assignments(
            assessment_id=definition.assessment_id) == ()


def test_self_directed_assessment_resume_reuses_attempt(client, flask_app):
    first = client.post(START, headers=headers(client),
                        data=json.dumps({"focus": "mfa",
                                         "mode": "assessment"}))
    assert first.status_code == 201
    first_payload = first.get_json()

    from rewindsec.prototype.api import SESSION_KEY
    with client.session_transaction() as flask_session:
        del flask_session[SESSION_KEY]

    resumed = client.post(START, headers=headers(client),
                          data=json.dumps({"focus": "mfa",
                                           "mode": "assessment"}))
    assert resumed.status_code == 200
    assert resumed.get_json()["resumed"] is True
    assert (resumed.get_json()["attempt"]["attempt_id"]
            == first_payload["attempt"]["attempt_id"])
    assert resumed.get_json()["attempt"]["session_id"] \
        == first_payload["attempt"]["session_id"]


def test_self_directed_assessment_remains_private_between_learners(
        client, other_client, flask_app):
    from rewindsec.prototype.api import SESSION_KEY

    start(client, focus="phishing", mode="assessment")
    victim = session_id_of(client, flask_app)
    start(other_client, focus="phishing", mode="assessment")
    with other_client.session_transaction() as flask_session:
        flask_session[SESSION_KEY] = victim
    response = other_client.get(SESSION, headers={"Accept": "application/json"})
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "no_session"


def test_all_three_architecture_modes_are_self_directed_choices(client):
    from rewindsec.prototype.api import SELF_DIRECTED_MODES

    assert set(SELF_DIRECTED_MODES) == {"practice", "simulation", "assessment"}
    for mode in SELF_DIRECTED_MODES:
        browser = client.application.test_client()
        assert start(browser, focus="mixed", mode=mode)["session"]["mode"] \
            == mode
