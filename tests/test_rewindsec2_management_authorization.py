"""Batch 5 authorization, ownership and leakage. A release blocker.

Three boundaries, held over HTTP against the real application:

**Learner boundary.** A learner cannot load, act on, resume or read the result
of another learner's session, and cannot change the student/session
association through a request payload. The mechanism is that there is no
session parameter to tamper with -- the active session id lives in the signed
cookie -- plus a server-side ownership check on every path that reads one.

**Trainer boundary.** Every trainer page and every trainer API route requires
the application's real instructor authentication. Not "the path starts with
``/trainer``": the guard is applied by the registration helper in
``rewindsec/prototype/trainer_api.py``, and the blueprint fails closed when no
guard is supplied at all.

**Active-Assessment secrecy.** Adding trainer data APIs must not create a side
channel. A learner in a live attempt gets progress and nothing else -- no
score, no correctness, no disposition, no rubric metadata, no hidden
occurrence or decision identifier.
"""

import json
import re

import pytest

from tests.conftest import login_instructor

TRAINER_PAGES = (
    "/prototype/trainer",
    "/prototype/trainer/students",
    "/prototype/trainer/groups",
    "/prototype/trainer/assessments",
)

TRAINER_APIS = (
    "/prototype/api/trainer/dashboard",
    "/prototype/api/trainer/students",
    "/prototype/api/trainer/groups",
    "/prototype/api/trainer/assessments",
    "/prototype/api/trainer/attempts",
    "/prototype/api/trainer/assignment-sources?assessment_id=a&student_id=b",
    "/prototype/api/trainer/assignment-duplicates"
    "?assessment_id=a&target_type=student&target_id=b",
    "/prototype/api/assignment-provenance?assessment_id=a&student_id=b",
)

META_CSRF = re.compile(rb'name="csrf-token" content="([^"]+)"')


def meta_token(client, path="/prototype/start"):
    """The CSRF token the prototype front end reads from the page."""
    page = client.get(path)
    match = META_CSRF.search(page.data)
    assert match, path
    return match.group(1).decode()


def json_post(client, path, payload, token=None):
    return client.post(path, json=payload, headers={
        "X-CSRF-Token": token or meta_token(client),
        "Accept": "application/json"})


def start_learner_session(client, focus="phishing", mode="practice"):
    response = json_post(client, "/prototype/api/session/start",
                         {"focus": focus, "mode": mode})
    assert response.status_code == 201, response.data
    return response.get_json()["snapshot"]


def trainer_client(flask_app):
    return login_instructor(flask_app.test_client())


def test_trainer_api_rejects_an_impossible_required_count(flask_app):
    from rewindsec.management.assessment_policy import (
        required_interaction_capacity)

    trainer = trainer_client(flask_app)
    capacity = required_interaction_capacity("phishing")
    response = json_post(
        trainer, "/prototype/api/trainer/assessments",
        {"name": "Impossible assessment", "focus": "phishing",
         "required_interactions": capacity + 1, "status": "open",
         "max_attempts": 1})
    assert response.status_code == 400
    error = response.get_json()["error"]
    assert error["code"] == "invalid_field"
    assert "between 1 and %d" % capacity in error["message"]


# ===========================================================================
# Trainer boundary
# ===========================================================================

@pytest.mark.parametrize("path", TRAINER_PAGES)
def test_trainer_pages_require_authorization(client, path):
    response = client.get(path)
    assert response.status_code in (302, 303), response.status_code
    assert "/trainer/login" in response.headers["Location"]


@pytest.mark.parametrize("path", TRAINER_APIS)
def test_trainer_apis_require_authorization(client, path):
    response = client.get(path, headers={"Accept": "application/json"})
    assert response.status_code == 403, (path, response.status_code)


@pytest.mark.parametrize("path", TRAINER_APIS)
def test_a_learner_session_is_not_a_trainer_session(client, path):
    """Ordinary learner authorization reaches no trainer endpoint."""
    start_learner_session(client)
    response = client.get(path, headers={"Accept": "application/json"})
    assert response.status_code == 403, (path, response.status_code)


def test_trainer_writes_require_authorization(client):
    for path, payload in (
            ("/prototype/api/trainer/students", {"display_name": "X"}),
            ("/prototype/api/trainer/groups", {"name": "X"}),
            ("/prototype/api/trainer/assessments",
             {"name": "X", "focus": "mixed", "required_interactions": 1}),
            ("/prototype/api/trainer/assignments",
             {"assessment_id": "a", "target_type": "student",
              "target_id": "b"})):
        response = json_post(client, path, payload)
        assert response.status_code == 403, path


def test_an_authorized_trainer_reaches_the_console(flask_app):
    trainer = trainer_client(flask_app)
    for path in TRAINER_PAGES:
        assert trainer.get(path).status_code == 200, path
    for path in ("/prototype/api/trainer/dashboard",
                 "/prototype/api/trainer/students",
                 "/prototype/api/trainer/groups",
                 "/prototype/api/trainer/assessments"):
        assert trainer.get(path,
                           headers={"Accept": "application/json"}
                           ).status_code == 200, path


def test_trainer_writes_still_require_csrf(flask_app):
    """Batch 5 adds POST routes and weakens nothing that guards them."""
    trainer = trainer_client(flask_app)
    response = trainer.post("/prototype/api/trainer/students",
                            json={"display_name": "No token"})
    assert response.status_code == 400
    assert b"csrf" in response.data.lower()


# ===========================================================================
# Learner boundary
# ===========================================================================

def test_a_learner_cannot_read_or_act_on_another_learners_session(
        flask_app, client, other_client):
    start_learner_session(client)
    # The session id is deliberately absent from the learner projection --
    # it is never sent to a browser -- so it is read from the signed cookie,
    # which is the only place it lives.
    with client.session_transaction() as sess:
        session_id = sess["rewindsec2_session"]

    # The other browser puts the victim's session id in its own cookie -- the
    # closest thing to "changing the id", since no route accepts one.
    with other_client.session_transaction() as sess:
        sess["rewindsec2_session"] = session_id
    token = meta_token(other_client)

    assert other_client.get("/prototype/api/session",
                            headers={"Accept": "application/json"}
                            ).status_code == 404
    assert other_client.get("/prototype/api/session/debrief",
                            headers={"Accept": "application/json"}
                            ).status_code == 404
    assert json_post(other_client, "/prototype/api/session/tick", {},
                     token).status_code == 404
    assert json_post(other_client, "/prototype/api/session/end", {},
                     token).status_code == 404
    assert json_post(other_client, "/prototype/api/actions",
                     {"action": "mail.open", "target": "m-payroll-restructure",
                      "revision": 0}, token).status_code == 404


def test_no_learner_route_accepts_a_session_or_student_identifier(client):
    """Ownership cannot be overridden through a request payload.

    Every unknown field is rejected before the session is even loaded, so
    there is no parameter through which a client could name a session, a
    student or an attempt that is not its own.
    """
    token = meta_token(client)
    for path, base in (("/prototype/api/session/start",
                        {"focus": "phishing", "mode": "practice"}),
                       ("/prototype/api/session/assessment/start",
                        {"assessment_id": "as-anything"})):
        for extra in ("session_id", "student_id", "learner_ref", "attempt_id"):
            payload = dict(base)
            payload[extra] = "somebody-else"
            response = json_post(client, path, payload, token)
            assert response.status_code == 400, (path, extra)
            body = response.get_json()["error"]
            assert body["code"] == "invalid_request", (path, extra)
            assert extra in body["message"], (path, extra)


def test_a_learner_cannot_claim_another_learners_attempt(flask_app, client,
                                                         other_client):
    """Resuming is resolved from the cookie's learner reference, not a body."""
    trainer = trainer_client(flask_app)
    token = meta_token(trainer, "/prototype/trainer")
    student = json_post(trainer, "/prototype/api/trainer/students",
                        {"display_name": "Owned Learner"},
                        token).get_json()["student"]
    assessment = json_post(trainer, "/prototype/api/trainer/assessments",
                           {"name": "Owned check", "focus": "phishing",
                            "required_interactions": 1, "status": "open"},
                           token).get_json()["assessment"]
    json_post(trainer, "/prototype/api/trainer/assignments",
              {"assessment_id": assessment["id"], "target_type": "student",
               "target_id": student["id"]}, token)

    # The learner becomes this student the way a real browser does: by
    # spending an enrolment code. Nothing here writes a cookie by hand, and
    # nothing here ever sees the student's learner reference.
    code = json_post(trainer,
                     "/prototype/api/trainer/students/%s/enrollment-code"
                     % student["id"], {}, token
                     ).get_json()["enrollment"]["code"]
    claimed = json_post(client, "/prototype/api/enroll", {"code": code})
    assert claimed.status_code == 201, claimed.data

    started = json_post(client, "/prototype/api/session/assessment/start",
                        {"assessment_id": assessment["id"]})
    assert started.status_code == 201, started.data
    session_id = started.get_json()["attempt"]["session_id"]

    # A different browser, with the victim's session id but its own reference.
    with other_client.session_transaction() as sess:
        sess["rewindsec2_session"] = session_id
    assert other_client.get("/prototype/api/session/assessment",
                            headers={"Accept": "application/json"}
                            ).status_code == 404
    refused = json_post(other_client,
                        "/prototype/api/session/assessment/start",
                        {"assessment_id": assessment["id"]})
    assert refused.status_code == 409
    error = refused.get_json()["error"]
    assert error["code"] == "not_assigned"
    # And the refusal says nothing about the attempt it declined to hand over.
    assert error.get("detail", {}) == {}
    assert session_id not in json.dumps(refused.get_json())


# ===========================================================================
# Active-Assessment secrecy
# ===========================================================================

#: Key names that would each be a leak in a learner-facing payload. Note that
#: "scored" is *not* here: the progress document's model version is
#: ``rewindsec-scored-interaction/v1``, which says how progress is counted and
#: reveals nothing about how anything was judged.
BANNED_KEYS = frozenset({
    "overall", "score", "scores", "rubric_version", "scoring_version",
    "evidence_model_version", "dimension", "dimensions", "disposition",
    "correct", "valence", "evidence_id", "evidence_ids",
    "resolving_decisions", "opportunity_id", "decision_class", "result",
    "result_state", "na_reason", "explanations", "answer",
})

BANNED_FRAGMENTS = ("rewindsec-rubric", "rewindsec-scoring",
                    "rewindsec-evidence-model", "resolving_decision",
                    "decision_class", "opportunity_id")


def _walk(value, path="$"):
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            for pair in _walk(item, "%s.%s" % (path, key)):
                yield pair
    elif isinstance(value, list):
        for index, item in enumerate(value):
            for pair in _walk(item, "%s[%d]" % (path, index)):
                yield pair


def _assessment_learner_payloads(flask_app, client):
    """Start a real attempt and return the learner-facing documents."""
    trainer = trainer_client(flask_app)
    token = meta_token(trainer, "/prototype/trainer")
    student = json_post(trainer, "/prototype/api/trainer/students",
                        {"display_name": "Secrecy Learner"},
                        token).get_json()["student"]
    assessment = json_post(trainer, "/prototype/api/trainer/assessments",
                           {"name": "Secrecy check", "focus": "phishing",
                            "required_interactions": 2, "status": "open"},
                           token).get_json()["assessment"]
    json_post(trainer, "/prototype/api/trainer/assignments",
              {"assessment_id": assessment["id"], "target_type": "student",
               "target_id": student["id"]}, token)

    code = json_post(trainer,
                     "/prototype/api/trainer/students/%s/enrollment-code"
                     % student["id"], {}, token
                     ).get_json()["enrollment"]["code"]
    assert json_post(client, "/prototype/api/enroll",
                     {"code": code}).status_code == 201

    started = json_post(client, "/prototype/api/session/assessment/start",
                        {"assessment_id": assessment["id"]})
    assert started.status_code == 201, started.data

    headers = {"Accept": "application/json"}
    return {
        "start": started.get_json(),
        "assessments": client.get("/prototype/api/assessments",
                                  headers=headers).get_json(),
        "attempt": client.get("/prototype/api/session/assessment",
                              headers=headers).get_json(),
    }


def test_an_active_attempt_leaks_no_score_or_answer_metadata(flask_app, client):
    payloads = _assessment_learner_payloads(flask_app, client)
    for name in ("assessments", "attempt"):
        for where, _value in _walk(payloads[name]):
            key = where.rsplit(".", 1)[-1].split("[")[0]
            assert key not in BANNED_KEYS, (name, where)
    for name, document in payloads.items():
        text = json.dumps(document).lower()
        for fragment in BANNED_FRAGMENTS:
            assert fragment not in text, (name, fragment)


def test_an_active_attempt_reports_progress_and_only_progress(flask_app, client):
    payloads = _assessment_learner_payloads(flask_app, client)
    progress = payloads["attempt"]["attempt"]["progress"]
    assert set(progress) == {"model_version", "required", "completed",
                             "remaining", "presented", "met"}
    assert progress["model_version"] == "rewindsec-scored-interaction/v1"
    assert progress["completed"] == 0


def test_the_debrief_is_still_closed_while_an_attempt_runs(flask_app, client):
    """Batch 5 adds routes to an active attempt and opens no new door.

    The debrief has refused an active session in every mode since Batch 2;
    that refusal is what keeps the answer key out of a live attempt, and
    nothing in the assessment wiring relaxes it.
    """
    _assessment_learner_payloads(flask_app, client)
    response = client.get("/prototype/api/session/debrief",
                          headers={"Accept": "application/json"})
    assert response.status_code == 403, response.status_code
    assert response.get_json()["error"]["code"] == "forbidden"


def test_the_fixture_world_stays_closed_during_an_attempt(flask_app, client):
    """The answer key was already closed mid-session; Batch 5 keeps it closed."""
    _assessment_learner_payloads(flask_app, client)
    response = client.get("/prototype/api/world",
                          headers={"Accept": "application/json"})
    assert response.status_code == 403
