"""Batch 5 correction: how a real browser becomes a roster Student.

The gap this closes: a trainer could create a Student, put them in a group and
assign them an assessment, and no actual browser had any way to *become* that
student. The smoke tests seeded the learner cookie by hand, which meant
trainer-created students, group memberships and assignments were not genuinely
end-to-end usable.

The mechanism is the smallest one that works: a bounded, single-use,
purpose-specific enrolment code, minted by a trainer and spent once by a
browser in exchange for a binding. It is not an account system, it grants no
ongoing access, and it stores no new personal data.

What these tests are really pinning down is the *negative* space:

* a learner names a code and nothing else -- no student id, no learner
  reference, no attempt id, no session id -- so there is no parameter through
  which they could ask to be somebody else;
* the persistent ``learner_ref`` is never a public roster identifier, and is
  not what a learner presents;
* the second browser to present the same material is refused, not served.
"""

import json

import pytest

from rewindsec.management.service import ManagementRefused

from tests.management_helpers import (LEARNER, OTHER_LEARNER, build,
                                      sqlite_uri)

THIRD_LEARNER = "learner-mgmt-3"


# ===========================================================================
# Service level
# ===========================================================================

def test_a_trainer_created_student_starts_unbound(tmp_path):
    """``learner_ref is None`` means exactly one thing: nobody has claimed
    this student. It used to be a minted value no browser would ever present,
    which made an unbound roster look bound."""
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    student = management.create_student("Aarti Rao", cohort="Operations A")
    assert student.learner_ref is None
    assert student.origin == "trainer"


def test_claiming_a_code_binds_this_browser_to_that_student(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    student = management.create_student("Aarti Rao")
    code = management.create_enrollment_code(student.student_id)

    bound, newly = management.claim_enrollment(LEARNER, code.code)

    assert newly is True
    assert bound.student_id == student.student_id
    assert bound.learner_ref == LEARNER, "the server's token, not the code"
    assert management.student_for_learner_ref(LEARNER).student_id \
        == student.student_id


def test_the_code_is_not_the_learner_reference(tmp_path):
    """Two separately minted secrets with two different jobs.

    Handing out the learner reference as a roster identifier would mean that
    anyone who saw it could claim that person's entire history, because it is
    the token every session they have ever had is owned by.
    """
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    student = management.create_student("Aarti Rao")
    code = management.create_enrollment_code(student.student_id)
    bound, _ = management.claim_enrollment(LEARNER, code.code)

    assert code.code != bound.learner_ref
    assert code.code != student.student_id


def test_re_presenting_the_code_from_the_same_browser_is_idempotent(tmp_path):
    """A double-submitted form or a reload must not be an error."""
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    student = management.create_student("Aarti Rao")
    code = management.create_enrollment_code(student.student_id)

    first, newly_first = management.claim_enrollment(LEARNER, code.code)
    second, newly_second = management.claim_enrollment(LEARNER, code.code)

    assert newly_first is True and newly_second is False
    assert first.student_id == second.student_id


def test_a_second_browser_replaying_the_code_is_refused(tmp_path):
    """The replay case. Storage decides, so two racing browsers have one
    winner rather than a check that both pass."""
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    student = management.create_student("Aarti Rao")
    code = management.create_enrollment_code(student.student_id)
    management.claim_enrollment(LEARNER, code.code)

    with pytest.raises(ManagementRefused) as excinfo:
        management.claim_enrollment(OTHER_LEARNER, code.code)

    assert excinfo.value.code == "enrollment_unusable"
    assert management.student_for_learner_ref(OTHER_LEARNER) is None
    assert management.get_student(student.student_id).learner_ref == LEARNER


def test_an_unknown_code_is_refused_the_same_way_a_spent_one_is(tmp_path):
    """One message for every unusable code, so the endpoint is not an oracle
    a stranger can use to discover which codes and students exist."""
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    student = management.create_student("Aarti Rao")
    spent = management.create_enrollment_code(student.student_id)
    management.claim_enrollment(LEARNER, spent.code)

    refusals = []
    for candidate, learner in ((spent.code, OTHER_LEARNER),
                               ("enr-not-a-real-code", OTHER_LEARNER)):
        with pytest.raises(ManagementRefused) as excinfo:
            management.claim_enrollment(learner, candidate)
        refusals.append((excinfo.value.code, excinfo.value.message))
    assert refusals[0] == refusals[1], "the two are indistinguishable"


def test_a_browser_cannot_swap_itself_onto_a_second_roster_student(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    first = management.create_student("Aarti Rao")
    second = management.create_student("Ben Okafor")
    management.claim_enrollment(LEARNER,
                                management.create_enrollment_code(
                                    first.student_id).code)
    other_code = management.create_enrollment_code(second.student_id)

    with pytest.raises(ManagementRefused) as excinfo:
        management.claim_enrollment(LEARNER, other_code.code)

    assert excinfo.value.code == "already_enrolled"
    assert management.student_for_learner_ref(LEARNER).student_id \
        == first.student_id


def test_a_bound_student_gets_no_second_code(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    student = management.create_student("Aarti Rao")
    management.claim_enrollment(
        LEARNER, management.create_enrollment_code(student.student_id).code)

    with pytest.raises(ManagementRefused) as excinfo:
        management.create_enrollment_code(student.student_id)
    assert excinfo.value.code == "already_enrolled"


def test_a_legacy_anonymous_identity_cannot_receive_new_session_ownership(
        tmp_path):
    """Legacy rows remain for audit but are not valid production owners."""
    management, workstation, _sessions = build(sqlite_uri(tmp_path))
    anonymous = management.ensure_student_for_learner_ref(LEARNER)
    session_id = workstation.start_session(LEARNER, "mixed", "practice")
    with pytest.raises(ManagementRefused) as excinfo:
        management.register_session(session_id, LEARNER)
    assert excinfo.value.code == "enrollment_required"
    assert management.get_student(anonymous.student_id) == anonymous
    assert management.get_session_ownership(session_id) is None


def test_sessions_started_after_binding_resolve_to_the_roster_student(tmp_path):
    management, workstation, _sessions = build(sqlite_uri(tmp_path))
    roster = management.create_student("Aarti Rao")
    management.claim_enrollment(
        LEARNER, management.create_enrollment_code(roster.student_id).code)

    for mode in ("practice", "simulation"):
        session_id = workstation.start_session(LEARNER, "mixed", mode)
        management.register_session(session_id, LEARNER)
        assert management.get_session_ownership(session_id).student_id \
            == roster.student_id


def test_a_trainer_assignment_becomes_usable_by_the_bound_student(tmp_path):
    """The whole point: roster, group, assignment and attempt joined up."""
    management, _ws, sessions = build(sqlite_uri(tmp_path))
    roster = management.create_student("Aarti Rao")
    group = management.create_group("Operations A")
    management.add_member(group.group_id, roster.student_id)
    assessment = management.create_assessment("Payments", "bec", 2,
                                              status="open")
    management.assign(assessment.assessment_id, "group", group.group_id)

    # Before enrolling, this browser is nobody the assignment reaches.
    with pytest.raises(ManagementRefused) as excinfo:
        management.start_attempt(LEARNER, assessment.assessment_id)
    assert excinfo.value.code == "enrollment_required"

    management.claim_enrollment(
        LEARNER, management.create_enrollment_code(roster.student_id).code)
    attempt, created = management.start_attempt(LEARNER,
                                                assessment.assessment_id)

    assert created is True
    assert attempt.student_id == roster.student_id
    assert attempt.assignment_source == "group"
    assert sessions.load(attempt.session_id).learner_ref == LEARNER
    assert management.get_session_ownership(attempt.session_id).student_id \
        == roster.student_id


def test_the_enrolment_binding_survives_the_object_graph_being_rebuilt(tmp_path):
    from rewindsec.management.ids import SequenceIdSource

    uri = sqlite_uri(tmp_path)
    ids = SequenceIdSource()
    management, _ws, _sessions = build(uri, ids=ids)
    roster = management.create_student("Aarti Rao")
    management.claim_enrollment(
        LEARNER, management.create_enrollment_code(roster.student_id).code)

    rebuilt, _ws2, _sessions2 = build(uri, ids=ids)
    assert rebuilt.student_for_learner_ref(LEARNER).student_id \
        == roster.student_id
    codes = rebuilt.enrollment_codes_for_student(roster.student_id)
    assert len(codes) == 1
    assert codes[0].status == "claimed"
    assert codes[0].claimed_learner_ref == LEARNER
    assert codes[0].claimed_at


# ===========================================================================
# HTTP level -- the real browser flow, with no cookie seeded by hand
# ===========================================================================

def _meta_token(client, path):
    import re
    page = client.get(path)
    match = re.search(rb'name="csrf-token" content="([^"]+)"', page.data)
    assert match, "no csrf meta on %s" % path
    return match.group(1).decode()


def _post(client, path, payload, token=None):
    return client.post(path, json=payload, headers={
        "X-CSRF-Token": token or _meta_token(client, "/prototype/start"),
        "Accept": "application/json"})


def _trainer(flask_app):
    from tests.conftest import INSTRUCTOR_PASSWORD, csrf_for
    client = flask_app.test_client()
    token = csrf_for(client)
    client.post("/instructor/login",
                data={"csrf_token": token, "password": INSTRUCTOR_PASSWORD},
                follow_redirects=True)
    return client


def _seed_roster(flask_app):
    trainer = _trainer(flask_app)
    token = _meta_token(trainer, "/prototype/trainer")
    student = _post(trainer, "/prototype/api/trainer/students",
                    {"display_name": "Enrolled Learner"},
                    token).get_json()["student"]
    assessment = _post(trainer, "/prototype/api/trainer/assessments",
                       {"name": "Enrolment check", "focus": "phishing",
                        "required_interactions": 1, "status": "open"},
                       token).get_json()["assessment"]
    _post(trainer, "/prototype/api/trainer/assignments",
          {"assessment_id": assessment["id"], "target_type": "student",
           "target_id": student["id"]}, token)
    code = _post(trainer,
                 "/prototype/api/trainer/students/%s/enrollment-code"
                 % student["id"], {}, token).get_json()["enrollment"]["code"]
    return trainer, token, student, assessment, code


def test_a_browser_enrols_and_reaches_its_assignment(flask_app, client):
    _trainer_client, _token, student, assessment, code = _seed_roster(flask_app)

    assert client.get("/prototype/api/me").get_json()["student"] is None

    claimed = _post(client, "/prototype/api/enroll", {"code": code})
    assert claimed.status_code == 201, claimed.data
    assert claimed.get_json()["student"]["id"] == student["id"]

    listed = client.get("/prototype/api/assessments",
                        headers={"Accept": "application/json"}).get_json()
    assert [row["id"] for row in listed["assessments"]] == [assessment["id"]]

    started = _post(client, "/prototype/api/session/assessment/start",
                    {"assessment_id": assessment["id"]})
    assert started.status_code == 201, started.data
    assert started.get_json()["snapshot"]["session"]["mode"] == "assessment"


def test_enrolment_trims_surrounding_whitespace_without_weakening_replay(
        flask_app, client, other_client):
    """Pasting a code may add whitespace; the code itself stays exact and
    single-use after that transport-only normalization."""
    _trainer_client, _token, student, _assessment, code = _seed_roster(
        flask_app)

    claimed = _post(client, "/prototype/api/enroll",
                    {"code": "  %s\r\n" % code})
    assert claimed.status_code == 201, claimed.data
    assert claimed.get_json()["student"]["id"] == student["id"]

    replayed = _post(other_client, "/prototype/api/enroll", {"code": code})
    assert replayed.status_code == 409
    assert replayed.get_json()["error"]["code"] == "enrollment_unusable"


def test_the_enrol_route_accepts_a_code_and_nothing_else(flask_app, client):
    """The fields somebody would try to add here are exactly the dangerous
    ones, so they are rejected by name rather than ignored."""
    _trainer_client, _token, student, _assessment, code = _seed_roster(
        flask_app)
    for extra in ("student_id", "learner_ref", "attempt_id", "session_id"):
        refused = _post(client, "/prototype/api/enroll",
                        {"code": code, extra: "anything"})
        assert refused.status_code == 400, extra
        assert refused.get_json()["error"]["code"] == "invalid_request"
    assert client.get("/prototype/api/me").get_json()["student"] is None


def test_naming_a_student_instead_of_a_code_enrols_nobody(flask_app, client):
    _trainer_client, _token, student, _assessment, _code = _seed_roster(
        flask_app)
    refused = _post(client, "/prototype/api/enroll",
                    {"code": student["id"]})
    assert refused.status_code == 409
    assert refused.get_json()["error"]["code"] == "enrollment_unusable"
    assert client.get("/prototype/api/me").get_json()["student"] is None


def test_a_second_browser_cannot_replay_the_code_over_http(
        flask_app, client, other_client):
    _trainer_client, _token, student, assessment, code = _seed_roster(
        flask_app)
    assert _post(client, "/prototype/api/enroll",
                 {"code": code}).status_code == 201

    replayed = _post(other_client, "/prototype/api/enroll", {"code": code})
    assert replayed.status_code == 409
    assert replayed.get_json()["error"]["code"] == "enrollment_unusable"
    assert other_client.get("/prototype/api/me").get_json()["student"] is None

    # And it did not inherit the assignment either.
    refused = _post(other_client, "/prototype/api/session/assessment/start",
                    {"assessment_id": assessment["id"]})
    assert refused.status_code == 409
    assert refused.get_json()["error"]["code"] == "enrollment_required"


def test_the_learner_reference_is_never_rendered_on_the_trainer_roster(
        flask_app, client):
    trainer, _token, _student, _assessment, code = _seed_roster(flask_app)
    assert _post(client, "/prototype/api/enroll",
                 {"code": code}).status_code == 201

    page = trainer.get("/prototype/trainer/students").data.decode()
    listing = json.dumps(
        trainer.get("/prototype/api/trainer/students").get_json())
    for surface in (page, listing):
        assert "learner-" not in surface
        assert "rewindsec2_learner" not in surface


def test_the_enrolment_routes_are_trainer_gated(flask_app, client):
    _trainer_client, _token, student, _assessment, _code = _seed_roster(
        flask_app)
    minted = _post(client,
                   "/prototype/api/trainer/students/%s/enrollment-code"
                   % student["id"], {})
    assert minted.status_code in (401, 403, 302), minted.status_code
    status = client.get("/prototype/api/trainer/students/%s/enrollment"
                        % student["id"])
    assert status.status_code in (401, 403, 302), status.status_code
