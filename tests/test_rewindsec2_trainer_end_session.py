"""Trainer-authorized ending of a still-active learner session.

The stuck state this feature exists for
---------------------------------------
``/api/session/end`` identifies the session to end from the *learner's* own
signed cookie -- deliberately, because that cookie is the only thing that
proves a browser is the learner. When it is gone (a cleared browser, a new
device, an enrollment that moved on) the session row stays ``active``
forever. :meth:`ManagementService._active_work` then refuses enrollment reset
and roster deletion for as long as that row says active, and nothing in the
system could move it to a terminal state.

These suites assert the *decision*, not the button:

* the trainer path never impersonates the learner -- the owning
  ``learner_ref`` is derived from the persisted ownership record and cannot
  be supplied, guessed or overridden by a caller;
* a session is ended only for the student it actually belongs to;
* it is the ordinary end-of-session transition: history preserved, nothing
  deleted, nothing rescored, no simulation state reset;
* an Assessment attempt ended before its required scored-interaction
  boundary follows the *existing* policy and is recorded ``abandoned`` /
  ``requirement_unmet`` -- never falsely ``completed``;
* it is idempotent and race-safe, and refused without trainer authorization,
  without CSRF, or without an explicit confirmation.
"""

import inspect
import re

import pytest

from rewindsec.management.ports import NotFoundError
from rewindsec.management.service import ManagementRefused, ManagementService
from rewindsec.scoring import state as scoring_state
from tests.management_helpers import (LEARNER, OTHER_LEARNER, build,
                                      enrolled_student, sqlite_uri)

META_CSRF = re.compile(rb'name="csrf-token" content="([^"]+)"')


# ---------------------------------------------------------------------------
# Scaffolding
# ---------------------------------------------------------------------------

def _active_session(management, workstation, learner_ref=LEARNER,
                    name="Stuck Learner", mode="simulation"):
    """A roster student with one genuinely active, owned session."""
    student = enrolled_student(management, learner_ref=learner_ref, name=name)
    session_id = workstation.start_session(learner_ref, "phishing", mode)
    management.register_session(session_id, learner_ref)
    return student, session_id


def _csrf(client, path="/prototype/start"):
    page = client.get(path)
    match = META_CSRF.search(page.data)
    assert match
    return match.group(1).decode()


def _trainer(flask_app):
    from tests.conftest import login_instructor
    return login_instructor(flask_app.test_client())


def _end_url(student_id, session_id):
    return ("/prototype/api/trainer/students/%s/sessions/%s/end"
            % (student_id, session_id))


# ---------------------------------------------------------------------------
# A. The stuck state, and the transition that clears it
# ---------------------------------------------------------------------------

def test_active_session_blocks_enrollment_reset_until_a_trainer_ends_it(
        tmp_path):
    """The whole feature in one test: stuck, then unstuck, nothing destroyed."""
    management, workstation, _sessions = build(sqlite_uri(tmp_path))
    student, session_id = _active_session(management, workstation)

    # Reproduce the stuck state exactly as a trainer meets it.
    with pytest.raises(ManagementRefused) as refusal:
        management.reset_enrollment(student.student_id)
    assert refusal.value.code == "enrollment_reset_active_work"

    result = management.end_session_for_student(student.student_id, session_id)

    assert result["kind"] == "ended"
    assert result["status"] == "completed"
    assert result["student_has_active_work"] is False
    assert workstation.load(session_id).is_active is False

    # The guard that was blocking now lets the reset through.
    _unbound, changed = management.reset_enrollment(student.student_id)
    assert changed is True


def test_ending_preserves_the_session_its_actions_and_its_identity(tmp_path):
    """Never deleted, never reset, never reassigned. Facts survive verbatim."""
    management, workstation, _sessions = build(sqlite_uri(tmp_path))
    student, session_id = _active_session(management, workstation)

    before = workstation.load(session_id)
    before_actions = len(before.action_log.actions())
    before_seed = before.root_seed
    before_focus = before.focus
    before_owner = before.learner_ref

    management.end_session_for_student(student.student_id, session_id)

    after = workstation.load(session_id)
    assert after.session_id == session_id
    assert after.root_seed == before_seed
    assert after.focus == before_focus
    assert after.learner_ref == before_owner
    assert len(after.action_log.actions()) >= before_actions
    # Ownership is untouched: the row still names the same student.
    ownership = management.get_session_ownership(session_id)
    assert ownership.student_id == student.student_id
    assert ownership.learner_ref == before_owner


def test_the_learner_cannot_continue_an_ended_session(tmp_path):
    """A terminal session accepts no further learner work."""
    management, workstation, _sessions = build(sqlite_uri(tmp_path))
    student, session_id = _active_session(management, workstation)
    management.end_session_for_student(student.student_id, session_id)

    before = workstation.load(session_id).revision
    # The ordinary learner advance path is a no-op on a terminal session: it
    # projects, it does not resume, and it writes nothing.
    workstation.tick(session_id, LEARNER)
    assert workstation.load(session_id).is_active is False
    assert workstation.load(session_id).revision == before


# ---------------------------------------------------------------------------
# B. Ownership: derived on the server, never accepted from a caller
# ---------------------------------------------------------------------------

def test_a_session_belonging_to_another_student_is_refused(tmp_path):
    """Mismatched student/session data ends nothing."""
    management, workstation, _sessions = build(sqlite_uri(tmp_path))
    owner, session_id = _active_session(management, workstation)
    other = enrolled_student(management, learner_ref=OTHER_LEARNER,
                             name="Someone Else")

    with pytest.raises(ManagementRefused) as refusal:
        management.end_session_for_student(other.student_id, session_id)
    assert refusal.value.code == "session_not_owned"
    assert workstation.load(session_id).is_active is True
    assert owner.student_id != other.student_id


def test_an_unknown_session_and_an_unknown_student_are_both_refused(tmp_path):
    management, workstation, _sessions = build(sqlite_uri(tmp_path))
    student, _session_id = _active_session(management, workstation)

    with pytest.raises(NotFoundError):
        management.end_session_for_student(student.student_id, "ws-nope")
    with pytest.raises(NotFoundError):
        management.end_session_for_student("stu-nope", "ws-nope")


def test_the_owning_learner_reference_is_never_taken_from_the_caller():
    """There is no parameter through which an owner could arrive."""
    signature = inspect.signature(ManagementService.end_session_for_student)
    assert list(signature.parameters) == ["self", "student_id", "session_id"]


# ---------------------------------------------------------------------------
# C. Idempotence and races
# ---------------------------------------------------------------------------

def test_repeating_the_request_cannot_corrupt_state(tmp_path):
    management, workstation, _sessions = build(sqlite_uri(tmp_path))
    student, session_id = _active_session(management, workstation)

    first = management.end_session_for_student(student.student_id, session_id)
    revision = workstation.load(session_id).revision

    for _ in range(3):
        again = management.end_session_for_student(student.student_id,
                                                   session_id)
        assert again["kind"] == "already_ended"
        assert again["status"] == first["status"]
    # Not one further write.
    assert workstation.load(session_id).revision == revision


def test_a_learner_ending_first_leaves_the_trainer_request_safe(tmp_path):
    """The learner wins the race; the trainer is told, not given a second end."""
    management, workstation, _sessions = build(sqlite_uri(tmp_path))
    student, session_id = _active_session(management, workstation)

    workstation.end_session(session_id, LEARNER)
    revision = workstation.load(session_id).revision

    result = management.end_session_for_student(student.student_id, session_id)
    assert result["kind"] == "already_ended"
    assert result["status"] == "completed"
    assert workstation.load(session_id).revision == revision


# ---------------------------------------------------------------------------
# D. Assessment semantics: the existing policy, unchanged
# ---------------------------------------------------------------------------

def test_an_assessment_ended_early_is_not_recorded_as_completed(tmp_path):
    """Exact-N completion semantics are not weakened by the trainer path.

    The attempt's session completes normally and keeps its finalized Batch 4
    result. What it does not get is a valid completed assessment: the
    required scored-interaction boundary was not satisfied, so
    :meth:`ManagementService.sync_attempt` records ``abandoned`` with
    ``requirement_unmet`` -- exactly as it does when a learner presses End
    Training early.
    """
    management, _workstation, _sessions = build(sqlite_uri(tmp_path))
    enrolled_student(management, learner_ref=LEARNER, name="Assessment Taker")
    attempt, created = management.start_self_directed_attempt(LEARNER, "mixed")
    assert created
    assert attempt.required_interactions >= 1

    result = management.end_session_for_student(attempt.student_id,
                                                attempt.session_id)

    assert result["kind"] == "ended"
    settled = management.get_attempt(attempt.attempt_id)
    assert settled.status == "abandoned"
    assert settled.termination_reason == "requirement_unmet"
    assert settled.completed_interactions < settled.required_interactions
    assert result["attempt_status"] == "abandoned"


def test_a_finalized_score_is_never_recomputed_by_ending_again(tmp_path):
    management, workstation, _sessions = build(sqlite_uri(tmp_path))
    enrolled_student(management, learner_ref=LEARNER, name="Score Keeper")
    attempt, _created = management.start_self_directed_attempt(LEARNER, "mixed")
    management.end_session_for_student(attempt.student_id, attempt.session_id)

    stored = scoring_state.get_result(workstation.load(attempt.session_id))
    settled = management.get_attempt(attempt.attempt_id)

    management.end_session_for_student(attempt.student_id, attempt.session_id)

    again = scoring_state.get_result(workstation.load(attempt.session_id))
    assert (stored is None) == (again is None)
    if stored is not None:
        assert again.to_state() == stored.to_state()
    assert (management.get_attempt(attempt.attempt_id).to_state()
            == settled.to_state())


# ---------------------------------------------------------------------------
# E. The HTTP adapter: authorization, CSRF, confirmation
# ---------------------------------------------------------------------------

def _http_active_session(flask_app):
    """A browser with a real enrolled student and one live session."""
    from tests.management_helpers import enroll_http_client

    browser = flask_app.test_client()
    student = enroll_http_client(browser, name="HTTP Stuck Learner")
    started = browser.post("/prototype/api/session/start",
                           json={"focus": "phishing", "mode": "simulation"},
                           headers={"Accept": "application/json",
                                    "X-CSRF-Token": _csrf(browser)})
    assert started.status_code == 201, started.data
    # The learner snapshot deliberately carries no session id -- that is a
    # Batch 5 leakage control, not an oversight -- so the id is read from the
    # authorized trainer view, which is where a trainer would see it too.
    trainer = _trainer(flask_app)
    detail = trainer.get("/prototype/api/trainer/students/%s" % student["id"])
    active = [row for row in detail.get_json()["sessions"]
              if row["status"] == "active"]
    assert len(active) == 1, active
    return student, active[0]["session_id"]


def test_the_endpoint_refuses_an_unauthenticated_request(flask_app):
    student, session_id = _http_active_session(flask_app)
    anonymous = flask_app.test_client()
    response = anonymous.post(
        _end_url(student["id"], session_id), json={"confirm": True},
        headers={"Accept": "application/json",
                 "X-CSRF-Token": _csrf(anonymous)})
    assert response.status_code in (302, 401, 403), response.status_code

    trainer = _trainer(flask_app)
    detail = trainer.get("/prototype/api/trainer/students/%s" % student["id"])
    rows = [row for row in detail.get_json()["sessions"]
            if row["session_id"] == session_id]
    assert rows and rows[0]["status"] == "active"


def test_the_endpoint_refuses_a_post_without_csrf(flask_app):
    student, session_id = _http_active_session(flask_app)
    trainer = _trainer(flask_app)
    response = trainer.post(_end_url(student["id"], session_id),
                            json={"confirm": True},
                            headers={"Accept": "application/json"})
    assert response.status_code in (400, 403), response.status_code

    detail = trainer.get("/prototype/api/trainer/students/%s" % student["id"])
    rows = [row for row in detail.get_json()["sessions"]
            if row["session_id"] == session_id]
    assert rows and rows[0]["status"] == "active"


def test_the_endpoint_requires_an_explicit_confirmation(flask_app):
    student, session_id = _http_active_session(flask_app)
    trainer = _trainer(flask_app)
    # Absent confirmation, and confirmation explicitly withheld. Both refuse
    # before anything is read, decided or written.
    for payload, code in (({}, "missing_field"),
                          ({"confirm": False}, "confirmation_required"),
                          ({"confirm": "yes"}, "confirmation_required")):
        response = trainer.post(_end_url(student["id"], session_id),
                                json=payload,
                                headers={"Accept": "application/json",
                                         "X-CSRF-Token": _csrf(trainer)})
        assert response.status_code == 400, payload
        assert response.get_json()["error"]["code"] == code, payload

    detail = trainer.get("/prototype/api/trainer/students/%s" % student["id"])
    rows = [row for row in detail.get_json()["sessions"]
            if row["session_id"] == session_id]
    assert rows and rows[0]["status"] == "active"


def test_the_endpoint_accepts_no_owner_or_learner_reference(flask_app):
    """An unrecognised field is refused outright, not quietly ignored."""
    student, session_id = _http_active_session(flask_app)
    trainer = _trainer(flask_app)
    for smuggled in ({"confirm": True, "learner_ref": "learner-someone-else"},
                     {"confirm": True, "student_id": "stu-other"},
                     {"confirm": True, "attempt_id": "att-other"}):
        response = trainer.post(_end_url(student["id"], session_id),
                                json=smuggled,
                                headers={"Accept": "application/json",
                                         "X-CSRF-Token": _csrf(trainer)})
        assert response.status_code == 400, smuggled
        assert response.get_json()["error"]["code"] == "unknown_field"


def test_the_authorized_trainer_ends_the_session_and_then_gets_a_conflict(
        flask_app):
    student, session_id = _http_active_session(flask_app)
    trainer = _trainer(flask_app)

    first = trainer.post(_end_url(student["id"], session_id),
                         json={"confirm": True},
                         headers={"Accept": "application/json",
                                  "X-CSRF-Token": _csrf(trainer)})
    assert first.status_code == 200, first.data
    assert first.get_json()["kind"] == "ended"
    assert first.get_json()["status"] == "completed"

    second = trainer.post(_end_url(student["id"], session_id),
                          json={"confirm": True},
                          headers={"Accept": "application/json",
                                   "X-CSRF-Token": _csrf(trainer)})
    assert second.status_code == 409
    assert second.get_json()["kind"] == "already_ended"

    detail = trainer.get("/prototype/api/trainer/students/%s" % student["id"])
    rows = [row for row in detail.get_json()["sessions"]
            if row["session_id"] == session_id]
    assert rows and rows[0]["status"] == "completed"


def test_the_student_detail_page_offers_the_control_only_while_active(
        flask_app):
    student, session_id = _http_active_session(flask_app)
    trainer = _trainer(flask_app)
    page = trainer.get("/prototype/trainer/students/%s" % student["id"])
    assert b"End session" in page.data
    assert b"End this training session?" in page.data
    assert _end_url(student["id"], session_id).encode() in page.data

    trainer.post(_end_url(student["id"], session_id), json={"confirm": True},
                 headers={"Accept": "application/json",
                          "X-CSRF-Token": _csrf(trainer)})

    after = trainer.get("/prototype/trainer/students/%s" % student["id"])
    assert _end_url(student["id"], session_id).encode() not in after.data
