"""Trainer roster deletion: removed, refused, and the races between them.

The feature under test is one trainer intent -- "delete this student" -- with
two server-decided outcomes: refused while the student is working, and
removed from the active roster otherwise. These suites assert the decision,
not the button.

The invariant that runs through all of it: **the Student row is never
physically deleted, and nothing historical is ever deleted, rewritten or
rescored by removing a student.** Keeping the row is what makes the races in
section D safe rather than merely unlikely -- an ownership or Attempt insert
that lands after a deletion commits still resolves to a real Student, so no
dangling reference can exist, and the ordinary compensation path brings the
raced work to a safe terminal state.
"""

import re

import pytest
import sqlalchemy as sa

from rewindsec.management import projection
from rewindsec.management.ports import NotFoundError
from rewindsec.management.service import ManagementRefused
from rewindsec.persistence.management_adapter import (
    SqlAlchemyManagementRepository, students_table)
from tests.management_helpers import LEARNER, OTHER_LEARNER, build, sqlite_uri

ACTIVE_WORK_CODE = "student_delete_active_work"
ACTIVE_WORK_MESSAGE = (
    "End the student's active training session before deleting the student.")


def _csrf(client, path="/prototype/start"):
    page = client.get(path)
    match = re.search(rb'name="csrf-token" content="([^"]+)"', page.data)
    assert match
    return match.group(1).decode()


def _post(client, path, payload):
    return client.post(path, json=payload, headers={
        "Accept": "application/json", "X-CSRF-Token": _csrf(client)})


def _delete(trainer, student_id, confirm=True):
    return _post(trainer, "/prototype/api/trainer/students/%s/delete"
                 % student_id, {"confirm": confirm})


def _trainer(flask_app):
    from tests.conftest import login_instructor
    return login_instructor(flask_app.test_client())


def _enrolled(flask_app, name):
    """A roster student, a browser bound to it, and one spare open code."""
    import app as app_module
    with flask_app.app_context():
        manager = app_module.management_service()
        student = manager.create_student(name)
        used = manager.create_enrollment_code(student.student_id)
        spare = manager.create_enrollment_code(student.student_id)
    browser = flask_app.test_client()
    assert _post(browser, "/prototype/api/enroll",
                 {"code": used.code}).status_code == 201
    return student, browser, used, spare


# ---------------------------------------------------------------------------
# A. An unused record: off the roster, retained, only its own metadata cleared
# ---------------------------------------------------------------------------

def test_unused_student_leaves_the_roster_and_only_its_own_metadata_clears(
        tmp_path):
    manager, _workstation, _sessions = build(sqlite_uri(tmp_path))
    doomed = manager.create_student("Delete Me Test")
    keeper = manager.create_student("Untouched Learner")
    group = manager.create_group("Shared Group")
    assessment = manager.create_assessment("Shared assessment", "mixed", 1)
    manager.add_member(group.group_id, doomed.student_id)
    manager.add_member(group.group_id, keeper.student_id)
    code = manager.create_enrollment_code(doomed.student_id)
    doomed_assignment, _replayed = manager.assign(
        assessment.assessment_id, "student", doomed.student_id)
    keeper_assignment, _replayed = manager.assign(
        assessment.assessment_id, "student", keeper.student_id)
    group_assignment, _replayed = manager.assign(
        assessment.assessment_id, "group", group.group_id,
        confirm_duplicate=True)

    result = manager.delete_student(doomed.student_id)

    assert result["kind"] == "removed_from_roster"
    # Off the active roster, but the row itself is deliberately retained --
    # there is no code path that removes it.
    assert doomed.student_id not in {s.student_id
                                     for s in manager.list_students()}
    stored = manager.repository.get_student(doomed.student_id)
    assert stored is not None and stored.is_deleted
    assert stored.learner_ref is None
    assert not manager.list_memberships(student_id=doomed.student_id)
    # The open code is revoked, not destroyed: it stays as an audit row and
    # can never re-establish a binding.
    assert manager.repository.get_enrollment_code(code.code).status \
        == "revoked"
    assignment_ids = {row.assignment_id
                      for row in manager.repository.list_assignments()}
    # Assignments are provenance and are preserved even for an unused record.
    assert doomed_assignment.assignment_id in assignment_ids
    # Nothing shared and nothing belonging to anybody else moved.
    assert keeper_assignment.assignment_id in assignment_ids
    assert group_assignment.assignment_id in assignment_ids
    assert manager.get_group(group.group_id) == group
    assert manager.get_assessment(assessment.assessment_id) == assessment
    assert manager.repository.get_student(keeper.student_id) == keeper
    assert [m.student_id for m in manager.list_memberships(
        group_id=group.group_id)] == [keeper.student_id]


def test_delete_disappears_from_the_roster_and_stays_gone(flask_app):
    import app as app_module
    with flask_app.app_context():
        student = app_module.management_service().create_student(
            "Delete Me Test")
    trainer = _trainer(flask_app)

    listing = trainer.get("/prototype/api/trainer/students").get_json()
    assert student.student_id in {row["id"] for row in listing["students"]}
    assert trainer.get("/prototype/trainer/students/%s"
                       % student.student_id).status_code == 200

    deleted = _delete(trainer, student.student_id)
    assert deleted.status_code == 200
    assert deleted.get_json() == {
        "ok": True, "kind": "removed_from_roster",
        "student_id": student.student_id,
        "message": "Student removed from the active roster."}

    after = trainer.get("/prototype/api/trainer/students").get_json()
    assert student.student_id not in {row["id"] for row in after["students"]}
    assert student.display_name.encode() not in trainer.get(
        "/prototype/trainer/students").data
    # Survives a refresh, and the direct route refuses afterwards.
    assert trainer.get("/prototype/trainer/students/%s"
                       % student.student_id).status_code == 404
    assert _delete(trainer, student.student_id).status_code == 404
    with flask_app.app_context():
        manager = app_module.management_service()
        # Retained, and retained exactly once: no duplicate and no phantom.
        stored = manager.repository.get_student(student.student_id)
        assert stored is not None and stored.is_deleted
        assert len([s for s in manager.repository.list_students()
                    if s.student_id == student.student_id]) == 1


def test_delete_requires_an_explicit_confirmation(flask_app):
    import app as app_module
    with flask_app.app_context():
        student = app_module.management_service().create_student("Unconfirmed")
    trainer = _trainer(flask_app)
    refused = _delete(trainer, student.student_id, confirm=False)
    assert refused.status_code == 400
    assert refused.get_json()["error"]["code"] == "confirmation_required"
    with flask_app.app_context():
        assert app_module.management_service().get_student(
            student.student_id) is not None


def test_enrolled_but_unused_student_is_removed_and_browser_unenrolled(
        flask_app):
    import app as app_module
    student, browser, used, spare = _enrolled(flask_app, "Enrolled Unused")
    trainer = _trainer(flask_app)
    with flask_app.app_context():
        before = len(app_module.management_service().repository.list_students())

    assert _delete(trainer, student.student_id).get_json()["kind"] \
        == "removed_from_roster"

    # The previously enrolled browser is treated exactly like a fresh one.
    assert browser.get("/prototype/api/me").get_json() == {
        "enrolled": False, "student": None}
    refused = _post(browser, "/prototype/api/session/start",
                    {"focus": "mixed", "mode": "practice"})
    assert refused.status_code == 409
    assert refused.get_json()["error"]["code"] == "enrollment_required"
    with flask_app.app_context():
        manager = app_module.management_service()
        # No phantom student was provisioned to absorb the orphaned browser,
        # and none was destroyed either.
        assert len(manager.repository.list_students()) == before
        assert manager.repository.get_student(student.student_id).is_deleted
        # The claimed code stays as audit history; the open one is revoked.
        assert manager.repository.get_enrollment_code(used.code).status \
            != "open"
        assert manager.repository.get_enrollment_code(spare.code).status \
            == "revoked"
    # And the old codes cannot bring the student back.
    for code in (used.code, spare.code):
        replayed = _post(browser, "/prototype/api/enroll", {"code": code})
        assert replayed.status_code in (400, 409)
    with flask_app.app_context():
        manager = app_module.management_service()
        assert len(manager.repository.list_students()) == before
        assert manager.repository.get_student(
            student.student_id).learner_ref is None


# ---------------------------------------------------------------------------
# B. Soft delete -- history exists, so the record stays as evidence
# ---------------------------------------------------------------------------

def _student_with_history(manager, workstation, name="Historical Learner",
                          learner_ref=LEARNER):
    student = manager.create_student(name)
    code = manager.create_enrollment_code(student.student_id)
    # Minted before the binding exists, because a bound student may not be
    # issued another. It stays open, so a deletion has something to revoke.
    spare = manager.create_enrollment_code(student.student_id)
    manager.claim_enrollment(learner_ref, code.code)
    session_id = workstation.start_session(learner_ref, "mixed", "simulation")
    manager.register_session(session_id, learner_ref)
    workstation.end_session(session_id, learner_ref)
    return student, session_id, spare


def test_student_with_history_leaves_the_roster_but_keeps_every_record(
        tmp_path):
    manager, workstation, sessions = build(sqlite_uri(tmp_path))
    group = manager.create_group("Cohort A")
    student, session_id, spare = _student_with_history(manager, workstation)
    manager.add_member(group.group_id, student.student_id)
    ownership_before = manager.get_session_ownership(session_id)
    state_before = sessions.load(session_id).capture_state()

    result = manager.delete_student(student.student_id)

    assert result["kind"] == "removed_from_roster"
    # Off the roster ...
    assert student.student_id not in {s.student_id
                                      for s in manager.list_students()}
    with pytest.raises(NotFoundError):
        manager.require_roster_student(student.student_id)
    # ... but still there, and still resolvable for history.
    row = manager.repository.get_student(student.student_id)
    assert row is not None and row.is_deleted
    assert row.display_name == student.display_name
    assert row.learner_ref is None
    assert manager.historical_student(student.student_id) == row
    assert student.student_id in {s.student_id
                                  for s in manager.known_students()}
    # Historical evidence: untouched, byte for byte.
    assert manager.get_session_ownership(session_id) == ownership_before
    assert sessions.load(session_id).capture_state() == state_before
    # Roster-current state: cleared.
    assert not manager.list_memberships(student_id=student.student_id)
    assert manager.get_group(group.group_id) == group
    assert manager.repository.get_enrollment_code(spare.code).status \
        == "revoked"
    assert manager.student_for_learner_ref(LEARNER) is None


def test_deleted_student_is_absent_from_every_active_roster_surface(tmp_path):
    manager, workstation, _sessions = build(sqlite_uri(tmp_path))
    keeper = manager.create_student("Still Here")
    group = manager.create_group("Cohort A")
    student, _session_id, _spare = _student_with_history(manager, workstation)
    manager.add_member(group.group_id, student.student_id)
    manager.add_member(group.group_id, keeper.student_id)

    manager.delete_student(student.student_id)

    overview = projection.students_overview(manager)
    assert overview["student_total"] == 1
    assert [row["student"].student_id
            for row in overview["rows"]] == [keeper.student_id]
    board = projection.dashboard(manager)
    assert next(card for card in board["cards"]
                if card["id"] == "students")["value"] == "1"
    group_view = projection.group_detail(manager, group.group_id)
    member_ids = {row["student"].student_id for row in group_view["members"]}
    assert member_ids == {keeper.student_id}
    # The picker of students who could be added offers only the active roster.
    assert student.student_id not in {
        s.student_id for s in group_view["candidates"]}
    # The historical session it owns is still on the dashboard, attributed.
    historical = next(row for row in board["sessions"]
                      if row["student_id"] == student.student_id)
    assert historical["student_name"] == student.display_name
    assert historical["student_deleted"] is True


def test_deleted_student_is_rejected_by_every_trainer_mutation_route(
        flask_app):
    import app as app_module
    student, browser, _used, _spare = _enrolled(flask_app, "历史 Learner")
    assert _post(browser, "/prototype/api/session/start",
                 {"focus": "mixed", "mode": "practice"}).status_code == 201
    assert _post(browser, "/prototype/api/session/end", {}).status_code == 200
    trainer = _trainer(flask_app)
    with flask_app.app_context():
        manager = app_module.management_service()
        group = manager.create_group("Target Group")
        assessment = manager.create_assessment("Target assessment", "mixed", 1)

    removed = _delete(trainer, student.student_id)
    assert removed.get_json()["kind"] == "removed_from_roster"

    crafted = [
        trainer.get("/prototype/trainer/students/%s" % student.student_id),
        trainer.get("/prototype/api/trainer/students/%s" % student.student_id),
        _post(trainer, "/prototype/api/trainer/groups/%s/members"
              % group.group_id, {"student_id": student.student_id}),
        _post(trainer, "/prototype/api/trainer/assignments", {
            "assessment_id": assessment.assessment_id,
            "target_type": "student", "target_id": student.student_id}),
        trainer.get("/prototype/api/trainer/assignment-duplicates",
                    query_string={
                        "assessment_id": assessment.assessment_id,
                        "target_type": "student",
                        "target_id": student.student_id}),
        trainer.get("/prototype/api/trainer/assignment-sources", query_string={
            "assessment_id": assessment.assessment_id,
            "student_id": student.student_id}),
        _post(trainer, "/prototype/api/trainer/students/%s/enrollment-code"
              % student.student_id, {}),
        trainer.get("/prototype/api/trainer/students/%s/enrollment"
                    % student.student_id),
        _post(trainer, "/prototype/api/trainer/students/%s/enrollment/reset"
              % student.student_id, {"confirm": True}),
        trainer.get("/prototype/api/trainer/attempts",
                    query_string={"student_id": student.student_id}),
        _delete(trainer, student.student_id),
    ]
    assert [response.status_code for response in crafted] \
        == [404] * len(crafted)

    with flask_app.app_context():
        manager = app_module.management_service()
        assert not manager.list_memberships(student_id=student.student_id)
        assert not [row for row in manager.repository.list_assignments()
                    if row.student_id == student.student_id]
        assert not [row for row in manager.repository.list_enrollment_codes(
            student_id=student.student_id) if row.status == "open"]
        # An ordinary active student is unaffected by any of this.
        healthy = manager.create_student("Perfectly Fine")
    assert _post(trainer, "/prototype/api/trainer/groups/%s/members"
                 % group.group_id,
                 {"student_id": healthy.student_id}).status_code == 201
    assert _post(trainer, "/prototype/api/trainer/students/%s/enrollment-code"
                 % healthy.student_id, {}).status_code == 201


def test_legacy_self_provisioned_rows_are_still_rejected(tmp_path):
    manager, _workstation, _sessions = build(sqlite_uri(tmp_path))
    legacy = manager.ensure_student_for_learner_ref(LEARNER)
    with pytest.raises(NotFoundError):
        manager.delete_student(legacy.student_id)
    assert manager.repository.get_student(legacy.student_id) == legacy


# ---------------------------------------------------------------------------
# Assessment history survives deletion, unchanged and unrescored
# ---------------------------------------------------------------------------

def test_assessment_history_survives_deletion_unchanged(flask_app):
    import app as app_module
    student, browser, _used, _spare = _enrolled(flask_app, "Assessed Learner")
    with flask_app.app_context():
        manager = app_module.management_service()
        assessment = manager.create_assessment("Audit", "mixed", 1,
                                               max_attempts=2)
        manager.assign(assessment.assessment_id, "student", student.student_id)
    assert _post(browser, "/prototype/api/session/assessment/start",
                 {"assessment_id": assessment.assessment_id}).status_code == 201
    assert _post(browser, "/prototype/api/session/end", {}).status_code == 200

    with flask_app.app_context():
        manager = app_module.management_service()
        before = manager.list_attempts(student_id=student.student_id)[0]
        assert not before.is_active
        session_state_before = app_module.workstation_repository().load(
            before.session_id).capture_state()

    trainer = _trainer(flask_app)
    assert _delete(trainer,
                   student.student_id).get_json()["kind"] \
        == "removed_from_roster"

    with flask_app.app_context():
        manager = app_module.management_service()
        after = manager.get_attempt(before.attempt_id)
        assert after.to_state() == before.to_state()
        # Exact-N completion semantics, the finalized result, its versions and
        # its provenance are all exactly what they were.
        assert after.required_interactions == before.required_interactions
        assert after.completed_interactions == before.completed_interactions
        assert after.requirement_met == before.requirement_met
        assert after.is_valid_assessment == before.is_valid_assessment
        assert after.result_state == before.result_state
        assert after.overall == before.overall
        assert after.scoring_version == before.scoring_version
        assert after.rubric_version == before.rubric_version
        assert after.assignment_id == before.assignment_id
        assert after.assignment_source == before.assignment_source
        # The definition and the assignment it came through both remain.
        assert manager.get_assessment(assessment.assessment_id) is not None
        assert manager.repository.get_assignment(
            before.assignment_id) is not None
        # The session, its actions and its score are untouched.
        assert app_module.workstation_repository().load(
            before.session_id).capture_state() == session_state_before
        assert manager.get_session_ownership(
            before.session_id).student_id == student.student_id

    # The historical trainer view still renders, and offers no way to act.
    page = trainer.get("/prototype/trainer/sessions/%s" % before.session_id)
    assert page.status_code == 200
    assert student.display_name.encode() in page.data
    assert b"Removed from roster" in page.data
    assert b"pw-delete-student" not in page.data
    assert b"pw-reset-enrollment" not in page.data
    assert b"pw-assign-btn" not in page.data


# ---------------------------------------------------------------------------
# C. Active work blocks deletion, and a refusal writes nothing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["practice", "simulation", "assessment"])
def test_active_self_directed_work_blocks_deletion_without_changes(
        flask_app, mode):
    import app as app_module
    student, browser, _used, spare = _enrolled(flask_app, "Busy Learner")
    assert _post(browser, "/prototype/api/session/start",
                 {"focus": "mixed", "mode": mode}).status_code == 201
    with flask_app.app_context():
        manager = app_module.management_service()
        owner = manager.repository.list_session_ownership(
            student_id=student.student_id)[0]
        before = app_module.workstation_service().require_owned(
            owner.session_id, owner.learner_ref).capture_state()
        attempts_before = [a.to_state() for a in manager.list_attempts(
            student_id=student.student_id)]

    trainer = _trainer(flask_app)
    refused = _delete(trainer, student.student_id)

    assert refused.status_code == 400
    assert refused.get_json()["error"] == {
        "code": ACTIVE_WORK_CODE, "message": ACTIVE_WORK_MESSAGE}
    with flask_app.app_context():
        manager = app_module.management_service()
        row = manager.get_student(student.student_id)
        assert row is not None and not row.is_deleted
        assert row.learner_ref == owner.learner_ref
        assert manager.repository.get_enrollment_code(spare.code).status \
            == "open"
        assert manager.get_session_ownership(owner.session_id) == owner
        current = app_module.workstation_service().require_owned(
            owner.session_id, owner.learner_ref)
        assert current.is_active and current.capture_state() == before
        assert [a.to_state() for a in manager.list_attempts(
            student_id=student.student_id)] == attempts_before
    # The learner's session keeps working.
    assert browser.get("/prototype/api/session").status_code == 200
    assert _post(browser, "/prototype/api/session/tick", {}).status_code == 200

    # Ending it makes deletion possible, and the outcome is the same one it
    # is for every student: removed from the roster, record retained.
    assert _post(browser, "/prototype/api/session/end", {}).status_code == 200
    assert _delete(trainer, student.student_id).get_json()["kind"] \
        == "removed_from_roster"


def test_active_assigned_assessment_attempt_blocks_deletion(flask_app):
    import app as app_module
    student, browser, _used, _spare = _enrolled(flask_app, "Assigned Busy")
    with flask_app.app_context():
        manager = app_module.management_service()
        assessment = manager.create_assessment("Blocking audit", "mixed", 1,
                                               max_attempts=2)
        manager.assign(assessment.assessment_id, "student", student.student_id)
    assert _post(browser, "/prototype/api/session/assessment/start",
                 {"assessment_id": assessment.assessment_id}).status_code == 201

    trainer = _trainer(flask_app)
    refused = _delete(trainer, student.student_id)
    assert refused.status_code == 400
    assert refused.get_json()["error"]["code"] == ACTIVE_WORK_CODE
    with flask_app.app_context():
        manager = app_module.management_service()
        attempt = manager.list_attempts(student_id=student.student_id)[0]
        assert attempt.is_active
        assert not manager.get_student(student.student_id).is_deleted


def test_active_attempt_blocks_deletion_when_its_session_is_unreadable(
        tmp_path, monkeypatch):
    manager, _workstation, _sessions = build(sqlite_uri(tmp_path))
    student = manager.create_student("Unreadable Attempt Learner")
    code = manager.create_enrollment_code(student.student_id)
    manager.claim_enrollment(LEARNER, code.code)
    attempt, created = manager.start_self_directed_attempt(LEARNER, "mixed")
    assert created and attempt.is_active
    spare_before = manager.repository.list_enrollment_codes(
        student_id=student.student_id)
    # The bound session cannot be read at all. That must not be mistaken for
    # "no active work": the Attempt row is read directly and still says active.
    monkeypatch.setattr(manager, "load_session", lambda _session_id: None)

    with pytest.raises(ManagementRefused) as excinfo:
        manager.delete_student(student.student_id)

    assert excinfo.value.code == ACTIVE_WORK_CODE
    assert excinfo.value.message == ACTIVE_WORK_MESSAGE
    assert manager.get_student(student.student_id).learner_ref == LEARNER
    assert not manager.get_student(student.student_id).is_deleted
    assert manager.get_attempt(attempt.attempt_id).is_active
    assert manager.repository.list_enrollment_codes(
        student_id=student.student_id) == spare_before


# ---------------------------------------------------------------------------
# D. Start versus delete: exactly one winner, decided in storage
#
# The guard is a single conditional UPDATE, so the ordinary races have one
# winner. What the guard cannot cover is an insert that commits *after* the
# deletion has already committed -- no conditional write can see the future.
# That case is covered by the design instead of by the guard: because the
# Student row is retained, a late ownership or Attempt row still resolves,
# and ``register_session``'s compensation invalidates the raced work. The
# last two tests in this section are that case.
# ---------------------------------------------------------------------------

def test_start_wins_the_race_and_the_delete_is_refused(tmp_path, monkeypatch):
    """A session appearing between the check and the write must not be lost."""
    manager, workstation, _sessions = build(sqlite_uri(tmp_path))
    student = manager.create_student("Raced Roster Student")
    used = manager.create_enrollment_code(student.student_id)
    spare = manager.create_enrollment_code(student.student_id)
    manager.claim_enrollment(LEARNER, used.code)
    original = manager.repository.soft_delete_student
    raced = []

    def start_then_delete(*args, **kwargs):
        session_id = workstation.start_session(LEARNER, "mixed", "simulation")
        manager.register_session(session_id, LEARNER)
        raced.append(session_id)
        return original(*args, **kwargs)

    monkeypatch.setattr(manager.repository, "soft_delete_student",
                        start_then_delete)
    with pytest.raises(ManagementRefused) as excinfo:
        manager.delete_student(student.student_id)

    assert excinfo.value.code == "student_delete_changed"
    # The learner keeps a valid, active, correctly owned session.
    assert manager.get_student(student.student_id).learner_ref == LEARNER
    assert not manager.get_student(student.student_id).is_deleted
    assert workstation.require_owned(raced[0], LEARNER).is_active
    assert manager.get_session_ownership(raced[0]).student_id \
        == student.student_id
    # Rolled back whole: the open code was not revoked either.
    assert manager.repository.get_enrollment_code(spare.code).status == "open"
    assert manager.list_memberships(student_id=student.student_id) == ()
    # Retrying once the session has ended succeeds, and the row still stands.
    monkeypatch.undo()
    workstation.end_session(raced[0], LEARNER)
    assert manager.delete_student(student.student_id)["kind"] \
        == "removed_from_roster"
    assert manager.repository.get_student(student.student_id).is_deleted


def test_soft_delete_rolls_back_when_an_attempt_appears_after_the_check(
        tmp_path, monkeypatch):
    manager, workstation, _sessions = build(sqlite_uri(tmp_path))
    student, session_id, spare = _student_with_history(manager, workstation)
    original = manager.repository.soft_delete_student

    def attempt_then_delete(*args, **kwargs):
        manager.start_self_directed_attempt(LEARNER, "mixed")
        return original(*args, **kwargs)

    monkeypatch.setattr(manager.repository, "soft_delete_student",
                        attempt_then_delete)
    with pytest.raises(ManagementRefused) as excinfo:
        manager.delete_student(student.student_id)

    assert excinfo.value.code == "student_delete_changed"
    assert not manager.get_student(student.student_id).is_deleted
    assert manager.get_student(student.student_id).learner_ref == LEARNER
    assert manager.repository.get_enrollment_code(spare.code).status == "open"
    assert manager.list_memberships(student_id=student.student_id) == ()
    assert manager.get_session_ownership(session_id) is not None


def test_delete_wins_the_race_and_the_started_session_is_abandoned(
        flask_app, monkeypatch):
    import app as app_module
    student, browser, _used, _spare = _enrolled(flask_app, "Raced Learner")
    with flask_app.app_context():
        workstation = app_module.workstation_service()
        manager = app_module.management_service()
        original = workstation.start_session
        before = len(manager.repository.list_students())

    def delete_then_create(*args, **kwargs):
        with flask_app.app_context():
            result = app_module.management_service().delete_student(
                student.student_id)
            assert result["kind"] == "removed_from_roster"
        return original(*args, **kwargs)

    monkeypatch.setattr(workstation, "start_session", delete_then_create)
    raced = _post(browser, "/prototype/api/session/start",
                  {"focus": "mixed", "mode": "practice"})

    assert raced.status_code == 409
    assert raced.get_json()["error"]["code"] == "enrollment_required"
    with flask_app.app_context():
        manager = app_module.management_service()
        summaries = manager.session_summaries()
        owned = {row.session_id
                 for row in manager.repository.list_session_ownership()}
        raced_session = next(row for row in summaries
                             if row.session_id not in owned)
        # The losing session is preserved but invalidated -- never left active
        # and never attributed to the deleted student.
        assert raced_session.status == "abandoned"
        assert manager.repository.get_session_ownership(
            raced_session.session_id) is None
        # The Student row is still there -- deleted means off the roster, not
        # gone -- so nothing the loser wrote can dangle.
        stored = manager.repository.get_student(student.student_id)
        assert stored is not None and stored.is_deleted
        assert manager.student_for_learner_ref(raced_session.learner_ref) \
            is None
        # No student was created, duplicated, destroyed or resurrected.
        assert len(manager.repository.list_students()) == before
    # No valid session cookie was handed back, and the browser is unenrolled.
    with browser.session_transaction() as flask_session:
        assert "rewindsec2_session" not in flask_session
    assert browser.get("/prototype/api/me").get_json()["enrolled"] is False


def test_delete_wins_the_assessment_race_and_the_attempt_is_made_safe(
        flask_app, monkeypatch):
    import app as app_module
    student, browser, _used, _spare = _enrolled(flask_app, "Raced Assessment")
    with flask_app.app_context():
        manager = app_module.management_service()
        original = manager.ensure_self_directed_assessment
        before = len(manager.repository.list_students())

    def delete_then_policy(focus):
        assessment = original(focus)
        result = app_module.management_service().delete_student(
            student.student_id)
        assert result["kind"] == "removed_from_roster"
        return assessment

    monkeypatch.setattr(manager, "ensure_self_directed_assessment",
                        delete_then_policy)
    raced = _post(browser, "/prototype/api/session/start",
                  {"focus": "mixed", "mode": "assessment"})

    assert raced.status_code == 409
    assert raced.get_json()["error"]["code"] == "enrollment_required"
    with flask_app.app_context():
        manager = app_module.management_service()
        attempts = manager.list_attempts(student_id=student.student_id)
        # No orphaned *active* Attempt and no orphaned active TrainingSession.
        assert attempts and not any(a.is_active for a in attempts)
        for attempt in attempts:
            assert app_module.workstation_repository().load(
                attempt.session_id).status.value == "abandoned"
            # Every Attempt written by the loser still resolves to a real
            # Student row: this is the referential-integrity invariant.
            assert manager.repository.get_student(
                attempt.student_id) is not None
        stored = manager.repository.get_student(student.student_id)
        assert stored is not None and stored.is_deleted
        assert len(manager.repository.list_students()) == before
    with browser.session_transaction() as flask_session:
        assert "rewindsec2_session" not in flask_session


def test_attempt_inserted_after_the_delete_commits_cannot_dangle(
        tmp_path, monkeypatch):
    """The race the retained row exists to make safe.

    Deletion commits *first*, and only then does the Attempt row land. No
    conditional write can guard against that, so nothing here relies on one.
    What the design guarantees instead is that the Attempt has a real Student
    to point at, that it cannot stay active, and that the learner gets
    nothing usable out of it.
    """
    manager, workstation, _sessions = build(sqlite_uri(tmp_path))
    student = manager.create_student("Late Attempt Learner")
    code = manager.create_enrollment_code(student.student_id)
    manager.claim_enrollment(LEARNER, code.code)
    original = manager.repository.create_attempt
    committed = []

    def delete_then_insert(attempt):
        # The whole deletion transaction commits here, between the service
        # deciding to write this Attempt and the Attempt actually existing.
        if not committed:
            committed.append(manager.delete_student(student.student_id))
            assert committed[0]["kind"] == "removed_from_roster"
        return original(attempt)

    monkeypatch.setattr(manager.repository, "create_attempt",
                        delete_then_insert)
    with pytest.raises(ManagementRefused) as excinfo:
        manager.start_self_directed_attempt(LEARNER, "mixed")

    assert excinfo.value.code == "enrollment_required"
    # 1. No dangling reference. The Attempt landed after the commit, and its
    #    student_id still resolves to a row that is physically present.
    attempts = manager.repository.list_attempts(student_id=student.student_id)
    assert attempts
    for attempt in attempts:
        owner = manager.repository.get_student(attempt.student_id)
        assert owner is not None
        assert owner.student_id == student.student_id
        assert owner.is_deleted
        # 2. It cannot remain active or useable.
        assert not manager.sync_attempt(attempt).is_active
        # 3. Its session, if one was created at all, is terminal.
        if attempt.session_id is not None:
            assert not workstation.require_owned(
                attempt.session_id, LEARNER).is_active
            assert manager.repository.get_session_ownership(
                attempt.session_id) is None
    # 4. The learner cannot start anything now, and holds no valid binding.
    assert manager.student_for_learner_ref(LEARNER) is None
    with pytest.raises(ManagementRefused):
        manager.start_self_directed_attempt(LEARNER, "mixed")
    # 5. Historical identity still resolves, and stays attributed.
    historical = manager.historical_student(student.student_id)
    assert historical is not None
    assert historical.display_name == student.display_name
    # 6. Every stored reference in the whole database resolves.
    known = {row.student_id for row in manager.repository.list_students()}
    for row in manager.repository.list_attempts():
        assert row.student_id in known
    for row in manager.repository.list_session_ownership():
        assert row.student_id in known


def test_late_attempt_over_http_leaves_no_usable_session_for_the_learner(
        flask_app, monkeypatch):
    """The same race end to end: nothing usable reaches the browser."""
    import app as app_module
    student, browser, _used, _spare = _enrolled(flask_app, "Late HTTP Learner")
    with flask_app.app_context():
        manager = app_module.management_service()
        original = manager.repository.create_attempt
        before = len(manager.repository.list_students())

    committed = []

    def delete_then_insert(attempt):
        if not committed:
            result = app_module.management_service().delete_student(
                student.student_id)
            assert result["kind"] == "removed_from_roster"
            committed.append(result)
        return original(attempt)

    with flask_app.app_context():
        monkeypatch.setattr(app_module.management_service().repository,
                            "create_attempt", delete_then_insert)
        raced = _post(browser, "/prototype/api/session/start",
                      {"focus": "mixed", "mode": "assessment"})

    assert raced.status_code == 409
    assert raced.get_json()["error"]["code"] == "enrollment_required"
    # No usable session cookie was handed back.
    with browser.session_transaction() as flask_session:
        assert "rewindsec2_session" not in flask_session
    assert browser.get("/prototype/api/me").get_json() == {
        "enrolled": False, "student": None}
    assert _post(browser, "/prototype/api/session/tick",
                 {}).status_code in (401, 404, 409)

    with flask_app.app_context():
        manager = app_module.management_service()
        # No phantom student, and the real one is retained rather than gone.
        assert len(manager.repository.list_students()) == before
        stored = manager.repository.get_student(student.student_id)
        assert stored is not None and stored.is_deleted
        # Every Attempt in the database still resolves to a Student row --
        # the referential invariant, checked across the whole table.
        known = {row.student_id for row in manager.repository.list_students()}
        for attempt in manager.repository.list_attempts():
            assert attempt.student_id in known
        # And the raced learner's own attempts are all terminal. Scoped to
        # this student: other suites sharing this app database legitimately
        # leave active attempts of their own behind.
        raced_attempts = manager.repository.list_attempts(
            student_id=student.student_id)
        assert raced_attempts
        for attempt in raced_attempts:
            assert not manager.sync_attempt(attempt).is_active


def test_the_repository_offers_no_way_to_remove_a_student_row(tmp_path):
    """The release gate itself: there is no physical-delete path to call.

    A guarded soft delete is only as safe as the absence of an alternative.
    If a hard delete ever comes back -- on the port, on the adapter, or as a
    raw ``students_table.delete()`` in the module -- this fails.
    """
    import inspect

    from rewindsec.management import ports
    from rewindsec.persistence import management_adapter

    for holder in (ports.ManagementRepository,
                   management_adapter.SqlAlchemyManagementRepository):
        assert not [name for name in dir(holder)
                    if "delete" in name and "student" in name
                    and name != "soft_delete_student"]
    # Comments may *mention* it; code may not call it.
    source = "\n".join(
        line for line in inspect.getsource(management_adapter).splitlines()
        if not line.lstrip().startswith("#"))
    assert "students_table.delete()" not in source

    # And the behaviour that follows from it, checked rather than assumed.
    manager, _workstation, _sessions = build(sqlite_uri(tmp_path))
    student = manager.create_student("Never Physically Gone")
    manager.delete_student(student.student_id)
    assert manager.repository.get_student(student.student_id) is not None


# ---------------------------------------------------------------------------
# E. Privacy
# ---------------------------------------------------------------------------

def test_deletion_never_exposes_a_learner_ref_or_a_raw_code(flask_app):
    import app as app_module
    student, _browser, used, spare = _enrolled(flask_app, "Private Learner")
    with flask_app.app_context():
        manager = app_module.management_service()
        learner_ref = manager.get_student(student.student_id).learner_ref
    assert learner_ref

    trainer = _trainer(flask_app)
    response = _delete(trainer, student.student_id)
    body = response.get_data(as_text=True)

    assert set(response.get_json()) == {"ok", "kind", "student_id", "message"}
    for secret in (learner_ref, used.code, spare.code):
        assert secret not in body
    listing = trainer.get("/prototype/trainer/students").get_data(as_text=True)
    for secret in (learner_ref, used.code, spare.code):
        assert secret not in listing


def test_historical_pages_never_expose_a_learner_ref(tmp_path):
    manager, workstation, _sessions = build(sqlite_uri(tmp_path))
    student, session_id, _spare = _student_with_history(manager, workstation)
    manager.delete_student(student.student_id)

    activity = projection.session_activity(manager, session_id)
    assert activity is not None
    assert activity["student"]["deleted"] is True
    assert LEARNER not in repr(activity)
    board = projection.dashboard(manager)
    assert LEARNER not in repr(board)


# ---------------------------------------------------------------------------
# F. Schema: additive, backward compatible, nothing rewritten
#
# The project has no migration framework -- ``manage.py`` says so
# deliberately -- and ``metadata.create_all(checkfirst=True)`` creates missing
# *tables* and never alters an existing one. So the compatibility step in
# ``SqlAlchemyManagementRepository._ensure_additive_columns`` is what gives an
# already-populated simulator.db the ``deleted_at`` column, and it runs from
# ``create_schema()``, which ``app.init_db()`` calls on every startup. These
# tests pin all three cases the release gate names: fresh, pre-change, and
# run-it-twice.
# ---------------------------------------------------------------------------

def _student_columns(uri):
    with sa.create_engine(uri).begin() as conn:
        return [row[1] for row in conn.execute(sa.text(
            "PRAGMA table_info(rewindsec2_students)")).fetchall()]


def test_a_fresh_database_has_the_deletion_column_and_the_flow_works(tmp_path):
    uri = sqlite_uri(tmp_path, "fresh.db")
    manager, _workstation, _sessions = build(uri)

    assert "deleted_at" in _student_columns(uri)
    student = manager.create_student("Fresh Database Student")
    assert manager.delete_student(student.student_id)["kind"] \
        == "removed_from_roster"
    assert manager.repository.get_student(student.student_id).is_deleted
    assert student.student_id not in {s.student_id
                                      for s in manager.list_students()}


def test_existing_database_without_the_column_upgrades_and_stays_active(
        tmp_path):
    """A database created before ``deleted_at`` existed keeps every row active."""
    uri = sqlite_uri(tmp_path, "legacy.db")
    manager, workstation, _sessions = build(uri)
    group = manager.create_group("Legacy Cohort")
    student, session_id, _spare = _student_with_history(
        manager, workstation, name="Predates The Column")
    manager.add_member(group.group_id, student.student_id)
    plain = manager.create_student("Also Predates")
    state_before = workstation.require_owned(session_id, LEARNER).capture_state()

    # Roll the schema back to what it was before this change shipped.
    engine = sa.create_engine(uri)
    with engine.begin() as conn:
        conn.execute(sa.text(
            'ALTER TABLE rewindsec2_students DROP COLUMN deleted_at'))
    assert "deleted_at" not in _student_columns(uri)

    # Ordinary startup is what runs the additive schema step -- exactly the
    # call ``app.init_db()`` makes, on the same repository class.
    repository = SqlAlchemyManagementRepository(sa.create_engine(uri))
    repository.create_schema()

    assert "deleted_at" in _student_columns(uri)
    # Every pre-existing row survives and reads back as *active*.
    reopened = repository.get_student(student.student_id)
    assert reopened is not None
    assert reopened.deleted_at is None and not reopened.is_deleted
    assert reopened.display_name == student.display_name
    assert reopened.reference == student.reference
    assert reopened.learner_ref == LEARNER
    assert repository.get_student(plain.student_id) is not None
    assert [row.student_id for row in repository.list_memberships(
        group_id=group.group_id)] == [student.student_id]
    with sa.create_engine(uri).begin() as conn:
        stored = conn.execute(sa.select(students_table.c.deleted_at)).all()
    assert stored == [(None,), (None,)]

    # And deletion works against the upgraded database, leaving history intact.
    upgraded, upgraded_ws, _s = build(uri)
    assert upgraded.delete_student(student.student_id)["kind"] \
        == "removed_from_roster"
    assert upgraded.repository.get_student(student.student_id).is_deleted
    assert upgraded.get_session_ownership(session_id) is not None
    assert upgraded_ws.require_owned(
        session_id, LEARNER).capture_state() == state_before


def test_the_schema_upgrade_is_idempotent(tmp_path):
    """Repeated startup neither errors, duplicates a column, nor loses a row."""
    uri = sqlite_uri(tmp_path, "repeat.db")
    manager, _workstation, _sessions = build(uri)
    keeper = manager.create_student("Survives Every Startup")
    removed = manager.create_student("Removed Once")
    manager.delete_student(removed.student_id)
    before = {row.student_id: row.to_state()
              for row in manager.repository.list_students()}

    for _run in range(3):
        # A fresh engine and repository each time, as a real restart would be.
        SqlAlchemyManagementRepository(sa.create_engine(uri)).create_schema()

    columns = _student_columns(uri)
    assert columns.count("deleted_at") == 1
    repository = SqlAlchemyManagementRepository(sa.create_engine(uri))
    assert {row.student_id: row.to_state()
            for row in repository.list_students()} == before
    # The deletion state persisted across every restart, unchanged.
    assert repository.get_student(removed.student_id).is_deleted
    assert not repository.get_student(keeper.student_id).is_deleted


def test_delete_reads_no_clock_into_a_simulation_and_no_rng(tmp_path):
    """Deletion is administrative: no simulation stream is drawn from."""
    manager, workstation, _sessions = build(sqlite_uri(tmp_path))
    other, other_session, _spare = _student_with_history(
        manager, workstation, name="Reference Learner",
        learner_ref=OTHER_LEARNER)
    reference = workstation.require_owned(
        other_session, OTHER_LEARNER).capture_state()
    doomed = manager.create_student("Deterministic Delete")
    manager.delete_student(doomed.student_id)
    assert workstation.require_owned(
        other_session, OTHER_LEARNER).capture_state() == reference
    assert manager.repository.get_student(other.student_id) is not None
