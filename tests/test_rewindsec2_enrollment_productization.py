"""Post-release enrollment, roster, activity and learner-UI invariants."""

import re

import pytest

from rewindsec.management import projection
from rewindsec.management.service import ManagementRefused
from tests.management_helpers import (LEARNER, OTHER_LEARNER, build,
                                      enrolled_student, sqlite_uri)
from tests.workstation_helpers import Driver


def _csrf(client, path="/prototype/start"):
    page = client.get(path)
    match = re.search(rb'name="csrf-token" content="([^"]+)"', page.data)
    assert match
    return match.group(1).decode()


def _post(client, path, payload):
    return client.post(path, json=payload, headers={
        "Accept": "application/json", "X-CSRF-Token": _csrf(client)})


def _counts(app):
    import app as app_module
    with app.app_context():
        manager = app_module.management_service()
        return {
            "students": len(manager.repository.list_students()),
            "owners": len(manager.repository.list_session_ownership()),
            "attempts": len(manager.list_attempts()),
            "sessions": len(manager.session_summaries()),
        }


def test_fresh_identity_reads_are_read_only(flask_app):
    browser = flask_app.test_client()
    before = _counts(flask_app)

    me = browser.get("/prototype/api/me").get_json()
    assessments = browser.get("/prototype/api/assessments").get_json()

    assert me == {"enrolled": False, "student": None}
    assert assessments == {"assessments": []}
    assert _counts(flask_app) == before


@pytest.mark.parametrize("mode", ["practice", "simulation", "assessment"])
def test_unenrolled_self_directed_start_creates_nothing(flask_app, mode):
    browser = flask_app.test_client()
    before = _counts(flask_app)

    refused = _post(browser, "/prototype/api/session/start",
                    {"focus": "mixed", "mode": mode})

    assert refused.status_code == 409
    assert refused.get_json()["error"]["code"] == "enrollment_required"
    assert _counts(flask_app) == before


def test_unenrolled_assigned_assessment_start_creates_nothing(flask_app):
    browser = flask_app.test_client()
    before = _counts(flask_app)
    refused = _post(browser, "/prototype/api/session/assessment/start",
                    {"assessment_id": "as-unenrolled-check"})
    assert refused.status_code == 409
    assert refused.get_json()["error"]["code"] == "enrollment_required"
    assert _counts(flask_app) == before


@pytest.mark.parametrize("mode", ["practice", "simulation"])
def test_reset_refuses_active_ordinary_work_without_changes(flask_app, mode):
    import app as app_module
    with flask_app.app_context():
        manager = app_module.management_service()
        student = manager.create_student("Mukund V")
        used = manager.create_enrollment_code(student.student_id)
        unused = manager.create_enrollment_code(student.student_id)

    browser = flask_app.test_client()
    assert _post(browser, "/prototype/api/enroll",
                 {"code": used.code}).status_code == 201
    started = _post(browser, "/prototype/api/session/start",
                    {"focus": "mixed", "mode": mode})
    assert started.status_code == 201
    with flask_app.app_context():
        manager = app_module.management_service()
        owner = manager.repository.list_session_ownership(
            student_id=student.student_id)[0]
        session_id = owner.session_id
        before = app_module.workstation_service().require_owned(
            session_id, owner.learner_ref).capture_state()

    from tests.conftest import login_instructor
    trainer = login_instructor(flask_app.test_client())
    refused = _post(
        trainer,
        "/prototype/api/trainer/students/%s/enrollment/reset"
        % student.student_id, {"confirm": True})

    assert refused.status_code == 400
    assert refused.get_json()["error"]["code"] \
        == "enrollment_reset_active_work"
    with flask_app.app_context():
        manager = app_module.management_service()
        assert manager.get_student(student.student_id).learner_ref \
            == owner.learner_ref
        assert manager.repository.get_enrollment_code(unused.code).status == "open"
        current = app_module.workstation_service().require_owned(
            session_id, owner.learner_ref)
        assert current.is_active
        assert current.capture_state() == before
    assert browser.get("/prototype/api/session").status_code == 200
    assert _post(browser, "/prototype/api/session/tick", {}).status_code == 200


@pytest.mark.parametrize("assigned", [False, True], ids=["self-directed", "assigned"])
def test_reset_refuses_active_assessment_without_changes(flask_app, assigned):
    import app as app_module
    with flask_app.app_context():
        manager = app_module.management_service()
        student = manager.create_student("Assessment Learner")
        code = manager.create_enrollment_code(student.student_id)
        if assigned:
            assessment = manager.create_assessment(
                "Assigned audit", "mixed", 1, max_attempts=2)
            manager.assign(assessment.assessment_id, "student",
                           student.student_id)

    browser = flask_app.test_client()
    assert _post(browser, "/prototype/api/enroll",
                 {"code": code.code}).status_code == 201
    path = ("/prototype/api/session/assessment/start" if assigned
            else "/prototype/api/session/start")
    payload = ({"assessment_id": assessment.assessment_id} if assigned
               else {"focus": "mixed", "mode": "assessment"})
    assert _post(browser, path, payload).status_code == 201

    from tests.conftest import login_instructor
    trainer = login_instructor(flask_app.test_client())
    refused = _post(
        trainer,
        "/prototype/api/trainer/students/%s/enrollment/reset"
        % student.student_id, {"confirm": True})
    assert refused.status_code == 400
    assert refused.get_json()["error"]["code"] \
        == "enrollment_reset_active_work"
    with flask_app.app_context():
        manager = app_module.management_service()
        attempt = manager.list_attempts(student_id=student.student_id)[0]
        assert attempt.is_active
        assert manager.get_student(student.student_id).learner_ref is not None
        assert app_module.workstation_service().require_owned(
            attempt.session_id, manager.get_student(
                student.student_id).learner_ref).is_active


def test_reset_refuses_active_attempt_when_session_is_unreadable(
        tmp_path, monkeypatch):
    manager, _workstation, _sessions = build(sqlite_uri(tmp_path))
    student = manager.create_student("Unreadable Attempt Learner")
    used = manager.create_enrollment_code(student.student_id)
    unused = manager.create_enrollment_code(student.student_id)
    manager.claim_enrollment(LEARNER, used.code)
    attempt, created = manager.start_self_directed_attempt(LEARNER, "mixed")
    assert created and attempt.is_active
    monkeypatch.setattr(manager, "load_session", lambda _session_id: None)

    with pytest.raises(ManagementRefused) as excinfo:
        manager.reset_enrollment(student.student_id)

    assert excinfo.value.code == "enrollment_reset_active_work"
    assert manager.get_student(student.student_id).learner_ref == LEARNER
    assert manager.repository.get_enrollment_code(unused.code).status == "open"
    assert manager.get_attempt(attempt.attempt_id).is_active


def test_enrolled_identity_is_exact_and_never_exposes_learner_ref(tmp_path):
    manager, workstation, _sessions = build(sqlite_uri(tmp_path))
    student = manager.create_student("Mukund V", reference="hon1", cohort="g1")
    code = manager.create_enrollment_code(student.student_id)
    bound, newly = manager.claim_enrollment(LEARNER, code.code)
    assert newly is True and bound.student_id == student.student_id
    assert manager.require_enrolled_student(LEARNER).student_id == student.student_id

    for mode in ("practice", "simulation"):
        session_id = workstation.start_session(LEARNER, "mixed", mode)
        owner = manager.register_session(session_id, LEARNER)
        assert owner.student_id == student.student_id
    assert len(manager.list_students()) == 1


def test_reset_enrollment_preserves_history_and_allows_a_new_device(tmp_path):
    manager, workstation, _sessions = build(sqlite_uri(tmp_path))
    student = manager.create_student("Mukund V")
    used = manager.create_enrollment_code(student.student_id)
    stale = manager.create_enrollment_code(student.student_id)
    manager.claim_enrollment(LEARNER, used.code)
    session_id = workstation.start_session(LEARNER, "mixed", "simulation")
    manager.register_session(session_id, LEARNER)
    workstation.end_session(session_id, LEARNER)

    reset, changed = manager.reset_enrollment(student.student_id)
    assert changed is True and reset.learner_ref is None
    assert manager.get_session_ownership(session_id).student_id == student.student_id
    assert manager.get_session_ownership(session_id).learner_ref == LEARNER
    assert manager.repository.get_enrollment_code(stale.code).status == "revoked"
    assert manager.student_for_learner_ref(LEARNER) is None

    replacement = manager.create_enrollment_code(student.student_id)
    rebound, newly = manager.claim_enrollment(OTHER_LEARNER, replacement.code)
    assert newly is True and rebound.student_id == student.student_id
    assert manager.get_session_ownership(session_id).learner_ref == LEARNER


def test_completed_assessment_reset_preserves_attempt_and_reenrolls(flask_app):
    import app as app_module
    with flask_app.app_context():
        manager = app_module.management_service()
        student = manager.create_student("Completed Learner")
        used = manager.create_enrollment_code(student.student_id)
        unused = manager.create_enrollment_code(student.student_id)
    browser = flask_app.test_client()
    assert _post(browser, "/prototype/api/enroll",
                 {"code": used.code}).status_code == 201
    assert _post(browser, "/prototype/api/session/start",
                 {"focus": "mixed", "mode": "assessment"}).status_code == 201
    assert _post(browser, "/prototype/api/session/end", {}).status_code == 200

    from tests.conftest import login_instructor
    trainer = login_instructor(flask_app.test_client())
    reset = _post(
        trainer,
        "/prototype/api/trainer/students/%s/enrollment/reset"
        % student.student_id, {"confirm": True})
    assert reset.status_code == 200
    with flask_app.app_context():
        manager = app_module.management_service()
        attempt = manager.list_attempts(student_id=student.student_id)[0]
        owner = manager.get_session_ownership(attempt.session_id)
        assert not attempt.is_active and attempt.result_state is not None
        assert owner.student_id == student.student_id
        assert manager.get_student(student.student_id).learner_ref is None
        assert manager.repository.get_enrollment_code(unused.code).status == "revoked"
        replacement = manager.create_enrollment_code(student.student_id)
    refused = _post(browser, "/prototype/api/session/start",
                    {"focus": "mixed", "mode": "practice"})
    assert refused.status_code == 409
    replacement_browser = flask_app.test_client()
    assert _post(replacement_browser, "/prototype/api/enroll",
                 {"code": replacement.code}).status_code == 201


def test_ordinary_start_reset_race_abandons_created_session(
        flask_app, monkeypatch):
    import app as app_module
    with flask_app.app_context():
        manager = app_module.management_service()
        workstation = app_module.workstation_service()
        student = manager.create_student("Raced Learner")
        code = manager.create_enrollment_code(student.student_id)
        original = workstation.start_session
    browser = flask_app.test_client()
    assert _post(browser, "/prototype/api/enroll",
                 {"code": code.code}).status_code == 201

    def reset_then_create(*args, **kwargs):
        with flask_app.app_context():
            reset, changed = app_module.management_service().reset_enrollment(
                student.student_id)
            assert changed and reset.learner_ref is None
        return original(*args, **kwargs)

    monkeypatch.setattr(workstation, "start_session", reset_then_create)
    raced = _post(browser, "/prototype/api/session/start",
                  {"focus": "mixed", "mode": "practice"})
    assert raced.status_code == 409
    assert raced.get_json()["error"]["code"] == "enrollment_required"
    with flask_app.app_context():
        manager = app_module.management_service()
        summaries = manager.session_summaries()
        raced_session = next(row for row in summaries
                             if row.learner_ref not in {
                                 owner.learner_ref for owner in
                                 manager.repository.list_session_ownership()})
        assert raced_session.status == "abandoned"
        assert manager.get_student(student.student_id).learner_ref is None
    with browser.session_transaction() as flask_session:
        assert "rewindsec2_session" not in flask_session


def test_reset_transaction_rolls_back_when_ownership_appears_after_check(
        tmp_path, monkeypatch):
    manager, workstation, _sessions = build(sqlite_uri(tmp_path))
    student = manager.create_student("Concurrent Ownership Learner")
    used = manager.create_enrollment_code(student.student_id)
    unused = manager.create_enrollment_code(student.student_id)
    manager.claim_enrollment(LEARNER, used.code)
    original = manager.repository.reset_student_enrollment
    raced_session = []

    def register_then_reset(*args, **kwargs):
        session_id = workstation.start_session(LEARNER, "mixed", "simulation")
        manager.register_session(session_id, LEARNER)
        raced_session.append(session_id)
        return original(*args, **kwargs)

    monkeypatch.setattr(manager.repository, "reset_student_enrollment",
                        register_then_reset)
    with pytest.raises(ManagementRefused) as excinfo:
        manager.reset_enrollment(student.student_id)

    assert excinfo.value.code == "enrollment_changed"
    assert manager.get_student(student.student_id).learner_ref == LEARNER
    assert manager.repository.get_enrollment_code(unused.code).status == "open"
    assert workstation.require_owned(raced_session[0], LEARNER).is_active


def test_assessment_start_reset_race_abandons_attempt_and_session(
        flask_app, monkeypatch):
    import app as app_module
    with flask_app.app_context():
        manager = app_module.management_service()
        student = manager.create_student("Raced Assessment Learner")
        code = manager.create_enrollment_code(student.student_id)
        original = manager.ensure_self_directed_assessment
    browser = flask_app.test_client()
    assert _post(browser, "/prototype/api/enroll",
                 {"code": code.code}).status_code == 201

    def create_policy_then_reset(focus):
        assessment = original(focus)
        reset, changed = app_module.management_service().reset_enrollment(
            student.student_id)
        assert changed and reset.learner_ref is None
        return assessment

    monkeypatch.setattr(manager, "ensure_self_directed_assessment",
                        create_policy_then_reset)
    raced = _post(browser, "/prototype/api/session/start",
                  {"focus": "mixed", "mode": "assessment"})
    assert raced.status_code == 409
    assert raced.get_json()["error"]["code"] == "enrollment_required"
    with flask_app.app_context():
        manager = app_module.management_service()
        attempt = manager.list_attempts(student_id=student.student_id)[0]
        assert attempt.status == "abandoned"
        assert app_module.workstation_repository().load(
            attempt.session_id).status.value == "abandoned"
        assert manager.get_student(student.student_id).learner_ref is None
    with browser.session_transaction() as flask_session:
        assert "rewindsec2_session" not in flask_session


def test_normal_roster_excludes_legacy_self_provisioned_rows(tmp_path):
    manager, _workstation, _sessions = build(sqlite_uri(tmp_path))
    legacy = manager.ensure_student_for_learner_ref(LEARNER)
    roster = manager.create_student("Awaiting Learner")

    assert manager.get_student(legacy.student_id) == legacy
    assert [row.student_id for row in manager.list_students()] == [roster.student_id]
    overview = projection.students_overview(manager)
    assert overview["student_total"] == 1
    assert overview["rows"][0]["student"].learner_ref is None


def test_legacy_student_ids_are_rejected_by_normal_trainer_surfaces(flask_app):
    import app as app_module
    with flask_app.app_context():
        manager = app_module.management_service()
        legacy = manager.ensure_student_for_learner_ref("learner-legacy-audit")
        roster = manager.create_student("Awaiting Learner")
        group = manager.create_group("Roster Group")
        assessment = manager.create_assessment("Roster assessment", "mixed", 1)
        roster_total = len(manager.list_students())

    from tests.conftest import login_instructor
    trainer = login_instructor(flask_app.test_client())
    cards = trainer.get(
        "/prototype/api/trainer/dashboard").get_json()["cards"]
    assert next(card for card in cards if card["id"] == "students")["value"] \
        == str(roster_total)
    assert legacy.display_name.encode() not in trainer.get(
        "/prototype/trainer/students").data
    students = trainer.get("/prototype/api/trainer/students").get_json()["students"]
    student_ids = {row["id"] for row in students}
    assert roster.student_id in student_ids
    assert legacy.student_id not in student_ids
    assert trainer.get("/prototype/trainer/students/%s" % legacy.student_id).status_code == 404
    assert trainer.get("/prototype/api/trainer/students/%s" % legacy.student_id).status_code == 404

    legacy_ops = [
        _post(trainer, "/prototype/api/trainer/groups/%s/members" % group.group_id,
              {"student_id": legacy.student_id}),
        _post(trainer, "/prototype/api/trainer/assignments", {
            "assessment_id": assessment.assessment_id, "target_type": "student",
            "target_id": legacy.student_id}),
        trainer.get("/prototype/api/trainer/assignment-duplicates", query_string={
            "assessment_id": assessment.assessment_id, "target_type": "student",
            "target_id": legacy.student_id}),
        trainer.get("/prototype/api/trainer/assignment-sources", query_string={
            "assessment_id": assessment.assessment_id,
            "student_id": legacy.student_id}),
        _post(trainer, "/prototype/api/trainer/students/%s/enrollment-code"
              % legacy.student_id, {}),
        _post(trainer, "/prototype/api/trainer/students/%s/enrollment/reset"
              % legacy.student_id, {"confirm": True}),
    ]
    assert all(response.status_code == 404 for response in legacy_ops)
    with flask_app.app_context():
        manager = app_module.management_service()
        assert not manager.list_memberships(student_id=legacy.student_id)
        assert not [row for row in manager.repository.list_assignments()
                    if row.student_id == legacy.student_id]
        assert manager.create_enrollment_code(roster.student_id).status == "open"


def test_activity_projection_uses_persisted_actions_and_stored_score(tmp_path):
    manager, workstation, _sessions = build(sqlite_uri(tmp_path))
    student = enrolled_student(manager, name="Mukund V")
    session_id = workstation.start_session(LEARNER, "mixed", "simulation")
    manager.register_session(session_id, LEARNER)
    driver = Driver(workstation, session_id, LEARNER)
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.open", target="m-payroll-restructure")
    workstation.end_session(session_id, LEARNER)

    detail = projection.session_activity(manager, session_id)
    assert detail["student"]["id"] == student.student_id
    assert detail["session"]["action_count"] == 1
    assert detail["actions"][0]["label"] == "Opened mail"
    assert detail["actions"][0]["target"]
    assert detail["session"]["score"] == detail["result"]["overall"]


def test_trainer_activity_html_excludes_private_learner_content(flask_app):
    import app as app_module
    from rewindsec.workstation.content import index as content_index
    with flask_app.app_context():
        manager = app_module.management_service()
        student = enrolled_student(manager, learner_ref=LEARNER,
                                   name="Private Activity Learner")
        workstation = app_module.workstation_service()
        session_id = workstation.start_session(LEARNER, "mixed", "simulation")
        manager.register_session(session_id, LEARNER)
        driver = Driver(workstation, session_id, LEARNER)
        created = driver.act("notes.create")
        driver.act("notes.save", created.notice["note"], {
            "title": "PRIVATE_NOTE_TITLE_91AA",
            "body": "PRIVATE_NOTE_BODY_7F3C"})
        conversation_id = next(iter(content_index.CONVERSATION_BY_ID))
        driver.act("messages.send", conversation_id,
                   {"text": "PRIVATE_MESSAGE_TEXT_22DE"})
        mail_id = driver.snapshot()["mail"]["messages"][0]["id"]
        driver.act("mail.reply", mail_id,
                   {"text": "PRIVATE_MAIL_REPLY_884B"})
        payment_url = "intranet.northbridge.example/finance/payments"
        driver.act("browser.navigate", params={"url": payment_url})
        driver.act("browser.release_payment", params={
            "url": payment_url, "account": "PRIVATE_PAYMENT_ACCOUNT_A1B2"})

    from tests.conftest import login_instructor
    trainer = login_instructor(flask_app.test_client())
    html = trainer.get(
        "/prototype/trainer/sessions/%s" % session_id).data.decode()
    for secret in (
            "PRIVATE_NOTE_TITLE_91AA", "PRIVATE_NOTE_BODY_7F3C",
            "PRIVATE_MESSAGE_TEXT_22DE", "PRIVATE_MAIL_REPLY_884B",
            "PRIVATE_PAYMENT_ACCOUNT_A1B2", LEARNER):
        assert secret not in html
    for safe_label in ("Saved note", "Sent message", "Replied to mail",
                       "Released payment"):
        assert safe_label in html


def test_trainer_activity_route_is_gated_and_unknown_ownership_is_404(
        flask_app):
    anonymous = flask_app.test_client()
    assert anonymous.get(
        "/prototype/trainer/sessions/not-a-session").status_code in (302, 401, 403)

    from tests.conftest import login_instructor
    trainer = login_instructor(flask_app.test_client())
    assert trainer.get(
        "/prototype/trainer/sessions/not-a-session").status_code == 404


def test_learner_templates_have_dynamic_identity_and_structural_result_note(
        flask_app):
    browser = flask_app.test_client()
    start = browser.get("/prototype/start").data.decode()
    assert ">Trainer<" not in start
    assert "Aarti Venkatesh" not in start
    assert "Unenrolled device" in start
    assert "pw-entry-name" in start

    results = browser.get("/prototype/results").data.decode()
    number_end = results.index("</div>", results.index('class="pw-overall-num"'))
    note_at = results.index('id="pw-res-scoring-note"')
    assert note_at > number_end

    with open("static/prototype/workstation.js", encoding="utf-8") as source:
        script = source.read()
    assert "var scrollPositions = {};" in script
    assert 'data-scroll-key="mail-list:' in script

    with open("static/prototype/workstation.css", encoding="utf-8") as source:
        styles = source.read()
    assert ".pw-ws.is-bannerless .pw-top" in styles
    assert "grid-row: 1" in styles


def test_enrolled_workstation_identity_comes_from_roster(flask_app):
    import app as app_module
    with flask_app.app_context():
        manager = app_module.management_service()
        student = manager.create_student("Mukund V", reference="hon1", cohort="g1")
        code = manager.create_enrollment_code(student.student_id).code

    browser = flask_app.test_client()
    assert _post(browser, "/prototype/api/enroll", {"code": code}).status_code == 201
    me = browser.get("/prototype/api/me").get_json()
    assert me == {"enrolled": True, "student": {
        "id": student.student_id, "name": "Mukund V",
        "reference": "hon1", "cohort": "g1"}}
    workstation = browser.get("/prototype/workstation").data.decode()
    assert "Mukund V" in workstation
    assert "Aarti Venkatesh" not in workstation


def test_desk_greeting_addresses_the_persona_not_the_roster_student(flask_app):
    """The simulated desk greets the persona; the rail names the real learner.

    Two identities sit on the workstation and they are not interchangeable.
    ``learner_identity`` is the enrolled roster student, and it belongs to the
    chrome -- the rail footer, which answers "whose device is this?".
    ``persona`` is the Northbridge employee the learner occupies, and every
    in-fiction surface belongs to it: the mailbox, the authored mail, the
    outstanding tasks. Greeting the roster student on the desk put the two on
    one screen -- "Good morning, Mukund" directly above a mailbox addressed to
    Aarti, whose messages all open by her name -- so the greeting is the
    persona's and the rail footer keeps the roster student.
    """
    import app as app_module
    with flask_app.app_context():
        manager = app_module.management_service()
        student = manager.create_student("Mukund V", reference="hon2")
        code = manager.create_enrollment_code(student.student_id).code

    browser = flask_app.test_client()
    assert _post(browser, "/prototype/api/enroll", {"code": code}).status_code == 201
    page = browser.get("/prototype/workstation").data.decode()

    from rewindsec.workstation.content import world as content_world
    given = content_world.LEARNER["given_name"]

    # The desk greets the persona, and does not greet the roster student.
    assert "Good morning, %s<" % given in page
    assert "Good morning, Mukund" not in page

    # The rail footer still identifies the real enrolled learner, and the
    # persona's full name is still never offered as the learner's own.
    assert "Mukund V" in page
    assert content_world.LEARNER["name"] not in page
