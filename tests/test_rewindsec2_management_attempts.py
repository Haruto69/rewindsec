"""Batch 5 attempt lifecycle, scored-interaction progress, and retry policy.

The two properties that matter most here, and that would be expensive to
discover late:

* **Progress is scored interactions.** Not events, not messages, not elapsed
  time, not scheduler ticks -- and not investigation. A learner who opens
  every message and inspects every header has completed nothing.
* **Provenance is copied at creation, not re-derived at read time.** A group
  membership removed after the fact cannot rewrite what a historical attempt
  says about how it was assigned.
"""

import json

import sqlalchemy as sa

import pytest

from rewindsec.management import progress as progress_rules
from rewindsec.management import session_link
from rewindsec.management.ids import SequenceIdSource
from rewindsec.management.service import ManagementRefused
from rewindsec.persistence.sqlalchemy_adapter import SqlAlchemySessionRepository
from rewindsec.scoring import state as scoring_state
from rewindsec.workstation.seeds import FixedSeedSource
from rewindsec.workstation.service import WorkstationService

from tests.management_helpers import (LEARNER, OTHER_LEARNER, build,
                                      enrolled_student, sqlite_uri)
from tests.workstation_helpers import Driver

#: Three authored mails that each present exactly one scoring opportunity and
#: that the engine can be asked for by name. Reporting one resolves it.
SCORED_MAILS = ("m-payroll-restructure", "m-rate-card", "m-invoice-amend")


def assigned(tmp_path, required=3, max_attempts=1, focus="mixed",
             status="open", ids=None, uri=None):
    """One student, in one group, holding one assessment through that group."""
    management, workstation, sessions = build(uri or sqlite_uri(tmp_path),
                                              ids=ids)
    student = enrolled_student(management)
    group = management.create_group("Operations A")
    management.add_member(group.group_id, student.student_id)
    assessment = management.create_assessment(
        "Q3 judgement", focus, required, status=status,
        max_attempts=max_attempts)
    management.assign(assessment.assessment_id, "group", group.group_id)
    return management, workstation, sessions, student, group, assessment


# ===========================================================================
# Starting an attempt
# ===========================================================================

def test_an_attempt_starts_in_assessment_mode_with_the_assessment_focus(tmp_path):
    management, _ws, sessions, student, _group, assessment = assigned(
        tmp_path, focus="bec")
    attempt, created = management.start_attempt(LEARNER, assessment.assessment_id)

    assert created is True
    assert attempt.attempt_number == 1 and attempt.is_active
    session = sessions.load(attempt.session_id)
    assert session.mode.value == "assessment", "the client does not choose this"
    assert session.focus.value == "bec", "focus comes from the assessment"
    assert session.learner_ref == LEARNER


def test_self_directed_attempt_has_system_policy_not_assignment_provenance(
        tmp_path):
    management, _workstation, sessions = build(sqlite_uri(tmp_path))
    enrolled_student(management)
    attempt, created = management.start_self_directed_attempt(LEARNER, "bec")

    assert created is True
    assert attempt.assignment_source == "self_directed"
    assert attempt.assignment_id is None
    assert attempt.assignment_group_id is None
    definition = management.get_assessment(attempt.assessment_id)
    assert definition.is_self_directed_policy
    assert definition.created_by == "RewindSec system policy"
    assert management.repository.list_assignments(
        assessment_id=definition.assessment_id) == ()
    assert sessions.load(attempt.session_id).mode.value == "assessment"
    from rewindsec.management.projection import assessments_overview
    trainer_ids = {row["assessment"].assessment_id
                   for row in assessments_overview(management)["rows"]}
    assert definition.assessment_id not in trainer_ids


def test_trainer_attempt_keeps_real_assignment_provenance(tmp_path):
    management, _ws, _sessions, _student, group, assessment = assigned(tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    assert attempt.assignment_source == "group"
    assert attempt.assignment_id is not None
    assert attempt.assignment_group_id == group.group_id


def test_the_session_carries_the_attempt_stamp(tmp_path):
    management, _ws, sessions, student, group, assessment = assigned(tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)

    stamp = session_link.attempt_stamp(sessions.load(attempt.session_id))
    assert stamp["attempt_id"] == attempt.attempt_id
    assert stamp["assessment_id"] == assessment.assessment_id
    assert stamp["student_id"] == student.student_id
    assert stamp["assignment_source"] == "group"
    assert stamp["assignment_group_id"] == group.group_id


def test_attempt_and_session_ownership_cannot_diverge(tmp_path):
    management, _ws, sessions, student, _group, assessment = assigned(tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)

    session = sessions.load(attempt.session_id)
    assert session.learner_ref == student.learner_ref
    ownership = management.get_session_ownership(attempt.session_id)
    assert ownership.student_id == attempt.student_id

    # And a caller cannot re-point the session at somebody else.
    with pytest.raises(ManagementRefused) as excinfo:
        management.register_session(attempt.session_id, OTHER_LEARNER)
    assert excinfo.value.code == "not_owner"


def test_an_unassigned_learner_cannot_start_an_attempt(tmp_path):
    management, _ws, _sessions, _student, _group, assessment = assigned(tmp_path)
    enrolled_student(management, learner_ref=OTHER_LEARNER,
                     name="Unassigned Learner")
    with pytest.raises(ManagementRefused) as excinfo:
        management.start_attempt(OTHER_LEARNER, assessment.assessment_id)
    assert excinfo.value.code == "not_assigned"
    assert management.list_attempts() == ()


@pytest.mark.parametrize("status", ["draft", "scheduled", "closed"])
def test_only_an_open_assessment_accepts_an_attempt(tmp_path, status):
    """Batch 5 correction: ``scheduled`` is not ``open``.

    The trainer UI shows the two as different states, so they have to behave
    as different states. ``scheduled`` means written and not yet released;
    accepting an attempt from it -- on the grounds that this batch implements
    no scheduling automation -- would make the trainer's choice meaningless
    and would use "the server does not do X" as an argument for letting a
    learner do X. Releasing an assessment is the explicit act of setting it
    ``open``.
    """
    management, _ws, _sessions, _student, _group, assessment = assigned(
        tmp_path, status=status)
    with pytest.raises(ManagementRefused) as excinfo:
        management.start_attempt(LEARNER, assessment.assessment_id)
    assert excinfo.value.code == "assessment_closed"
    assert excinfo.value.detail["status"] == status
    assert management.list_attempts() == (), "and nothing was written"


def test_an_open_assessment_accepts_an_attempt(tmp_path):
    management, _ws, _sessions, _student, _group, assessment = assigned(
        tmp_path, status="open")
    attempt, created = management.start_attempt(LEARNER,
                                                assessment.assessment_id)
    assert created is True and attempt.is_active


def test_releasing_a_scheduled_assessment_is_what_opens_it(tmp_path):
    """The remedy is a status change, not a wider start rule."""
    management, _ws, _sessions, _student, _group, assessment = assigned(
        tmp_path, status="scheduled")
    with pytest.raises(ManagementRefused):
        management.start_attempt(LEARNER, assessment.assessment_id)

    management.set_assessment_status(assessment.assessment_id, "open")
    attempt, created = management.start_attempt(LEARNER,
                                                assessment.assessment_id)
    assert created is True and attempt.is_active


# ===========================================================================
# Progress is counted in scored interactions
# ===========================================================================

def _drive(workstation, attempt):
    return Driver(workstation, attempt.session_id, LEARNER)


def test_delivery_alone_is_not_progress(tmp_path):
    management, workstation, _sessions, _s, _g, assessment = assigned(tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = _drive(workstation, attempt)

    for mail_id in SCORED_MAILS:
        driver.deliver_until(mail_id)

    progress = management.attempt_progress(attempt)
    assert progress["presented"] == 3, "three opportunities were presented"
    assert progress["completed"] == 0, "none of them has been resolved"
    assert progress["required"] == 3 and progress["met"] is False


def test_investigation_is_not_a_scored_interaction(tmp_path):
    """Clicking every investigation control moves progress by zero."""
    management, workstation, _sessions, _s, _g, assessment = assigned(tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = _drive(workstation, attempt)
    driver.deliver_until("m-payroll-restructure")

    before = management.attempt_progress(attempt)
    driver.act("mail.open", target="m-payroll-restructure")
    driver.act("mail.inspect_headers", target="m-payroll-restructure")
    driver.act("mail.inspect_link", target="m-payroll-restructure",
               params={"index": 0})
    after = management.attempt_progress(attempt)

    assert after["completed"] == before["completed"] == 0


def test_a_recorded_decision_completes_exactly_one_interaction(tmp_path):
    management, workstation, _sessions, _s, _g, assessment = assigned(tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = _drive(workstation, attempt)

    completed = []
    for mail_id in SCORED_MAILS:
        driver.deliver_until(mail_id)
    for mail_id in SCORED_MAILS:
        driver.act("mail.report", target=mail_id)
        completed.append(management.attempt_progress(attempt)["completed"])

    assert completed == [1, 2, 3]
    assert management.attempt_progress(attempt)["met"] is True


def test_the_same_occurrence_does_not_double_count_on_a_retry(tmp_path):
    """An idempotent repeat of a decision cannot inflate progress."""
    management, workstation, _sessions, _s, _g, assessment = assigned(tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = _drive(workstation, attempt)
    driver.deliver_until("m-payroll-restructure")

    driver.act("mail.report", target="m-payroll-restructure")
    once = management.attempt_progress(attempt)
    driver.act("mail.report", target="m-payroll-restructure")
    twice = management.attempt_progress(attempt)

    assert once["completed"] == 1
    assert twice["completed"] == 1, "the same occurrence resolves once"


def test_an_ignored_opportunity_stays_presented_and_unresolved(tmp_path):
    """Batch 4's ignored-opportunity semantics are consumed, not erased.

    An opportunity nobody touched is still counted as presented and still
    produces negative evidence at finalization. It simply does not count as
    completed -- progress is not bought by ignoring things.
    """
    management, workstation, sessions, _s, _g, assessment = assigned(tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = _drive(workstation, attempt)
    for mail_id in SCORED_MAILS:
        driver.deliver_until(mail_id)
    driver.act("mail.report", target=SCORED_MAILS[0])

    completed, presented, detail = progress_rules.scored_interactions(
        sessions.load(attempt.session_id))
    assert (completed, presented) == (1, 3)
    assert sum(1 for row in detail if not row["resolved"]) == 2


def test_progress_detail_carries_no_answer_key(tmp_path):
    """It is returned to a learner mid-attempt, so it must say nothing."""
    management, workstation, sessions, _s, _g, assessment = assigned(tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = _drive(workstation, attempt)
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", target="m-payroll-restructure")

    _c, _p, detail = progress_rules.scored_interactions(
        sessions.load(attempt.session_id))
    for row in detail:
        assert set(row) == {"opportunity_id", "opportunity_type",
                            "sim_time_ms", "resolved"}
    text = json.dumps(management.attempt_state(attempt)).lower()
    for banned in ("rubric", "dimension", "valence", "disposition",
                   "resolving", "decision_class", "overall"):
        assert banned not in text, banned


def test_progress_reads_opportunities_not_events(tmp_path):
    """Ticking the clock produces events and no progress whatsoever."""
    management, workstation, sessions, _s, _g, assessment = assigned(tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = _drive(workstation, attempt)

    driver.tick(times=30)
    session = sessions.load(attempt.session_id)
    assert len(list(session.event_log.events())) > 5, "events did happen"
    assert management.attempt_progress(attempt)["completed"] == 0


# ===========================================================================
# Resume, completion and retry
# ===========================================================================

def test_resume_returns_the_same_attempt_and_never_mints_a_second(tmp_path):
    management, _ws, _sessions, student, _g, assessment = assigned(tmp_path)
    first, created = management.start_attempt(LEARNER, assessment.assessment_id)
    second, created_again = management.start_attempt(LEARNER,
                                                     assessment.assessment_id)

    assert created is True and created_again is False
    assert second.attempt_id == first.attempt_id
    assert second.session_id == first.session_id
    assert second.attempt_number == 1
    assert len(management.list_attempts(student_id=student.student_id)) == 1


def test_resume_survives_the_whole_object_graph_being_rebuilt(tmp_path):
    """A restarted process, not merely a refresh."""
    uri = sqlite_uri(tmp_path)
    ids = SequenceIdSource()
    management, _ws, _sessions, _student, _g, assessment = assigned(
        tmp_path, ids=ids, uri=uri)
    first, _ = management.start_attempt(LEARNER, assessment.assessment_id)

    rebuilt, _ws2, _sessions2 = build(uri, ids=ids)
    resumed, created = rebuilt.start_attempt(LEARNER, assessment.assessment_id)
    assert created is False
    assert resumed.attempt_id == first.attempt_id
    assert len(rebuilt.list_attempts()) == 1


def test_completion_stores_the_finalized_batch4_result_verbatim(tmp_path):
    management, workstation, sessions, _s, _g, assessment = assigned(
        tmp_path, required=1)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = _drive(workstation, attempt)
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", target="m-payroll-restructure")

    workstation.end_session(attempt.session_id, LEARNER)
    done = management.sync_attempt(management.get_attempt(attempt.attempt_id))

    stored = scoring_state.get_result(sessions.load(attempt.session_id))
    assert done.status == "completed"
    assert done.result_state == stored.to_state(), \
        "the attempt's result IS the session's finalized result"
    assert done.overall == stored.overall
    assert done.rubric_version == "rewindsec-rubric/v1"
    assert done.scoring_version == "rewindsec-scoring/v1"
    assert done.evidence_model_version == "rewindsec-evidence-model/v1"
    assert done.ended_at


def test_syncing_a_completed_attempt_again_changes_nothing(tmp_path):
    management, workstation, _sessions, _s, _g, assessment = assigned(
        tmp_path, required=1)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = _drive(workstation, attempt)
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", target="m-payroll-restructure")
    workstation.end_session(attempt.session_id, LEARNER)

    once = management.sync_attempt(management.get_attempt(attempt.attempt_id))
    twice = management.sync_attempt(management.get_attempt(attempt.attempt_id))
    assert once == twice
    assert once.status == "completed"


def test_the_retry_limit_is_enforced_after_completion(tmp_path):
    management, workstation, _sessions, _s, _g, assessment = assigned(
        tmp_path, max_attempts=2)
    first, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    workstation.end_session(first.session_id, LEARNER)
    management.sync_attempt(first)

    second, created = management.start_attempt(LEARNER,
                                               assessment.assessment_id)
    assert created is True and second.attempt_number == 2
    workstation.end_session(second.session_id, LEARNER)
    management.sync_attempt(second)

    with pytest.raises(ManagementRefused) as excinfo:
        management.start_attempt(LEARNER, assessment.assessment_id)
    assert excinfo.value.code == "retry_limit_reached"
    assert excinfo.value.detail["max_attempts"] == 2
    assert excinfo.value.detail["retry_policy"] == "bounded-attempts/v1"
    assert len(management.list_attempts()) == 2


def test_no_retry_is_offered_while_an_attempt_is_active(tmp_path):
    """A second attempt is not started merely because one was asked for."""
    management, _ws, _sessions, _s, _g, assessment = assigned(
        tmp_path, max_attempts=3)
    first, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    for _ in range(3):
        again, created = management.start_attempt(LEARNER,
                                                  assessment.assessment_id)
        assert created is False and again.attempt_id == first.attempt_id
    assert len(management.list_attempts()) == 1


def test_an_abandoned_attempt_counts_against_the_limit(tmp_path):
    management, workstation, sessions, _s, _g, assessment = assigned(
        tmp_path, max_attempts=1)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)

    session = sessions.load(attempt.session_id)
    expected = session.revision
    session.abandon()
    sessions.update(session, expected_revision=expected)

    synced = management.sync_attempt(management.get_attempt(attempt.attempt_id))
    assert synced.status == "abandoned"
    assert synced.result_state is None, "an abandoned run has no finalized score"
    with pytest.raises(ManagementRefused):
        management.start_attempt(LEARNER, assessment.assessment_id)


# ===========================================================================
# Provenance survives, determinism is untouched
# ===========================================================================

def test_a_later_membership_change_does_not_rewrite_attempt_provenance(tmp_path):
    management, workstation, _sessions, student, group, assessment = assigned(
        tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    workstation.end_session(attempt.session_id, LEARNER)
    management.sync_attempt(attempt)

    management.remove_member(group.group_id, student.student_id)

    kept = management.get_attempt(attempt.attempt_id)
    assert kept.assignment_source == "group"
    assert kept.assignment_group_id == group.group_id
    assert kept.assignment_id == attempt.assignment_id
    assert kept.required_interactions == assessment.required_interactions
    assert kept.assessment_definition_version \
        == assessment.definition_version
    # The learner no longer *receives* it -- which is a different statement.
    assert management.effective_assignments(student.student_id) == ()


def test_determinism_is_unperturbed_by_management_metadata(tmp_path):
    """Same seed, same inputs -> byte-identical simulation, stamp or no stamp.

    The attempt stamp is a single world value written through ``mutate_world``.
    It draws nothing from any RNG stream, schedules nothing and advances no
    clock, so it cannot move the simulation's future by one millisecond.
    """
    def run(stamped):
        engine = sa.create_engine("sqlite://")
        repository = SqlAlchemySessionRepository(engine)
        repository.create_schema()
        workstation = WorkstationService(repository,
                                         seed_source=FixedSeedSource(4242),
                                         id_source=lambda: "ws-fixed")
        hook = None
        if stamped:
            def hook(session, cause_event_id=None):
                session_link.stamp_attempt(
                    session, attempt_id="att-1", assessment_id="as-1",
                    student_id="stu-1", assignment_id="asg-1",
                    assignment_source="group", required_interactions=3,
                    attempt_number=1, cause_event_id=cause_event_id)
        session_id = workstation.start_session(
            "learner-x", "mixed", "assessment", on_created=hook,
            attempt_bound=True)
        Driver(workstation, session_id, "learner-x").tick(times=40)
        session = repository.load(session_id)
        return {
            "rng": session.rng.capture_state(),
            "clock": session.clock.capture_state(),
            "scheduler": session.scheduler.capture_state(),
            "events": [(e.event_id, e.type, e.sim_time_ms)
                       for e in session.event_log.events()],
        }

    plain, stamped = run(False), run(True)
    assert plain["rng"] == stamped["rng"]
    assert plain["clock"] == stamped["clock"]
    assert plain["scheduler"] == stamped["scheduler"]
    assert plain["events"] == stamped["events"]
    assert plain["events"], "the run actually did something"


def test_the_attempt_stamp_is_not_in_the_learner_projection(tmp_path):
    management, workstation, _sessions, _s, _g, assessment = assigned(tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)

    snapshot = json.dumps(workstation.snapshot(attempt.session_id, LEARNER))
    assert session_link.NS_ASSESSMENT not in snapshot
    assert attempt.attempt_id not in snapshot
    assert assessment.assessment_id not in snapshot


def test_stamping_twice_does_not_mint_a_second_identity(tmp_path):
    management, _ws, sessions, _s, _g, assessment = assigned(tmp_path)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)

    session = sessions.load(attempt.session_id)
    before = session.revision
    session_link.stamp_attempt(session, "att-other", "as-other", "stu-other")
    assert session.revision == before, "a second stamp writes nothing"
    assert session_link.attempt_stamp(session)["attempt_id"] \
        == attempt.attempt_id
