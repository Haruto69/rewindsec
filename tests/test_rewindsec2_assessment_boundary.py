"""Batch 5 correction: what makes an Assessment Attempt valid, and where it ends.

Two invariants, and neither of them was actually held by the first cut of
Batch 5.

**Assessment mode implies an Attempt.** ``mode: "assessment"`` used to be
accepted by the generic self-directed start endpoint, which produced an
Assessment-mode ``TrainingSession`` with no ``Attempt`` behind it: nothing to
check a required-interaction rule against, no assignment it came from, no
retry it counted against, and nothing for a trainer to read. The chain is now

    Assessment mode => persistent Assessment Attempt => TrainingSession

and it is held at the single place a session is constructed, not only at the
route.

**``required_interactions`` is a completion rule, not a progress bar.** A
learner could previously start an assessment, resolve one interaction, press
End Training and be recorded as having *completed* the assessment. Ending
early is now recorded for what it is -- an attempt that did not satisfy the
definition -- while the session's own Batch 4 result is still stored verbatim,
because the learner's decisions keep their natural consequences either way.

The upper boundary is exact: it persists the first N resolved
opportunity/decision pairs. New primary arrivals stop, later actions remain in
history but cannot add N+1 to scoring, the clock keeps running, and factual
consequences already in flight still land.
"""

import pytest

from rewindsec.domain.errors import InvalidIdentityError
from rewindsec.management import assessment_policy
from rewindsec.management import session_link
from rewindsec.management.progress import scored_interactions
from rewindsec.management.records import ATTEMPT_STARTABLE_STATUSES
from rewindsec.management.service import ManagementRefused
from rewindsec.scoring import state as scoring_state
from rewindsec.workstation.errors import ForbiddenActionError

from tests.management_helpers import LEARNER, build, enrolled_student, sqlite_uri
from tests.workstation_helpers import Driver

#: Authored mails that each present exactly one scoring opportunity and that
#: the engine can be asked for by name. Reporting one resolves it.
SCORED_MAILS = ("m-payroll-restructure", "m-rate-card", "m-invoice-amend")


def assigned(tmp_path, required=3, max_attempts=3, status="open", uri=None,
             ids=None):
    management, workstation, sessions = build(uri or sqlite_uri(tmp_path),
                                              ids=ids)
    student = enrolled_student(management)
    group = management.create_group("Operations A")
    management.add_member(group.group_id, student.student_id)
    assessment = management.create_assessment(
        "Q3 judgement", "mixed", required, status=status,
        max_attempts=max_attempts)
    management.assign(assessment.assessment_id, "group", group.group_id)
    return management, workstation, sessions, student, assessment


def drive(workstation, attempt):
    return Driver(workstation, attempt.session_id, LEARNER)


def resolve(driver, mails):
    for mail_id in mails:
        driver.deliver_until(mail_id)
    for mail_id in mails:
        driver.act("mail.report", target=mail_id)


# ===========================================================================
# Correction 1: no Assessment-mode session without an Attempt
# ===========================================================================

def test_the_session_chokepoint_refuses_assessment_without_an_attempt(tmp_path):
    """The invariant is held where sessions are *made*, not only at the route.

    ``WorkstationService.start_session`` is the only place a
    ``SimulationSession`` is constructed anywhere in the system, which makes
    it the only place this can be enforced for every caller rather than for
    every caller somebody remembered to check.
    """
    _management, workstation, _sessions, _student, _assessment = assigned(
        tmp_path)
    with pytest.raises(ForbiddenActionError):
        workstation.start_session(LEARNER, "mixed", "assessment")


def test_self_directed_modes_are_unaffected(tmp_path):
    _management, workstation, sessions, _student, _assessment = assigned(
        tmp_path)
    for mode in ("practice", "simulation"):
        session_id = workstation.start_session(LEARNER, "mixed", mode)
        assert sessions.load(session_id).mode.value == mode


def test_the_only_caller_that_may_assert_the_binding_writes_the_attempt_first(
        tmp_path):
    """``start_attempt`` is the one caller, and the Attempt row precedes it."""
    management, _ws, sessions, _student, assessment = assigned(tmp_path)
    attempt, created = management.start_attempt(LEARNER,
                                                assessment.assessment_id)
    assert created is True
    session = sessions.load(attempt.session_id)
    assert session.mode.value == "assessment"
    # Both directions of the link exist: the row points at the session, and
    # the session carries its own stamp naming the attempt.
    assert management.attempt_for_session(session.session_id).attempt_id \
        == attempt.attempt_id
    assert session_link.attempt_stamp(session)["attempt_id"] \
        == attempt.attempt_id


def test_there_is_no_assessment_session_without_an_attempt_row(tmp_path):
    """Swept, not asserted about one session: every stored assessment-mode
    session in the database resolves to an attempt."""
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path)
    management.start_attempt(LEARNER, assessment.assessment_id)
    self_directed, _ = management.start_self_directed_attempt(
        LEARNER, "phishing")
    assert self_directed.assignment_source == "self_directed"
    workstation.start_session(LEARNER, "phishing", "practice")
    workstation.start_session(LEARNER, "bec", "simulation")

    orphans = []
    for summary in sessions.list_summaries():
        stored = management.load_session(summary.session_id)
        if stored is None or stored.mode.value != "assessment":
            continue
        if management.attempt_for_session(summary.session_id) is None:
            orphans.append(summary.session_id)
    assert orphans == []


# ===========================================================================
# Correction 4: only an open assessment may start
# ===========================================================================

def test_only_open_is_a_startable_status():
    assert ATTEMPT_STARTABLE_STATUSES == ("open",)


# ===========================================================================
# Correction 2, lower bound: ending early is not completing
# ===========================================================================

def test_ending_before_the_requirement_is_not_a_completed_assessment(tmp_path):
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path, required=3)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = drive(workstation, attempt)
    resolve(driver, SCORED_MAILS[:1])

    workstation.end_session(attempt.session_id, LEARNER)
    done = management.sync_attempt(management.get_attempt(attempt.attempt_id))

    assert done.status == "abandoned", "not a completed assessment"
    assert done.termination_reason == "requirement_unmet"
    assert done.completed_interactions == 1
    assert done.required_interactions == 3
    assert done.requirement_met is False
    assert done.is_valid_assessment is False


def test_early_termination_still_keeps_the_batch4_result(tmp_path):
    """The learner's decisions keep their consequences and their score.

    What ending early costs them is a *valid assessment*, not the factual
    record of what they did. Deleting the result would be rewriting history to
    make a status field tidier.
    """
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path, required=3)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = drive(workstation, attempt)
    resolve(driver, SCORED_MAILS[:1])
    workstation.end_session(attempt.session_id, LEARNER)

    done = management.sync_attempt(management.get_attempt(attempt.attempt_id))
    stored = scoring_state.get_result(sessions.load(attempt.session_id))
    assert stored is not None
    assert done.result_state == stored.to_state()
    assert done.overall == stored.overall


def test_an_early_ending_is_distinguishable_from_an_abandoned_session(tmp_path):
    """Both are ``abandoned``; the reason says which, so a trainer can tell."""
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path, required=3, max_attempts=3)
    early, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    workstation.end_session(early.session_id, LEARNER)
    early = management.sync_attempt(management.get_attempt(early.attempt_id))

    dropped, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    session = sessions.load(dropped.session_id)
    expected = session.revision
    session.abandon()
    sessions.update(session, expected_revision=expected)
    dropped = management.sync_attempt(management.get_attempt(
        dropped.attempt_id))

    assert early.termination_reason == "requirement_unmet"
    assert dropped.termination_reason == "session_abandoned"
    assert early.status == dropped.status == "abandoned"


def test_an_early_ending_still_counts_against_the_retry_limit(tmp_path):
    """Not completing is not a free retry."""
    management, workstation, _sessions, _student, assessment = assigned(
        tmp_path, required=3, max_attempts=1)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    workstation.end_session(attempt.session_id, LEARNER)
    management.sync_attempt(attempt)

    with pytest.raises(ManagementRefused) as excinfo:
        management.start_attempt(LEARNER, assessment.assessment_id)
    assert excinfo.value.code == "retry_limit_reached"


def test_reaching_the_required_count_completes_the_attempt(tmp_path):
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path, required=3)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    resolve(drive(workstation, attempt), SCORED_MAILS)

    workstation.end_session(attempt.session_id, LEARNER)
    done = management.sync_attempt(management.get_attempt(attempt.attempt_id))

    assert done.status == "completed"
    assert done.termination_reason is None
    assert done.completed_interactions == 3
    assert done.requirement_met is True
    assert done.is_valid_assessment is True


def test_the_final_batch4_result_is_the_authoritative_stored_result(tmp_path):
    """No second score is computed anywhere -- the attempt copies, verbatim."""
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path, required=3)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    resolve(drive(workstation, attempt), SCORED_MAILS)
    workstation.end_session(attempt.session_id, LEARNER)

    done = management.sync_attempt(management.get_attempt(attempt.attempt_id))
    stored = scoring_state.get_result(sessions.load(attempt.session_id))
    assert done.result_state == stored.to_state()
    assert done.overall == stored.overall
    assert done.scoring_version == stored.to_state()["scoring_version"]
    assert done.rubric_version == stored.to_state()["rubric_version"]
    assert done.evidence_model_version \
        == stored.to_state()["evidence_model_version"]


# ===========================================================================
# Correction 2, upper bound: the assessment completion boundary
# ===========================================================================

def test_the_boundary_closes_when_the_requirement_is_satisfied(tmp_path):
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path, required=2)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = drive(workstation, attempt)

    resolve(driver, SCORED_MAILS[:1])
    assert session_link.boundary_reached(sessions.load(attempt.session_id)) \
        is False, "one short of the requirement is not the boundary"

    resolve(driver, SCORED_MAILS[1:2])
    session = sessions.load(attempt.session_id)
    assert session_link.boundary_reached(session) is True
    record = session_link.boundary(session)
    assert record["required_interactions"] == 2
    assert record["completed_at_boundary"] == 2
    assert record["at_sim_time_ms"] == session.now_ms
    assert record["boundary_version"] == "rewindsec-assessment-boundary/v2"
    assert len(record["scored_resolutions"]) == 2
    assert record["closed_by_action_id"]
    assert record["cutoff_revision"] < session.revision


def test_no_new_scored_opportunity_arrives_after_the_boundary(tmp_path):
    """The specific failure this prevents: an attempt inflating itself.

    Left open long enough, an attempt would otherwise keep being handed new
    scored opportunities, and two attempts at the same assessment would end
    up having been asked different numbers of questions.
    """
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path, required=1)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = drive(workstation, attempt)
    resolve(driver, SCORED_MAILS[:1])

    at_boundary = management.attempt_progress(attempt)["presented"]
    driver.tick(times=150)
    after = management.attempt_progress(attempt)["presented"]

    assert after == at_boundary, "no new opportunity was introduced"


def test_the_boundary_stops_arrivals_and_not_the_world(tmp_path):
    """Time keeps moving past the boundary; the session is not frozen.

    Terminating exactly at the Nth resolution would cut off consequence
    chains the learner's own earlier decisions had already set in motion, and
    a training system that hides the consequence of a decision because a
    counter reached a threshold has removed the thing it exists to show.
    """
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path, required=1)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = drive(workstation, attempt)
    resolve(driver, SCORED_MAILS[:1])

    before = sessions.load(attempt.session_id)
    driver.tick(times=40)
    after = sessions.load(attempt.session_id)

    assert after.now_ms > before.now_ms, "the clock still runs"
    assert after.is_active, "the session is not ended by the boundary"


def test_actions_after_the_boundary_cannot_add_an_n_plus_one_interaction(
        tmp_path):
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path, required=1)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = drive(workstation, attempt)
    for mail_id in SCORED_MAILS[:2]:
        driver.deliver_until(mail_id)
    driver.act("mail.report", target=SCORED_MAILS[0])
    assert management.attempt_progress(attempt)["completed"] == 1

    # Still visible and still actionable, but outside the persisted cutoff.
    driver.act("mail.report", target=SCORED_MAILS[1])
    session = sessions.load(attempt.session_id)
    completed, presented, _detail = scored_interactions(session)
    assert completed == 1
    assert presented == 2

    workstation.end_session(attempt.session_id, LEARNER)
    session = sessions.load(attempt.session_id)
    result = scoring_state.get_result(session)
    assert result is not None
    done = management.sync_attempt(management.get_attempt(attempt.attempt_id))
    assert done.is_valid_assessment
    assert done.completed_interactions == done.required_interactions == 1
    assert done.result_state == result.to_state()
    explanations = [entry["code"]
                    for dimension in done.result_state["dimensions"].values()
                    for entry in dimension["explanations"]]
    assert "decision:safe:d-ransom-report" not in explanations
    assert not any(code.startswith("opportunity_ignored:mail:")
                   for code in explanations), (
        "the unadmitted visible opportunity must not enter the result as an "
        "ignored-opportunity penalty either")


def test_consequence_scheduled_by_the_nth_decision_still_settles(tmp_path):
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path, required=1)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    driver = drive(workstation, attempt)
    driver.deliver_until(SCORED_MAILS[0])
    before = sessions.load(attempt.session_id).world.get(
        "messages", "conv-lena-fischer")

    driver.act("mail.report", target=SCORED_MAILS[0])
    assert session_link.boundary_reached(sessions.load(attempt.session_id))
    driver.tick(times=3)  # 12 seconds; report consequence is due after 9.

    after = sessions.load(attempt.session_id).world.get(
        "messages", "conv-lena-fischer")
    assert after != before
    assert any("being blocked" in row["text"] for row in after["entries"])


def test_impossible_required_count_is_rejected_from_runtime_capacity(tmp_path):
    management, _workstation, _sessions = build(sqlite_uri(tmp_path))
    capacity = assessment_policy.required_interaction_capacity("phishing")
    with pytest.raises(InvalidIdentityError) as excinfo:
        management.create_assessment(
            "Impossible", "phishing", capacity + 1, status="open")
    assert "bound %d" % capacity in str(excinfo.value)


def test_a_practice_session_never_carries_a_boundary(tmp_path):
    _management, workstation, sessions, _student, _assessment = assigned(
        tmp_path)
    session_id = workstation.start_session(LEARNER, "mixed", "practice")
    driver = Driver(workstation, session_id, LEARNER)
    driver.deliver_until(SCORED_MAILS[0])
    driver.act("mail.report", target=SCORED_MAILS[0])
    driver.tick(times=40)
    assert session_link.boundary_reached(sessions.load(session_id)) is False


# ===========================================================================
# Resume around the boundary
# ===========================================================================

def test_resume_across_the_boundary_returns_the_same_attempt(tmp_path):
    from rewindsec.management.ids import SequenceIdSource

    uri = sqlite_uri(tmp_path)
    ids = SequenceIdSource()
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path, required=1, uri=uri, ids=ids)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    resolve(drive(workstation, attempt), SCORED_MAILS[:1])
    assert session_link.boundary_reached(sessions.load(attempt.session_id))

    rebuilt, rebuilt_ws, rebuilt_sessions = build(uri, ids=ids)
    resumed, created = rebuilt.start_attempt(LEARNER,
                                             assessment.assessment_id)

    assert created is False, "a satisfied requirement does not mint a retry"
    assert resumed.attempt_id == attempt.attempt_id
    assert len(rebuilt.list_attempts()) == 1
    assert session_link.boundary_reached(
        rebuilt_sessions.load(attempt.session_id)), "the boundary persisted"

    rebuilt_ws.end_session(attempt.session_id, LEARNER)
    done = rebuilt.sync_attempt(rebuilt.get_attempt(attempt.attempt_id))
    assert done.is_valid_assessment


def test_resume_before_the_boundary_can_still_reach_it(tmp_path):
    """A learner who closes the browser mid-attempt is not locked out of
    finishing it."""
    from rewindsec.management.ids import SequenceIdSource

    uri = sqlite_uri(tmp_path)
    ids = SequenceIdSource()
    management, workstation, sessions, _student, assessment = assigned(
        tmp_path, required=2, uri=uri, ids=ids)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    resolve(drive(workstation, attempt), SCORED_MAILS[:1])

    rebuilt, rebuilt_ws, rebuilt_sessions = build(uri, ids=ids)
    resumed, created = rebuilt.start_attempt(LEARNER,
                                             assessment.assessment_id)
    assert created is False and resumed.attempt_id == attempt.attempt_id
    assert rebuilt.attempt_progress(resumed)["completed"] == 1

    resolve(Driver(rebuilt_ws, resumed.session_id, LEARNER), SCORED_MAILS[1:2])
    assert session_link.boundary_reached(
        rebuilt_sessions.load(resumed.session_id))

    rebuilt_ws.end_session(resumed.session_id, LEARNER)
    done = rebuilt.sync_attempt(rebuilt.get_attempt(resumed.attempt_id))
    assert done.is_valid_assessment
    assert done.completed_interactions == 2


# ===========================================================================
# The learner-facing document says none of this in an answer-key way
# ===========================================================================

def test_the_attempt_state_reports_the_rule_without_reporting_a_score(tmp_path):
    management, workstation, _sessions, _student, assessment = assigned(
        tmp_path, required=2)
    attempt, _ = management.start_attempt(LEARNER, assessment.assessment_id)
    resolve(drive(workstation, attempt), SCORED_MAILS[:1])

    state = management.attempt_state(management.get_attempt(
        attempt.attempt_id))
    assert state["required_interactions"] == 2
    assert state["progress"]["completed"] == 1
    assert state["progress"]["met"] is False
    assert state["valid_assessment"] is False
    for banned in ("result", "overall", "scoring_version", "rubric_version",
                   "evidence_model_version"):
        assert banned not in state, banned
