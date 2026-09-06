"""Batch 5 assignment semantics: provenance, duplicates, and confirmation.

The property under test throughout is that an assignment is a *route*, and
routes are never merged. A learner who receives the same assessment through
two groups and directly holds three of them, each saying where it came from,
and no operation anywhere collapses that into "assigned: yes".
"""

import pytest

from rewindsec.management.service import DuplicateAssignment, ManagementRefused

from tests.management_helpers import build, sqlite_uri


def fixture(tmp_path):
    """A roster with the overlap every duplicate case needs.

    Alice is in both groups; Bob is only in Operations. One assessment.
    """
    management, workstation, sessions = build(sqlite_uri(tmp_path))
    alice = management.create_student("Alice Doe")
    bob = management.create_student("Bob Roe")
    ops = management.create_group("Operations A")
    finance = management.create_group("Finance payments")
    management.add_member(ops.group_id, alice.student_id)
    management.add_member(ops.group_id, bob.student_id)
    management.add_member(finance.group_id, alice.student_id)
    assessment = management.create_assessment("Q3 judgement", "mixed", 3)
    return management, alice, bob, ops, finance, assessment


# ===========================================================================
# The two kinds of route
# ===========================================================================

def test_a_direct_assignment_is_recorded_as_direct(tmp_path):
    management, alice, _bob, _ops, _fin, assessment = fixture(tmp_path)
    management.assign(assessment.assessment_id, "student", alice.student_id)

    routes = management.effective_assignments(alice.student_id)
    assert [r.source for r in routes] == ["direct"]
    assert routes[0].origin_label == "Assigned directly"


def test_a_group_assignment_reaches_every_current_member(tmp_path):
    management, alice, bob, ops, _fin, assessment = fixture(tmp_path)
    management.assign(assessment.assessment_id, "group", ops.group_id)

    for student in (alice, bob):
        routes = management.effective_assignments(student.student_id)
        assert [r.source for r in routes] == ["group"], student.display_name
        assert routes[0].origin_label == "Via group · Operations A"


def test_a_member_added_later_receives_what_the_group_carries(tmp_path):
    """An empty group is a legitimate target, and stays one."""
    management, _alice, _bob, _ops, _fin, assessment = fixture(tmp_path)
    late = management.create_student("Cara Lin")
    new_group = management.create_group("Q4 intake")
    management.assign(assessment.assessment_id, "group", new_group.group_id)
    assert management.effective_assignments(late.student_id) == ()

    management.add_member(new_group.group_id, late.student_id)
    assert [r.source for r in
            management.effective_assignments(late.student_id)] == ["group"]


# ===========================================================================
# Duplicate detection: sources, not a boolean
# ===========================================================================

def test_duplicate_lookup_returns_every_existing_source(tmp_path):
    management, alice, _bob, ops, finance, assessment = fixture(tmp_path)
    management.assign(assessment.assessment_id, "group", ops.group_id)
    # Alice is in both groups, so the second route *is* a duplicate for her.
    # That is the situation this test is about, and creating it deliberately
    # is exactly what the explicit confirmation is for.
    management.assign(assessment.assessment_id, "group", finance.group_id,
                      confirm_duplicate=True)

    sources = management.assignment_sources(assessment.assessment_id,
                                            alice.student_id)
    assert len(sources) == 2, sources
    assert {source["group_name"] for source in sources} \
        == {"Operations A", "Finance payments"}
    for source in sources:
        assert source["source"] == "group"
        assert source["assignment_id"]
        assert source["created"], "a route says when it was created"


def test_assigning_a_group_warns_about_the_members_who_already_have_it(tmp_path):
    """The hard case: most of the group is new, one member is not."""
    management, alice, bob, ops, finance, assessment = fixture(tmp_path)
    management.assign(assessment.assessment_id, "group", finance.group_id)

    duplicates = management.duplicate_preview(assessment.assessment_id,
                                              "group", ops.group_id)
    affected = {entry["student"]["id"] for entry in duplicates}
    assert affected == {alice.student_id}, "Bob does not hold it yet"
    assert duplicates[0]["sources"][0]["group_name"] == "Finance payments"


def test_an_unconfirmed_duplicate_is_refused_and_writes_nothing(tmp_path):
    management, alice, _bob, ops, _fin, assessment = fixture(tmp_path)
    management.assign(assessment.assessment_id, "group", ops.group_id)
    before = len(management.repository.list_assignments())

    with pytest.raises(DuplicateAssignment) as excinfo:
        management.assign(assessment.assessment_id, "student",
                          alice.student_id)

    duplicates = excinfo.value.detail["duplicates"]
    assert duplicates[0]["student"]["id"] == alice.student_id
    assert duplicates[0]["sources"][0]["source"] == "group"
    assert len(management.repository.list_assignments()) == before


def test_a_confirmed_duplicate_creates_a_distinct_provenance_row(tmp_path):
    """Both routes survive. Neither replaces nor absorbs the other."""
    management, alice, _bob, ops, _fin, assessment = fixture(tmp_path)
    group_assignment, _ = management.assign(assessment.assessment_id, "group",
                                            ops.group_id)
    direct, replayed = management.assign(
        assessment.assessment_id, "student", alice.student_id,
        confirm_duplicate=True)

    assert replayed is False
    assert direct.assignment_id != group_assignment.assignment_id
    assert direct.confirmed_duplicate is True
    assert direct.acknowledged_sources, \
        "the record says what the trainer was shown when they confirmed"

    routes = management.effective_assignments(alice.student_id)
    assert {r.source for r in routes} == {"group", "direct"}
    assert len({r.origin_label for r in routes}) == 2
    # The original row is exactly as it was.
    assert management.repository.get_assignment(
        group_assignment.assignment_id) == group_assignment


def test_confirmation_is_server_side_input_not_a_dialog_having_been_shown(tmp_path):
    """Looking the duplicate up does not authorise creating it."""
    management, alice, _bob, ops, _fin, assessment = fixture(tmp_path)
    management.assign(assessment.assessment_id, "group", ops.group_id)

    management.duplicate_preview(assessment.assessment_id, "student",
                                 alice.student_id)
    with pytest.raises(DuplicateAssignment):
        management.assign(assessment.assessment_id, "student",
                          alice.student_id)


# ===========================================================================
# Idempotency: a retried submission is not a second assignment
# ===========================================================================

def test_a_repeated_request_token_does_not_multiply_assignments(tmp_path):
    management, _alice, _bob, ops, _fin, assessment = fixture(tmp_path)
    first, replayed_first = management.assign(
        assessment.assessment_id, "group", ops.group_id, request_id="req-1")
    second, replayed_second = management.assign(
        assessment.assessment_id, "group", ops.group_id, request_id="req-1")

    assert replayed_first is False and replayed_second is True
    assert first.assignment_id == second.assignment_id
    assert len(management.repository.list_assignments(
        assessment.assessment_id)) == 1


def test_a_deliberate_duplicate_uses_its_own_token_and_makes_its_own_row(tmp_path):
    """Idempotency must not become a way to *prevent* an intended duplicate."""
    management, alice, _bob, ops, _fin, assessment = fixture(tmp_path)
    management.assign(assessment.assessment_id, "group", ops.group_id,
                      request_id="req-1")
    direct, replayed = management.assign(
        assessment.assessment_id, "student", alice.student_id,
        confirm_duplicate=True, request_id="req-2")

    assert replayed is False
    assert len(management.effective_assignments(alice.student_id)) == 2


def test_a_replayed_token_is_honoured_before_the_duplicate_check(tmp_path):
    """A retried confirmed duplicate does not raise, and does not add a row."""
    management, alice, _bob, ops, _fin, assessment = fixture(tmp_path)
    management.assign(assessment.assessment_id, "group", ops.group_id)
    management.assign(assessment.assessment_id, "student", alice.student_id,
                      confirm_duplicate=True, request_id="req-dup")

    again, replayed = management.assign(
        assessment.assessment_id, "student", alice.student_id,
        confirm_duplicate=True, request_id="req-dup")
    assert replayed is True
    assert len(management.effective_assignments(alice.student_id)) == 2


# ===========================================================================
# Targets
# ===========================================================================

def test_an_unknown_target_is_refused_before_anything_is_written(tmp_path):
    management, _alice, _bob, _ops, _fin, assessment = fixture(tmp_path)
    with pytest.raises(Exception):
        management.assign(assessment.assessment_id, "student", "stu-nobody")
    with pytest.raises(ManagementRefused):
        management.assign(assessment.assessment_id, "cohort", "anything")
    assert management.repository.list_assignments() == ()
