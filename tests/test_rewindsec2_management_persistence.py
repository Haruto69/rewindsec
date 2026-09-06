"""Batch 5 persistence: students, groups, many-to-many membership, assessments.

What these hold is that the administrative records are *records* -- they
survive a service being thrown away and rebuilt, they express membership as a
genuine many-to-many relation rather than a label on a person, and adding them
to a database leaves the Batch 1-4 session tables exactly as they were.
"""

import sqlalchemy as sa

import pytest

from rewindsec.domain.errors import InvalidIdentityError
from rewindsec.management.ids import SequenceIdSource, derive_student_id
from rewindsec.management.ports import AlreadyExistsError, NotFoundError
from rewindsec.management.records import (Assessment, Assignment, Student,
                                          RETRY_POLICY_BOUNDED)
from rewindsec.management.service import ManagementRefused
from rewindsec.persistence import sqlalchemy_adapter as session_adapter
from rewindsec.persistence.management_adapter import \
    SqlAlchemyManagementRepository

from tests.management_helpers import LEARNER, build, sqlite_uri


# ===========================================================================
# Round trips
# ===========================================================================

def test_student_round_trips_through_storage(tmp_path):
    uri = sqlite_uri(tmp_path)
    ids = SequenceIdSource()
    management, _ws, _sessions = build(uri, ids=ids)
    created = management.create_student("Alice Doe", reference="NB-1",
                                        cohort="Operations")

    reloaded = management.get_student(created.student_id)
    assert reloaded == created
    assert reloaded.learner_ref is None, \
        "a trainer-created student is unbound until a learner claims them"
    assert reloaded.origin == "trainer"
    assert reloaded.initials == "AD"


def test_records_survive_service_recreation(tmp_path):
    """The whole object graph rebuilt against the same database sees the rows."""
    uri = sqlite_uri(tmp_path)
    ids = SequenceIdSource()
    first, _ws, _sessions = build(uri, ids=ids)
    student = first.create_student("Alice Doe")
    group = first.create_group("Operations A")
    first.add_member(group.group_id, student.student_id)
    assessment = first.create_assessment("Q3 judgement", "mixed", 3)
    first.assign(assessment.assessment_id, "group", group.group_id)

    second, _ws2, _sessions2 = build(uri, ids=ids)
    assert [s.student_id for s in second.list_students()] == [student.student_id]
    assert [g.group_id for g in second.list_groups()] == [group.group_id]
    assert [a.assessment_id for a in second.list_assessments()] \
        == [assessment.assessment_id]
    routes = second.effective_assignments(student.student_id)
    assert [r.source for r in routes] == ["group"]


def test_assessment_round_trips_with_its_retry_policy(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    created = management.create_assessment(
        "Payment authorisation", "bec", 4, status="open", max_attempts=3,
        window_label="1 - 30 September", note="Finance facing.")

    reloaded = management.get_assessment(created.assessment_id)
    assert reloaded == created
    assert reloaded.focus == "bec"
    assert reloaded.required_interactions == 4
    assert reloaded.max_attempts == 3
    assert reloaded.retry_policy == RETRY_POLICY_BOUNDED
    assert reloaded.definition_version == "rewindsec-assessment-definition/v1"


# ===========================================================================
# Membership is many-to-many, and is not a cohort string
# ===========================================================================

def test_one_student_belongs_to_several_groups(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    alice = management.create_student("Alice Doe", cohort="Operations")
    ops = management.create_group("Operations A")
    finance = management.create_group("Finance payments")
    management.add_member(ops.group_id, alice.student_id)
    management.add_member(finance.group_id, alice.student_id)

    groups = {g.group_id for g in management.groups_for_student(alice.student_id)}
    assert groups == {ops.group_id, finance.group_id}
    # And the cohort label is not what carried either of them.
    assert alice.cohort == "Operations"


def test_one_group_contains_several_students(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    alice = management.create_student("Alice Doe")
    bob = management.create_student("Bob Roe")
    group = management.create_group("Operations A")
    management.add_member(group.group_id, alice.student_id)
    management.add_member(group.group_id, bob.student_id)

    members = {m.student_id for m in
               management.list_memberships(group_id=group.group_id)}
    assert members == {alice.student_id, bob.student_id}


def test_adding_the_same_member_twice_is_refused_not_duplicated(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    alice = management.create_student("Alice Doe")
    group = management.create_group("Operations A")
    management.add_member(group.group_id, alice.student_id)

    with pytest.raises(ManagementRefused) as excinfo:
        management.add_member(group.group_id, alice.student_id)
    assert excinfo.value.code == "already_member"
    assert len(management.list_memberships(group_id=group.group_id)) == 1


def test_removing_membership_leaves_the_assignment_rows_alone(tmp_path):
    """Membership is current state; an assignment is a record of a decision.

    Removing a member stops the group *reaching* them -- effective assignments
    are resolved from current membership -- but the assignment row itself is
    untouched, so the group still carries the assessment for everybody else
    and the historical fact that it was assigned is not rewritten.
    """
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    alice = management.create_student("Alice Doe")
    bob = management.create_student("Bob Roe")
    group = management.create_group("Operations A")
    management.add_member(group.group_id, alice.student_id)
    management.add_member(group.group_id, bob.student_id)
    assessment = management.create_assessment("Q3", "mixed", 2)
    assignment, _ = management.assign(assessment.assessment_id, "group",
                                      group.group_id)

    assert management.remove_member(group.group_id, alice.student_id) is True

    assert management.repository.get_assignment(assignment.assignment_id) \
        is not None
    assert management.effective_assignments(alice.student_id) == ()
    assert len(management.effective_assignments(bob.student_id)) == 1


# ===========================================================================
# Identity rules
# ===========================================================================

def test_a_learner_reference_belongs_to_exactly_one_student(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    first = management.ensure_student_for_learner_ref(LEARNER)
    second = management.ensure_student_for_learner_ref(LEARNER)
    assert first.student_id == second.student_id

    # And storage refuses a second student claiming the same reference, so two
    # rows can never both answer "whose session is this?".
    with pytest.raises(AlreadyExistsError):
        management.repository.create_student(Student(
            student_id="stu-other", display_name="Impostor",
            learner_ref=LEARNER))


def test_auto_provisioned_student_id_is_derived_not_random(tmp_path):
    """Re-provisioning the same reference cannot split one person's history."""
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    student = management.ensure_student_for_learner_ref(LEARNER)
    assert student.student_id == derive_student_id(LEARNER)
    assert student.origin == "self_provisioned"
    # Stable across processes: no ``hash()``, no RNG.
    assert derive_student_id(LEARNER) == derive_student_id(LEARNER)


def test_auto_provisioned_identity_carries_no_personal_data(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    student = management.ensure_student_for_learner_ref(LEARNER)
    assert student.reference is None
    assert student.cohort is None
    assert LEARNER not in student.display_name


def test_records_reject_a_malformed_identity():
    with pytest.raises(InvalidIdentityError):
        Student(student_id="not a valid id", display_name="X")
    with pytest.raises(InvalidIdentityError):
        Assessment(assessment_id="as-1", name="X", focus="not-a-focus",
                   required_interactions=1)
    with pytest.raises(InvalidIdentityError):
        # A direct assignment naming a group is incoherent, not merely odd.
        Assignment(assignment_id="asg-1", assessment_id="as-1",
                   target_type="student", student_id="stu-1", group_id="grp-1")


# ===========================================================================
# Schema discipline
# ===========================================================================

def test_batch5_tables_are_additive_and_separately_named(tmp_path):
    """Adding Batch 5 creates new tables and alters no Batch 1-4 one."""
    uri = sqlite_uri(tmp_path)
    engine = sa.create_engine(uri)
    sessions = session_adapter.SqlAlchemySessionRepository(engine)
    sessions.create_schema()

    before = _table_shapes(engine)
    SqlAlchemyManagementRepository(engine).create_schema()
    after = _table_shapes(engine)

    for name, columns in before.items():
        assert after[name] == columns, "Batch 5 altered %s" % name
    added = set(after) - set(before)
    assert added == {
        "rewindsec2_students", "rewindsec2_student_groups",
        "rewindsec2_group_members", "rewindsec2_assessments",
        "rewindsec2_assignments", "rewindsec2_attempts",
        "rewindsec2_session_owners", "rewindsec2_enrollment_codes"}
    for name in added:
        assert name.startswith("rewindsec2_"), name


def test_creating_the_schema_twice_is_non_destructive(tmp_path):
    uri = sqlite_uri(tmp_path)
    ids = SequenceIdSource()
    management, _ws, _sessions = build(uri, ids=ids)
    student = management.create_student("Alice Doe")

    engine = sa.create_engine(uri)
    SqlAlchemyManagementRepository(engine).create_schema()
    SqlAlchemyManagementRepository(engine).create_schema()

    again, _ws2, _sessions2 = build(uri, ids=ids)
    assert again.get_student(student.student_id) == student


def test_a_missing_record_is_a_not_found_not_a_guess(tmp_path):
    management, _ws, _sessions = build(sqlite_uri(tmp_path))
    assert management.get_student("stu-nobody") is None
    assert management.get_group("grp-nothing") is None
    assert management.get_assessment("as-nothing") is None
    with pytest.raises(NotFoundError):
        management.require_student("stu-nobody")


def _table_shapes(engine):
    inspector = sa.inspect(engine)
    return {name: sorted(column["name"]
                         for column in inspector.get_columns(name))
            for name in inspector.get_table_names()}


# ===========================================================================
# Package boundaries
# ===========================================================================

import ast  # noqa: E402
import io as _io  # noqa: E402
import pathlib  # noqa: E402

MANAGEMENT_ROOT = (pathlib.Path(__file__).resolve().parent.parent
                   / "rewindsec" / "management")
MANAGEMENT_MODULES = sorted(p for p in MANAGEMENT_ROOT.rglob("*.py")
                            if "__pycache__" not in p.parts)


def _imports(path):
    tree = ast.parse(_io.open(path, encoding="utf-8").read())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_the_management_package_has_modules():
    assert MANAGEMENT_MODULES
    names = {p.name for p in MANAGEMENT_MODULES}
    assert {"__init__.py", "records.py", "ports.py", "service.py",
            "assignments.py", "progress.py", "analytics.py",
            "session_link.py", "projection.py", "ids.py"} <= names, names


@pytest.mark.parametrize("module_path", MANAGEMENT_MODULES,
                         ids=lambda p: p.name)
def test_management_module_imports_no_framework_or_storage(module_path):
    """The management layer talks to storage and HTTP only through ports.

    The SQLAlchemy adapter lives in ``rewindsec/persistence/``; the HTTP
    adapter lives in ``rewindsec/prototype/``. Neither may leak in here, or
    the records could not be exercised in a pure Python test.
    """
    forbidden = _imports(module_path) & {
        "flask", "flask_sqlalchemy", "sqlalchemy", "werkzeug", "app"}
    assert not forbidden, (module_path.name, sorted(forbidden))


@pytest.mark.parametrize("module_path", MANAGEMENT_MODULES,
                         ids=lambda p: p.name)
def test_management_module_never_imports_random(module_path):
    """No administrative value is ever drawn from a random source.

    ``secrets`` in ``ids.py`` is the one entropy source, and it is
    deliberately *not* the simulation's RNG: a session's named streams decide
    what happens inside the simulation, and an administrative id drawn from
    one would make the simulation's future depend on how many students a
    trainer happened to create.
    """
    assert "random" not in _imports(module_path), module_path.name


def test_only_the_id_module_reaches_for_entropy():
    users = {p.name for p in MANAGEMENT_MODULES if "secrets" in _imports(p)}
    assert users == {"ids.py"}, users


def test_no_management_module_derives_an_identifier_from_builtin_hash():
    """``hash()`` is salted per process; a stable id must never come from it."""
    for path in MANAGEMENT_MODULES:
        tree = ast.parse(_io.open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id != "hash", path.name


def test_only_the_service_reads_an_application_clock():
    """Administrative time is confined, and never reaches a simulation."""
    users = {p.name for p in MANAGEMENT_MODULES
             if _imports(p) & {"datetime", "time"}}
    assert users == {"service.py"}, users
