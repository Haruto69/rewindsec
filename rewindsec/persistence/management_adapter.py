"""The SQLAlchemy-backed :class:`~rewindsec.management.ports.ManagementRepository`.

The same adapter shape ``sqlalchemy_adapter.py`` already uses for the session
aggregate, extended to the Batch 5 administrative records rather than
duplicated into a second persistence stack: SQLAlchemy Core tables on their
own :class:`~sqlalchemy.MetaData`, constructed against an
:class:`~sqlalchemy.engine.Engine` handed in by the caller, with no Flask
import anywhere and no ``app.py`` dependency. It is testable in-process
against a throwaway SQLite engine.

Storage shape
-------------
Eight tables, all prefixed ``rewindsec2_`` like every other 2.0 table so no
query can mix 2.0 rows with v1 ones:

``rewindsec2_students``          one row per learner record
``rewindsec2_student_groups``    one row per group
``rewindsec2_group_members``     the many-to-many membership relation
``rewindsec2_assessments``       one row per assessment definition
``rewindsec2_assignments``       one row per assignment, with its provenance
``rewindsec2_attempts``          one row per assessment attempt
``rewindsec2_session_owners``    session -> student, plus admin timestamps
``rewindsec2_enrollment_codes``  the single-use learner -> student claim

Creation is ``checkfirst=True`` and additive. Adding Batch 5 touches no Batch
1-4 table: the session, event and action tables keep their columns and their
rows, and a session stored before this module existed simply has no
``rewindsec2_session_owners`` row -- which is exactly how a legacy, unowned
session is recognised rather than guessed at.

No pickle. The one structured column (an attempt's finalized scoring result)
is JSON text produced by
:meth:`rewindsec.scoring.result.ScoringResult.to_state` and read back with
:func:`json.loads`.
"""

import json

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from rewindsec.management.ports import (AlreadyExistsError,
                                        DuplicateRequestError,
                                        ManagementRepository, NotFoundError)
from rewindsec.management.records import (Assessment, Assignment, Attempt,
                                          EnrollmentCode, GroupMembership,
                                          SessionOwnership, Student,
                                          StudentGroup)


class _EnrollmentResetChanged(Exception):
    """Roll back a reset whose checked ownership/Attempt set moved."""

__all__ = ["SqlAlchemyManagementRepository", "metadata", "students_table",
           "groups_table", "memberships_table", "assessments_table",
           "assignments_table", "attempts_table", "session_owners_table",
           "enrollment_codes_table"]

metadata = sa.MetaData()

students_table = sa.Table(
    "rewindsec2_students", metadata,
    sa.Column("student_id", sa.String(128), primary_key=True),
    sa.Column("display_name", sa.String(120), nullable=False),
    sa.Column("reference", sa.String(64)),
    sa.Column("cohort", sa.String(64)),
    sa.Column("status", sa.String(32), nullable=False),
    # Unique, so one server-minted learner reference can never be bound to two
    # student records -- the condition under which "whose session is this?"
    # would stop having one answer.
    sa.Column("learner_ref", sa.String(128), unique=True),
    sa.Column("origin", sa.String(32), nullable=False),
    sa.Column("created_at", sa.String(64)),
)

groups_table = sa.Table(
    "rewindsec2_student_groups", metadata,
    sa.Column("group_id", sa.String(128), primary_key=True),
    sa.Column("name", sa.String(120), nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("created_at", sa.String(64)),
    sa.Column("created_by", sa.String(120)),
)

memberships_table = sa.Table(
    "rewindsec2_group_members", metadata,
    sa.Column("membership_id", sa.String(128), primary_key=True),
    sa.Column("group_id", sa.String(128), nullable=False, index=True),
    sa.Column("student_id", sa.String(128), nullable=False, index=True),
    sa.Column("added_at", sa.String(64)),
    sa.Column("added_by", sa.String(120)),
    sa.UniqueConstraint("group_id", "student_id",
                        name="uq_rewindsec2_group_member"),
)

assessments_table = sa.Table(
    "rewindsec2_assessments", metadata,
    sa.Column("assessment_id", sa.String(128), primary_key=True),
    sa.Column("name", sa.String(120), nullable=False),
    sa.Column("focus", sa.String(32), nullable=False),
    sa.Column("required_interactions", sa.Integer, nullable=False),
    sa.Column("status", sa.String(32), nullable=False),
    sa.Column("max_attempts", sa.Integer, nullable=False),
    sa.Column("retry_policy", sa.String(64), nullable=False),
    sa.Column("window_label", sa.String(160)),
    sa.Column("note", sa.Text),
    sa.Column("created_at", sa.String(64)),
    sa.Column("created_by", sa.String(120)),
    sa.Column("definition_version", sa.String(64), nullable=False),
)

assignments_table = sa.Table(
    "rewindsec2_assignments", metadata,
    sa.Column("assignment_id", sa.String(128), primary_key=True),
    sa.Column("assessment_id", sa.String(128), nullable=False, index=True),
    sa.Column("target_type", sa.String(16), nullable=False),
    sa.Column("student_id", sa.String(128), index=True),
    sa.Column("group_id", sa.String(128), index=True),
    sa.Column("created_at", sa.String(64)),
    sa.Column("created_by", sa.String(120)),
    # The trainer client's idempotency token. Unique so a retried submission
    # of the *same* intended operation resolves to the row it already made
    # instead of creating a second one. A deliberate duplicate is a different
    # operation and carries a different token.
    sa.Column("request_id", sa.String(80), unique=True),
    sa.Column("confirmed_duplicate", sa.Boolean, nullable=False,
              default=False),
    sa.Column("acknowledged_sources_json", sa.Text),
    sa.Column("status", sa.String(16), nullable=False),
)

attempts_table = sa.Table(
    "rewindsec2_attempts", metadata,
    sa.Column("attempt_id", sa.String(128), primary_key=True),
    sa.Column("assessment_id", sa.String(128), nullable=False, index=True),
    sa.Column("student_id", sa.String(128), nullable=False, index=True),
    sa.Column("attempt_number", sa.Integer, nullable=False),
    sa.Column("status", sa.String(32), nullable=False),
    # Unique: one TrainingSession is at most one attempt. A second attempt can
    # never be pointed at a session that already belongs to one.
    sa.Column("session_id", sa.String(128), unique=True),
    sa.Column("assignment_id", sa.String(128)),
    sa.Column("assignment_source", sa.String(16)),
    sa.Column("assignment_group_id", sa.String(128)),
    sa.Column("required_interactions", sa.Integer, nullable=False),
    sa.Column("assessment_definition_version", sa.String(64), nullable=False),
    sa.Column("started_at", sa.String(64)),
    sa.Column("ended_at", sa.String(64)),
    sa.Column("result_json", sa.Text),
    sa.Column("scoring_version", sa.String(64)),
    sa.Column("rubric_version", sa.String(64)),
    sa.Column("evidence_model_version", sa.String(64)),
    sa.Column("overall", sa.Integer),
    # Batch 5 correction. Nullable, so a row written before the
    # required-interaction completion rule existed reads back as "never
    # recorded" rather than as "the learner resolved none of them".
    sa.Column("completed_interactions", sa.Integer),
    sa.Column("termination_reason", sa.String(32)),
    sa.UniqueConstraint("student_id", "assessment_id", "attempt_number",
                        name="uq_rewindsec2_attempt_number"),
)

session_owners_table = sa.Table(
    "rewindsec2_session_owners", metadata,
    sa.Column("session_id", sa.String(128), primary_key=True),
    sa.Column("student_id", sa.String(128), nullable=False, index=True),
    sa.Column("learner_ref", sa.String(128), nullable=False, index=True),
    sa.Column("focus", sa.String(32), nullable=False),
    sa.Column("mode", sa.String(32), nullable=False),
    sa.Column("attempt_id", sa.String(128)),
    sa.Column("started_at", sa.String(64)),
    sa.Column("last_seen_at", sa.String(64)),
)

enrollment_codes_table = sa.Table(
    "rewindsec2_enrollment_codes", metadata,
    sa.Column("code_id", sa.String(128), primary_key=True),
    # Unique, and the only column a learner request is ever matched
    # against. Two codes that collided would be two students one claim
    # could resolve to, which is the condition under which "who is this?"
    # stops having one answer.
    sa.Column("code", sa.String(128), nullable=False, unique=True),
    sa.Column("student_id", sa.String(128), nullable=False, index=True),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("created_at", sa.String(64)),
    sa.Column("created_by", sa.String(120)),
    sa.Column("claimed_at", sa.String(64)),
    # Which browser spent this code. Written exactly once, by the
    # conditional UPDATE in ``claim_enrollment_code``; a replay finds it
    # already set and matches zero rows.
    sa.Column("claimed_learner_ref", sa.String(128)),
)


def _dumps(state):
    return json.dumps(state, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)


def _loads(text):
    if not text:
        return None
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


class SqlAlchemyManagementRepository(ManagementRepository):
    """A :class:`~rewindsec.management.ports.ManagementRepository` over SQLAlchemy.

    ``create_schema()`` must be called once per engine before use. It is
    ``checkfirst=True``, so running it against a database that already holds
    Batch 1-4 tables adds these eight and touches nothing else.
    """

    def __init__(self, engine):
        self._engine = engine

    def create_schema(self):
        metadata.create_all(self._engine, checkfirst=True)

    # -- students ---------------------------------------------------------

    def create_student(self, student):
        row = {
            "student_id": student.student_id,
            "display_name": student.display_name,
            "reference": student.reference,
            "cohort": student.cohort,
            "status": student.status,
            "learner_ref": student.learner_ref,
            "origin": student.origin,
            "created_at": student.created_at,
        }
        try:
            with self._engine.begin() as conn:
                conn.execute(students_table.insert().values(**row))
        except IntegrityError as exc:
            raise AlreadyExistsError(
                "student %r (or its learner reference) already exists"
                % student.student_id) from exc
        return student

    def update_student(self, student):
        with self._engine.begin() as conn:
            result = conn.execute(
                students_table.update()
                .where(students_table.c.student_id == student.student_id)
                .values(display_name=student.display_name,
                        reference=student.reference, cohort=student.cohort,
                        status=student.status, learner_ref=student.learner_ref,
                        origin=student.origin, created_at=student.created_at))
            if result.rowcount == 0:
                raise NotFoundError("no student with id %r" % student.student_id)
        return student

    def get_student(self, student_id):
        return self._one(students_table, students_table.c.student_id == student_id,
                         self._student)

    def student_for_learner_ref(self, learner_ref):
        if not learner_ref:
            return None
        return self._one(students_table,
                         students_table.c.learner_ref == learner_ref,
                         self._student)

    def list_students(self):
        return self._many(
            sa.select(students_table).order_by(students_table.c.display_name,
                                               students_table.c.student_id),
            self._student)

    # -- groups and membership --------------------------------------------

    def create_group(self, group):
        try:
            with self._engine.begin() as conn:
                conn.execute(groups_table.insert().values(
                    group_id=group.group_id, name=group.name,
                    description=group.description,
                    created_at=group.created_at, created_by=group.created_by))
        except IntegrityError as exc:
            raise AlreadyExistsError(
                "group %r already exists" % group.group_id) from exc
        return group

    def get_group(self, group_id):
        return self._one(groups_table, groups_table.c.group_id == group_id,
                         self._group)

    def list_groups(self):
        return self._many(
            sa.select(groups_table).order_by(groups_table.c.name,
                                             groups_table.c.group_id),
            self._group)

    def add_membership(self, membership):
        try:
            with self._engine.begin() as conn:
                conn.execute(memberships_table.insert().values(
                    membership_id=membership.membership_id,
                    group_id=membership.group_id,
                    student_id=membership.student_id,
                    added_at=membership.added_at,
                    added_by=membership.added_by))
        except IntegrityError as exc:
            raise AlreadyExistsError(
                "student %r is already a member of group %r"
                % (membership.student_id, membership.group_id)) from exc
        return membership

    def remove_membership(self, group_id, student_id):
        with self._engine.begin() as conn:
            result = conn.execute(
                memberships_table.delete().where(sa.and_(
                    memberships_table.c.group_id == group_id,
                    memberships_table.c.student_id == student_id)))
        return bool(result.rowcount)

    def list_memberships(self, group_id=None, student_id=None):
        query = sa.select(memberships_table)
        if group_id is not None:
            query = query.where(memberships_table.c.group_id == group_id)
        if student_id is not None:
            query = query.where(memberships_table.c.student_id == student_id)
        query = query.order_by(memberships_table.c.group_id,
                               memberships_table.c.student_id)
        return self._many(query, self._membership)

    # -- assessments -------------------------------------------------------

    def create_assessment(self, assessment):
        try:
            with self._engine.begin() as conn:
                conn.execute(assessments_table.insert().values(
                    **self._assessment_row(assessment)))
        except IntegrityError as exc:
            raise AlreadyExistsError(
                "assessment %r already exists" % assessment.assessment_id) from exc
        return assessment

    def update_assessment(self, assessment):
        row = self._assessment_row(assessment)
        row.pop("assessment_id")
        with self._engine.begin() as conn:
            result = conn.execute(
                assessments_table.update()
                .where(assessments_table.c.assessment_id
                       == assessment.assessment_id)
                .values(**row))
            if result.rowcount == 0:
                raise NotFoundError(
                    "no assessment with id %r" % assessment.assessment_id)
        return assessment

    def get_assessment(self, assessment_id):
        return self._one(assessments_table,
                         assessments_table.c.assessment_id == assessment_id,
                         self._assessment)

    def list_assessments(self):
        return self._many(
            sa.select(assessments_table).order_by(
                assessments_table.c.name, assessments_table.c.assessment_id),
            self._assessment)

    # -- assignments -------------------------------------------------------

    def create_assignment(self, assignment):
        try:
            with self._engine.begin() as conn:
                conn.execute(assignments_table.insert().values(
                    assignment_id=assignment.assignment_id,
                    assessment_id=assignment.assessment_id,
                    target_type=assignment.target_type,
                    student_id=assignment.student_id,
                    group_id=assignment.group_id,
                    created_at=assignment.created_at,
                    created_by=assignment.created_by,
                    request_id=assignment.request_id,
                    confirmed_duplicate=assignment.confirmed_duplicate,
                    acknowledged_sources_json=_dumps(
                        assignment.acknowledged_sources),
                    status=assignment.status))
        except IntegrityError as exc:
            existing = (self.assignment_for_request(assignment.request_id)
                        if assignment.request_id else None)
            if existing is not None:
                raise DuplicateRequestError(
                    "assignment request %r has already been applied"
                    % assignment.request_id,
                    assignment_id=existing.assignment_id) from exc
            raise AlreadyExistsError(
                "assignment %r already exists" % assignment.assignment_id) from exc
        return assignment

    def get_assignment(self, assignment_id):
        return self._one(assignments_table,
                         assignments_table.c.assignment_id == assignment_id,
                         self._assignment)

    def assignment_for_request(self, request_id):
        if not request_id:
            return None
        return self._one(assignments_table,
                         assignments_table.c.request_id == request_id,
                         self._assignment)

    def list_assignments(self, assessment_id=None):
        query = sa.select(assignments_table).where(
            assignments_table.c.status == "active")
        if assessment_id is not None:
            query = query.where(
                assignments_table.c.assessment_id == assessment_id)
        query = query.order_by(assignments_table.c.created_at,
                               assignments_table.c.assignment_id)
        return self._many(query, self._assignment)

    # -- attempts ----------------------------------------------------------

    def create_attempt(self, attempt):
        try:
            with self._engine.begin() as conn:
                conn.execute(attempts_table.insert().values(
                    **self._attempt_row(attempt)))
        except IntegrityError as exc:
            raise AlreadyExistsError(
                "attempt %r already exists, or its session or attempt number "
                "is already taken" % attempt.attempt_id) from exc
        return attempt

    def update_attempt(self, attempt):
        row = self._attempt_row(attempt)
        row.pop("attempt_id")
        with self._engine.begin() as conn:
            result = conn.execute(
                attempts_table.update()
                .where(attempts_table.c.attempt_id == attempt.attempt_id)
                .values(**row))
            if result.rowcount == 0:
                raise NotFoundError("no attempt with id %r" % attempt.attempt_id)
        return attempt

    def get_attempt(self, attempt_id):
        return self._one(attempts_table,
                         attempts_table.c.attempt_id == attempt_id,
                         self._attempt)

    def attempt_for_session(self, session_id):
        if not session_id:
            return None
        return self._one(attempts_table,
                         attempts_table.c.session_id == session_id,
                         self._attempt)

    def list_attempts(self, student_id=None, assessment_id=None):
        query = sa.select(attempts_table)
        if student_id is not None:
            query = query.where(attempts_table.c.student_id == student_id)
        if assessment_id is not None:
            query = query.where(attempts_table.c.assessment_id == assessment_id)
        query = query.order_by(attempts_table.c.student_id,
                               attempts_table.c.assessment_id,
                               attempts_table.c.attempt_number)
        return self._many(query, self._attempt)

    # -- session ownership -------------------------------------------------

    def record_session_ownership(self, ownership):
        with self._engine.begin() as conn:
            existing = conn.execute(
                sa.select(session_owners_table)
                .where(session_owners_table.c.session_id == ownership.session_id)
            ).mappings().first()
            if existing is None:
                conn.execute(session_owners_table.insert().values(
                    session_id=ownership.session_id,
                    student_id=ownership.student_id,
                    learner_ref=ownership.learner_ref,
                    focus=ownership.focus, mode=ownership.mode,
                    attempt_id=ownership.attempt_id,
                    started_at=ownership.started_at,
                    last_seen_at=ownership.last_seen_at))
                return ownership
            if existing["student_id"] != ownership.student_id \
                    or existing["learner_ref"] != ownership.learner_ref:
                # Ownership is established once, from the server-minted
                # learner reference the session was created under. A later
                # call claiming a different owner is a bug or an attack, and
                # either way must not be applied.
                raise AlreadyExistsError(
                    "session %r is already owned by student %r"
                    % (ownership.session_id, existing["student_id"]))
            conn.execute(
                session_owners_table.update()
                .where(session_owners_table.c.session_id == ownership.session_id)
                .values(attempt_id=ownership.attempt_id or existing["attempt_id"],
                        last_seen_at=ownership.last_seen_at
                        or existing["last_seen_at"]))
        return self.get_session_ownership(ownership.session_id)

    def get_session_ownership(self, session_id):
        return self._one(session_owners_table,
                         session_owners_table.c.session_id == session_id,
                         self._ownership)

    def list_session_ownership(self, student_id=None):
        query = sa.select(session_owners_table)
        if student_id is not None:
            query = query.where(session_owners_table.c.student_id == student_id)
        query = query.order_by(sa.desc(session_owners_table.c.started_at),
                               session_owners_table.c.session_id)
        return self._many(query, self._ownership)

    # -- enrolment ---------------------------------------------------------

    def create_enrollment_code(self, code):
        try:
            with self._engine.begin() as conn:
                conn.execute(enrollment_codes_table.insert().values(
                    code_id=code.code_id, code=code.code,
                    student_id=code.student_id, status=code.status,
                    created_at=code.created_at, created_by=code.created_by,
                    claimed_at=code.claimed_at,
                    claimed_learner_ref=code.claimed_learner_ref))
        except IntegrityError as exc:
            raise AlreadyExistsError(
                "enrolment code %r already exists" % code.code_id) from exc
        return code

    def get_enrollment_code(self, code):
        if not code:
            return None
        return self._one(enrollment_codes_table,
                         enrollment_codes_table.c.code == code,
                         self._enrollment_code)

    def list_enrollment_codes(self, student_id=None):
        query = sa.select(enrollment_codes_table)
        if student_id is not None:
            query = query.where(
                enrollment_codes_table.c.student_id == student_id)
        query = query.order_by(enrollment_codes_table.c.created_at,
                               enrollment_codes_table.c.code_id)
        return self._many(query, self._enrollment_code)

    def claim_enrollment_code(self, code, learner_ref, claimed_at):
        """One conditional UPDATE, and deliberately not a read-then-write.

        The ``WHERE`` clause carries the whole precondition -- still open,
        still unclaimed -- so the database decides which of two browsers
        racing on the same code wins. The loser matches zero rows and is told
        no; there is no window in which both read "unclaimed" and both write.
        """
        with self._engine.begin() as conn:
            result = conn.execute(
                enrollment_codes_table.update()
                .where(sa.and_(
                    enrollment_codes_table.c.code == code,
                    enrollment_codes_table.c.status == "open",
                    enrollment_codes_table.c.claimed_learner_ref.is_(None)))
                .values(status="claimed", claimed_at=claimed_at,
                        claimed_learner_ref=learner_ref))
            if result.rowcount == 0:
                return None
        return self.get_enrollment_code(code)

    def revoke_open_enrollment_codes(self, student_id):
        with self._engine.begin() as conn:
            result = conn.execute(
                enrollment_codes_table.update()
                .where(sa.and_(
                    enrollment_codes_table.c.student_id == student_id,
                    enrollment_codes_table.c.status == "open"))
                .values(status="revoked"))
        return int(result.rowcount or 0)

    def reset_student_enrollment(self, student_id, expected_learner_ref,
                                 expected_ownership_count,
                                 expected_attempt_count):
        """One transaction: revoke codes, then conditionally clear binding."""
        ownership_count = sa.select(sa.func.count()).select_from(
            session_owners_table).where(
                session_owners_table.c.student_id == student_id).scalar_subquery()
        attempt_count = sa.select(sa.func.count()).select_from(
            attempts_table).where(
                attempts_table.c.student_id == student_id).scalar_subquery()
        binding = students_table.c.student_id == student_id
        if expected_learner_ref is None:
            binding = sa.and_(binding, students_table.c.learner_ref.is_(None))
        else:
            binding = sa.and_(
                binding,
                students_table.c.learner_ref == expected_learner_ref)
        condition = sa.and_(
            binding,
            ownership_count == expected_ownership_count,
            attempt_count == expected_attempt_count)
        try:
            with self._engine.begin() as conn:
                conn.execute(
                    enrollment_codes_table.update()
                    .where(sa.and_(
                        enrollment_codes_table.c.student_id == student_id,
                        enrollment_codes_table.c.status == "open"))
                    .values(status="revoked"))
                result = conn.execute(
                    students_table.update().where(condition)
                    .values(learner_ref=None))
                if result.rowcount == 0:
                    raise _EnrollmentResetChanged()
        except _EnrollmentResetChanged:
            return None
        return self.get_student(student_id)

    def bind_student_learner_ref(self, student_id, learner_ref,
                                 expected_learner_ref=None):
        """A compare-and-set on the student's learner reference.

        Guarded the same way for the same reason: binding is the moment a
        person becomes a roster record, and a lost update here would attach
        two browsers to one student.
        """
        condition = students_table.c.student_id == student_id
        if expected_learner_ref is None:
            condition = sa.and_(condition,
                                students_table.c.learner_ref.is_(None))
        else:
            condition = sa.and_(
                condition,
                students_table.c.learner_ref == expected_learner_ref)
        try:
            with self._engine.begin() as conn:
                result = conn.execute(
                    students_table.update().where(condition)
                    .values(learner_ref=learner_ref))
        except IntegrityError as exc:
            # The unique index on ``learner_ref`` rejected it: that reference
            # already belongs to another student. Refused, never resolved by
            # picking a winner.
            raise AlreadyExistsError(
                "learner reference is already bound to another student"
            ) from exc
        if result.rowcount == 0:
            return None
        return self.get_student(student_id)

    # -- row helpers -------------------------------------------------------

    def _one(self, table, condition, build):
        with self._engine.begin() as conn:
            row = conn.execute(
                sa.select(table).where(condition)).mappings().first()
        return None if row is None else build(row)

    def _many(self, query, build):
        with self._engine.begin() as conn:
            rows = conn.execute(query).mappings().all()
        return tuple(build(row) for row in rows)

    @staticmethod
    def _assessment_row(assessment):
        return {
            "assessment_id": assessment.assessment_id,
            "name": assessment.name, "focus": assessment.focus,
            "required_interactions": assessment.required_interactions,
            "status": assessment.status,
            "max_attempts": assessment.max_attempts,
            "retry_policy": assessment.retry_policy,
            "window_label": assessment.window_label, "note": assessment.note,
            "created_at": assessment.created_at,
            "created_by": assessment.created_by,
            "definition_version": assessment.definition_version,
        }

    @staticmethod
    def _attempt_row(attempt):
        return {
            "attempt_id": attempt.attempt_id,
            "assessment_id": attempt.assessment_id,
            "student_id": attempt.student_id,
            "attempt_number": attempt.attempt_number,
            "status": attempt.status, "session_id": attempt.session_id,
            "assignment_id": attempt.assignment_id,
            "assignment_source": attempt.assignment_source,
            "assignment_group_id": attempt.assignment_group_id,
            "required_interactions": attempt.required_interactions,
            "assessment_definition_version":
                attempt.assessment_definition_version,
            "started_at": attempt.started_at, "ended_at": attempt.ended_at,
            "result_json": (None if attempt.result_state is None
                            else _dumps(attempt.result_state)),
            "scoring_version": attempt.scoring_version,
            "rubric_version": attempt.rubric_version,
            "evidence_model_version": attempt.evidence_model_version,
            "overall": attempt.overall,
            "completed_interactions": attempt.completed_interactions,
            "termination_reason": attempt.termination_reason,
        }

    @staticmethod
    def _student(row):
        return Student(student_id=row["student_id"],
                       display_name=row["display_name"],
                       reference=row["reference"], cohort=row["cohort"],
                       status=row["status"], learner_ref=row["learner_ref"],
                       origin=row["origin"], created_at=row["created_at"])

    @staticmethod
    def _group(row):
        return StudentGroup(group_id=row["group_id"], name=row["name"],
                            description=row["description"],
                            created_at=row["created_at"],
                            created_by=row["created_by"])

    @staticmethod
    def _membership(row):
        return GroupMembership(membership_id=row["membership_id"],
                               group_id=row["group_id"],
                               student_id=row["student_id"],
                               added_at=row["added_at"],
                               added_by=row["added_by"])

    @staticmethod
    def _assessment(row):
        return Assessment(
            assessment_id=row["assessment_id"], name=row["name"],
            focus=row["focus"],
            required_interactions=row["required_interactions"],
            status=row["status"], max_attempts=row["max_attempts"],
            retry_policy=row["retry_policy"],
            window_label=row["window_label"], note=row["note"],
            created_at=row["created_at"], created_by=row["created_by"],
            definition_version=row["definition_version"])

    @staticmethod
    def _assignment(row):
        return Assignment(
            assignment_id=row["assignment_id"],
            assessment_id=row["assessment_id"],
            target_type=row["target_type"], student_id=row["student_id"],
            group_id=row["group_id"], created_at=row["created_at"],
            created_by=row["created_by"], request_id=row["request_id"],
            confirmed_duplicate=bool(row["confirmed_duplicate"]),
            acknowledged_sources=_loads(row["acknowledged_sources_json"]) or [],
            status=row["status"])

    @staticmethod
    def _attempt(row):
        return Attempt(
            attempt_id=row["attempt_id"], assessment_id=row["assessment_id"],
            student_id=row["student_id"],
            attempt_number=row["attempt_number"], status=row["status"],
            session_id=row["session_id"], assignment_id=row["assignment_id"],
            assignment_source=row["assignment_source"],
            assignment_group_id=row["assignment_group_id"],
            required_interactions=row["required_interactions"],
            assessment_definition_version=row["assessment_definition_version"],
            started_at=row["started_at"], ended_at=row["ended_at"],
            result_state=_loads(row["result_json"]),
            scoring_version=row["scoring_version"],
            rubric_version=row["rubric_version"],
            evidence_model_version=row["evidence_model_version"],
            overall=row["overall"],
            completed_interactions=row["completed_interactions"],
            termination_reason=row["termination_reason"])

    @staticmethod
    def _enrollment_code(row):
        return EnrollmentCode(
            code_id=row["code_id"], code=row["code"],
            student_id=row["student_id"], status=row["status"],
            created_at=row["created_at"], created_by=row["created_by"],
            claimed_at=row["claimed_at"],
            claimed_learner_ref=row["claimed_learner_ref"])

    @staticmethod
    def _ownership(row):
        return SessionOwnership(
            session_id=row["session_id"], student_id=row["student_id"],
            learner_ref=row["learner_ref"], focus=row["focus"],
            mode=row["mode"], attempt_id=row["attempt_id"],
            started_at=row["started_at"], last_seen_at=row["last_seen_at"])
