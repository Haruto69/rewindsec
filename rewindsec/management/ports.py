"""The storage-independent contract for administrative records.

The same *port* pattern :mod:`rewindsec.persistence.ports` already
establishes for the simulation aggregate, applied to the Batch 5 records: an
interface expressed only in terms of :mod:`rewindsec.management.records`
objects and the exceptions below, importing nothing from SQLAlchemy or Flask.
:mod:`rewindsec.persistence.management_adapter` is the one adapter this batch
ships; a test can substitute an in-memory one without the service noticing.

Uniqueness contract
-------------------
Four uniqueness rules are the adapter's responsibility, because only storage
can enforce them against a concurrent writer:

* a ``learner_ref`` belongs to at most one :class:`~rewindsec.management
  .records.Student`;
* a ``(group_id, student_id)`` pair has at most one *current*
  :class:`~rewindsec.management.records.GroupMembership`;
* an :class:`~rewindsec.management.records.Assignment` ``request_id``, when
  present, is claimed at most once -- which is what stops a retried network
  submission from manufacturing a second assignment;
* an :class:`~rewindsec.management.records.EnrollmentCode` ``code`` is unique,
  and the transition from unclaimed to claimed happens at most once -- which
  is what makes a replayed enrolment a refusal rather than a second browser
  quietly taking over a student.

A violation of any of them is raised as :class:`AlreadyExistsError`, never
resolved by silently picking a winner.
"""

from abc import ABC, abstractmethod

__all__ = [
    "ManagementRepository", "ManagementError", "AlreadyExistsError",
    "NotFoundError", "DuplicateRequestError",
]


class ManagementError(Exception):
    """Base class for every failure raised by a :class:`ManagementRepository`."""


class AlreadyExistsError(ManagementError):
    """A create violated one of the uniqueness rules above."""


class NotFoundError(ManagementError):
    """No record exists with the requested id."""


class DuplicateRequestError(AlreadyExistsError):
    """An assignment ``request_id`` had already been claimed.

    Distinct from the general case so the service can answer a retried
    submission with the row it already created instead of an error.
    """

    def __init__(self, message, assignment_id=None):
        super(DuplicateRequestError, self).__init__(message)
        self.assignment_id = assignment_id


class ManagementRepository(ABC):
    """Persistence for students, groups, memberships, assessments,
    assignments, attempts and session ownership.

    Every method takes and returns
    :mod:`rewindsec.management.records` objects. Listing methods return
    tuples in a deterministic order (the adapter sorts; a caller must never
    depend on insertion order or on a database's natural order).
    """

    # -- students ---------------------------------------------------------

    @abstractmethod
    def create_student(self, student):
        """Persist a new student. Raises :class:`AlreadyExistsError` on a
        duplicate ``student_id`` or a ``learner_ref`` already bound."""

    @abstractmethod
    def update_student(self, student):
        """Replace an existing student row. Raises :class:`NotFoundError`."""

    @abstractmethod
    def get_student(self, student_id):
        """The student, or ``None``."""

    @abstractmethod
    def student_for_learner_ref(self, learner_ref):
        """The student bound to this server-minted learner reference, or ``None``."""

    @abstractmethod
    def list_students(self):
        """Every student, ordered by display name then id."""

    # -- groups and membership --------------------------------------------

    @abstractmethod
    def create_group(self, group):
        """Persist a new group."""

    @abstractmethod
    def get_group(self, group_id):
        """The group, or ``None``."""

    @abstractmethod
    def list_groups(self):
        """Every group, ordered by name then id."""

    @abstractmethod
    def add_membership(self, membership):
        """Add one student to one group.

        Raises :class:`AlreadyExistsError` if that student is already a
        current member, so "add twice" is a refusal rather than two rows.
        """

    @abstractmethod
    def remove_membership(self, group_id, student_id):
        """Drop current membership. Returns whether a row was removed.

        Removal affects membership only. No assignment and no attempt is
        touched: their provenance was recorded when they were made and is not
        re-derived from this table.
        """

    @abstractmethod
    def list_memberships(self, group_id=None, student_id=None):
        """Current memberships, optionally narrowed, deterministically ordered."""

    # -- assessments -------------------------------------------------------

    @abstractmethod
    def create_assessment(self, assessment):
        """Persist a new assessment definition."""

    @abstractmethod
    def update_assessment(self, assessment):
        """Replace an existing assessment definition."""

    @abstractmethod
    def get_assessment(self, assessment_id):
        """The assessment, or ``None``."""

    @abstractmethod
    def list_assessments(self):
        """Every assessment, ordered by name then id."""

    # -- assignments -------------------------------------------------------

    @abstractmethod
    def create_assignment(self, assignment):
        """Persist a new assignment.

        Raises :class:`DuplicateRequestError`, carrying the existing
        ``assignment_id``, when the assignment's ``request_id`` has already
        been claimed.
        """

    @abstractmethod
    def get_assignment(self, assignment_id):
        """The assignment, or ``None``."""

    @abstractmethod
    def assignment_for_request(self, request_id):
        """The assignment already created for this idempotency token, or ``None``."""

    @abstractmethod
    def list_assignments(self, assessment_id=None):
        """Active assignments, optionally for one assessment, ordered by
        creation timestamp then id."""

    # -- attempts ----------------------------------------------------------

    @abstractmethod
    def create_attempt(self, attempt):
        """Persist a new attempt."""

    @abstractmethod
    def update_attempt(self, attempt):
        """Replace an existing attempt row."""

    @abstractmethod
    def get_attempt(self, attempt_id):
        """The attempt, or ``None``."""

    @abstractmethod
    def attempt_for_session(self, session_id):
        """The attempt this session belongs to, or ``None``."""

    @abstractmethod
    def list_attempts(self, student_id=None, assessment_id=None):
        """Attempts, optionally narrowed, ordered by student, assessment and
        attempt number."""

    # -- session ownership -------------------------------------------------

    @abstractmethod
    def record_session_ownership(self, ownership):
        """Insert or refresh the ownership row for one session.

        Idempotent by ``session_id``. The adapter must refuse to move a
        session to a different student: ownership is established once, at
        creation, from the server-minted learner reference.
        """

    @abstractmethod
    def get_session_ownership(self, session_id):
        """The ownership row, or ``None`` for a legacy/unowned session."""

    @abstractmethod
    def list_session_ownership(self, student_id=None):
        """Ownership rows, optionally for one student, newest first."""

    # -- enrolment ---------------------------------------------------------

    @abstractmethod
    def create_enrollment_code(self, code):
        """Persist a new enrolment code. Raises :class:`AlreadyExistsError`
        on a duplicate code or code id."""

    @abstractmethod
    def get_enrollment_code(self, code):
        """The enrolment code record for this secret, or ``None``."""

    @abstractmethod
    def list_enrollment_codes(self, student_id=None):
        """Enrolment codes, optionally for one student, deterministically
        ordered."""

    @abstractmethod
    def claim_enrollment_code(self, code, learner_ref, claimed_at):
        """Atomically move one *unclaimed* code to claimed by this learner.

        Returns the updated record on success and ``None`` when the code was
        not there to claim -- because it does not exist, is revoked, or had
        already been claimed by the time this call reached storage. The
        service must not implement this as a read followed by a write: two
        browsers racing on the same code is exactly the case that has to have
        one winner, and only storage can decide it.
        """

    @abstractmethod
    def bind_student_learner_ref(self, student_id, learner_ref,
                                 expected_learner_ref=None):
        """Atomically point one student at one server-minted learner reference.

        A compare-and-set on ``expected_learner_ref``: the update applies only
        while the student still carries that value, so a student cannot be
        re-pointed by a second, later caller who read a stale row. Returns the
        updated :class:`~rewindsec.management.records.Student` on success and
        ``None`` when the row had moved on.
        """
