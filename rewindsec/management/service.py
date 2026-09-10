"""The management application service: the only thing that changes a record.

The administrative counterpart to
:mod:`rewindsec.workstation.service`, and it follows the same rules. Every
operation is validated here, on the server. Nothing decides anything from a
display name, a URL parameter or a client-held identifier: a learner is
resolved from the server-minted ``learner_ref`` in their signed cookie, and a
trainer operation is reached only through an authorized route.

What this service refuses to do
-------------------------------
* It never recomputes a score. A completed attempt's result *is* the
  session's own immutable, finalized
  :class:`~rewindsec.scoring.result.ScoringResult`, copied verbatim under the
  versions it was produced with.
* It never counts progress in events, messages, elapsed time or ticks. See
  :mod:`rewindsec.management.progress`.
* It never merges two assignments. A duplicate is created only on an
  explicit, separate, server-checked instruction, and both provenances
  survive.
* It never moves a session to a different owner, and never infers an owner
  from anything a client sent.
* It never draws from a simulation RNG stream or reads a real clock into a
  simulation decision. Administrative timestamps are ordinary application
  time and are used for display and audit only.
* It never lets a learner name the student, learner reference, attempt or
  session they would like to be. Enrolment takes one single-use code and
  nothing else; every identity in the result is resolved on the server.
* It never records an assessment attempt as ``completed`` unless the
  assessment definition's required scored-interaction rule was satisfied.
  See :meth:`ManagementService.sync_attempt`.
"""

import datetime

from rewindsec.domain.identifiers import validate_identity
from rewindsec.management import assessment_policy
from rewindsec.management import assignments as assignment_rules
from rewindsec.management import progress as progress_rules
from rewindsec.management import session_link
from rewindsec.management.ids import SecretsIdSource, derive_student_id
from rewindsec.management.ports import (AlreadyExistsError,
                                        DuplicateRequestError, NotFoundError)
from rewindsec.management.records import (Assessment, Assignment, Attempt,
                                          EnrollmentCode, GroupMembership,
                                          SessionOwnership, Student,
                                          StudentGroup)
from rewindsec.persistence.ports import SessionNotFoundError
from rewindsec.scoring import state as scoring_state
from rewindsec.workstation.errors import StaleRevisionConflict

__all__ = ["ManagementService", "ManagementRefused", "DuplicateAssignment",
           "TRAINER_ACTOR", "SYSTEM_ACTOR", "utc_now"]

#: The single trainer role this deployment has (see ``security.py``: one
#: instructor flag, no user table). Recorded as the actor on every trainer
#: write so provenance says *a trainer did this*, which is all the auth model
#: can honestly support. It is deliberately not a person's name.
TRAINER_ACTOR = "Instructor"
SYSTEM_ACTOR = "RewindSec system policy"


def utc_now():
    """An administrative timestamp. Never reaches a simulation decision."""
    return datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0).isoformat()


class ManagementRefused(Exception):
    """An operation was refused for a stated, learner- or trainer-safe reason."""

    def __init__(self, message, code="refused", detail=None):
        super(ManagementRefused, self).__init__(message)
        self.message = message
        self.code = code
        self.detail = detail or {}


class DuplicateAssignment(ManagementRefused):
    """The requested assignment would duplicate one or more existing routes.

    Carries the full provenance of every existing route for every affected
    student in ``detail["duplicates"]`` -- never a bare ``duplicate: true``,
    because a trainer cannot decide anything from a boolean. Creating the
    assignment anyway requires re-submitting with an explicit confirmation.
    """

    def __init__(self, duplicates):
        super(DuplicateAssignment, self).__init__(
            "One or more of these learners already receives this assessment.",
            code="duplicate_assignment", detail={"duplicates": duplicates})


class ManagementService(object):
    """Server-authoritative operations on the RewindSec 2.0 administrative records.

    ``workstation`` is the :class:`~rewindsec.workstation.service
    .WorkstationService`; it is used only to *start*, *end* and *abandon*
    sessions, so that every session state transition in the system still goes
    through exactly one piece of code with exactly one set of rules.
    ``sessions`` is the
    :class:`~rewindsec.persistence.ports.SessionRepository` and ``directory``
    the :class:`~rewindsec.persistence.ports.SessionDirectory` -- reads only,
    for history and analytics.
    """

    def __init__(self, repository, sessions, directory, workstation,
                 id_source=None, clock=None):
        self._repository = repository
        self._sessions = sessions
        self._directory = directory
        self._workstation = workstation
        self._ids = id_source or SecretsIdSource()
        self._clock = clock or utc_now

    @property
    def repository(self):
        return self._repository

    def _now(self):
        return self._clock()

    # -- students ----------------------------------------------------------

    def list_students(self):
        """The **active** trainer roster: trainer-created and not deleted.

        Historical ``self_provisioned`` records remain in storage and remain
        addressable by id for audit, but they are technical identities rather
        than members of the trainer's roster. A student the trainer has
        deleted is excluded for the same kind of reason: the row survives so
        that historical sessions, attempts and results stay resolvable, but it
        is no longer a member of the roster and no longer counts as one.

        This is the one place the active roster is defined. Every list,
        picker, count and aggregate reads it, so there is no second, weaker
        notion of "active student" anywhere.
        """
        return tuple(student for student in self._repository.list_students()
                     if student.origin == "trainer" and not student.is_deleted)

    def known_students(self):
        """Every trainer-created student, deleted ones included.

        The *historical* read, and deliberately a different method from
        :meth:`list_students` rather than a flag on it: a caller has to say
        which of the two questions it is asking. It exists so a completed
        session, an assessment attempt, a finalized result or an assignment
        provenance record can still render the identity it belongs to after
        that student has been removed from the roster. It is never a roster
        list, and nothing mutable is reached through it.
        """
        return tuple(student for student in self._repository.list_students()
                     if student.origin == "trainer")

    def historical_student(self, student_id):
        """A trainer-created student for a read-only historical view, or ``None``.

        Deliberately *not* :meth:`require_roster_student`: this is how a
        historical page resolves a deleted student's display identity without
        weakening the guard every mutation route depends on.
        """
        student = self._repository.get_student(student_id)
        if student is None or student.origin != "trainer":
            return None
        return student

    def get_student(self, student_id):
        return self._repository.get_student(student_id)

    def require_student(self, student_id):
        student = self._repository.get_student(student_id)
        if student is None:
            raise NotFoundError("no student with id %r" % student_id)
        return student

    def require_roster_student(self, student_id):
        """An **active** trainer-created Student, or the same safe absence as no row.

        The single roster guard every trainer mutation route goes through. A
        deleted student fails it exactly the way a legacy ``self_provisioned``
        row and a made-up id already do -- one refusal, one shape, no oracle
        telling a caller which of the three it hit. A historical read that
        genuinely needs a deleted student's identity uses
        :meth:`historical_student` instead; this guard is never relaxed to
        serve one.
        """
        student = self._repository.get_student(student_id)
        if student is None or student.origin != "trainer" \
                or student.is_deleted:
            raise NotFoundError("no roster student with id %r" % student_id)
        return student

    def create_student(self, display_name, reference=None, cohort=None,
                       status="active"):
        """Create a roster entry. **Unbound** until a learner claims it.

        ``learner_ref`` is deliberately left ``None``. It used to be minted
        here, which produced a reference no browser would ever present and
        therefore a student no real learner could ever become -- the roster
        looked bound and was not. ``None`` now means exactly one thing, and it
        is checkable: *nobody has claimed this student yet*. The reference is
        written once, by :meth:`claim_enrollment`, from the server-minted
        token the claiming browser already carries.

        A reference is still never accepted from a request, for the same
        reason a session id is not: a reference chosen by a client is an
        invitation to claim somebody else's history.
        """
        student = Student(
            student_id=self._ids.new_id("stu"),
            display_name=display_name, reference=reference, cohort=cohort,
            status=status, learner_ref=None,
            origin="trainer", created_at=self._now())
        return self._repository.create_student(student)

    def student_for_learner_ref(self, learner_ref):
        return self._repository.student_for_learner_ref(learner_ref)

    ENROLLMENT_REQUIRED = (
        "Enroll this device with the code from your trainer before starting "
        "training.")

    def require_enrolled_student(self, learner_ref):
        """Resolve an active trainer-created roster student without writes."""
        student = self._repository.student_for_learner_ref(learner_ref)
        if student is None or student.origin != "trainer" \
                or student.status != "active" or student.is_deleted:
            raise ManagementRefused(self.ENROLLMENT_REQUIRED,
                                    code="enrollment_required")
        return student

    def ensure_student_for_learner_ref(self, learner_ref, display_name=None):
        """The student bound to this server-minted reference, provisioning one
        if the reference has never been seen.

        Auto-provisioning is what makes an ordinary *self-directed* run
        belong to somebody. Enrolment (:meth:`claim_enrollment`) is how a
        browser becomes a **roster** student; this is the other case -- a
        learner who walks up and starts a Practice or Simulation session
        without one -- and without it that run would produce history with no
        owner. The identity is minimal and synthetic -- a derived id, a
        generated display label, no personal data of any kind -- and the id is
        *derived* from the reference (:func:`rewindsec.management.ids
        .derive_student_id`), so re-provisioning the same reference can never
        split one person's history across two records.
        """
        existing = self._repository.student_for_learner_ref(learner_ref)
        if existing is not None:
            return existing
        student_id = derive_student_id(learner_ref)
        already = self._repository.get_student(student_id)
        if already is not None:
            return already
        label = display_name or ("Learner %s" % student_id[-6:])
        student = Student(
            student_id=student_id, display_name=label,
            reference=None, cohort=None, status="active",
            learner_ref=learner_ref, origin="self_provisioned",
            created_at=self._now())
        try:
            return self._repository.create_student(student)
        except AlreadyExistsError:
            # Another request provisioned the same reference first. Its row is
            # the right one; ours is discarded rather than retried.
            found = self._repository.student_for_learner_ref(learner_ref)
            if found is None:
                raise
            return found

    # -- enrolment: how a browser becomes a roster student ------------------
    #
    # The gap this closes: a trainer could create a Student, put them in a
    # group and assign them an assessment, and no actual browser had any way
    # to *become* that student. The smoke tests seeded the learner cookie by
    # hand, which meant trainer-created students, memberships and assignments
    # were not genuinely end-to-end usable.
    #
    # The mechanism is deliberately the smallest one that works: a bounded,
    # single-use, purpose-specific code, spent once, in exchange for a
    # binding. It is not an account system, it grants no ongoing access, it
    # stores no new personal data, and it is not the learner reference -- see
    # :class:`~rewindsec.management.records.EnrollmentCode`.

    def create_enrollment_code(self, student_id, created_by=TRAINER_ACTOR):
        """Mint one single-use claim on one roster student. Trainer-only.

        Minting a second code for a student who is already bound is refused:
        the code exists to establish a binding, and once one exists there is
        nothing left for a code to do except take the student away from the
        browser that holds them.
        """
        student = self.require_roster_student(student_id)
        if student.status != "active":
            raise ManagementRefused(
                "That student is not active.", code="student_inactive")
        if student.learner_ref is not None:
            raise ManagementRefused(
                "That student is already enrolled on a device.",
                code="already_enrolled",
                detail={"student_id": student.student_id})
        code = EnrollmentCode(
            code_id=self._ids.new_id("enr"),
            code=self._ids.new_code("enr"),
            student_id=student.student_id, status="open",
            created_at=self._now(), created_by=created_by)
        return self._repository.create_enrollment_code(code)

    def enrollment_codes_for_student(self, student_id):
        return self._repository.list_enrollment_codes(student_id=student_id)

    #: One refusal message for every unusable code, on purpose.
    #:
    #: "No such code", "already claimed by somebody else" and "revoked" are
    #: answered identically. Distinguishing them would turn the endpoint into
    #: an oracle a stranger could use to learn which codes exist and which
    #: roster students have already enrolled.
    ENROLLMENT_UNUSABLE = "That enrolment code cannot be used."

    def claim_enrollment(self, learner_ref, code):
        """Bind this browser's learner reference to the coded roster student.

        ``learner_ref`` is the server-minted token from the signed cookie and
        is supplied by the adapter, never by the request body. ``code`` is the
        *only* thing the learner chooses, and it names no student id, no
        learner reference, no attempt and no session -- so there is no
        parameter here through which a learner could ask to become somebody
        else. Presenting material for a student they were not given resolves
        to no code, and is refused.

        Replay is refused by storage, not by a check here: the claim is one
        conditional UPDATE that matches only an unclaimed row
        (:meth:`~rewindsec.management.ports.ManagementRepository
        .claim_enrollment_code`), so of two browsers presenting the same code
        exactly one can win. The winner may re-present it -- a retried form, a
        double submit, a reload -- and gets the same binding back, because the
        row already names them.
        """
        learner_ref = validate_identity(learner_ref, "learner_ref")
        if not isinstance(code, str) or not code:
            raise ManagementRefused(self.ENROLLMENT_UNUSABLE,
                                    code="enrollment_unusable")
        record = self._repository.get_enrollment_code(code)
        if record is None:
            raise ManagementRefused(self.ENROLLMENT_UNUSABLE,
                                    code="enrollment_unusable")

        current = self._repository.student_for_learner_ref(learner_ref)

        # Already spent by this same browser: idempotent, and the only case in
        # which a claimed code resolves to anything at all.
        if record.claimed_learner_ref == learner_ref:
            if current is not None and current.student_id == record.student_id:
                return current, False
            raise ManagementRefused(self.ENROLLMENT_UNUSABLE,
                                    code="enrollment_unusable")

        if not record.is_open:
            raise ManagementRefused(self.ENROLLMENT_UNUSABLE,
                                    code="enrollment_unusable")

        target = self._repository.get_student(record.student_id)
        if target is None or target.origin != "trainer" \
                or target.status != "active" or target.is_deleted \
                or target.learner_ref is not None:
            raise ManagementRefused(self.ENROLLMENT_UNUSABLE,
                                    code="enrollment_unusable")

        if current is not None:
            if current.student_id == target.student_id:
                return current, False
            if current.origin != "self_provisioned":
                # This browser is already a roster student. Swapping it for
                # another would detach a person from their own record on
                # nothing more than a pasted string.
                raise ManagementRefused(
                    "This browser is already enrolled as a different student.",
                    code="already_enrolled")

        claimed = self._repository.claim_enrollment_code(
            code, learner_ref, self._now())
        if claimed is None:
            # Lost the race, or the row moved between the read and the write.
            raise ManagementRefused(self.ENROLLMENT_UNUSABLE,
                                    code="enrollment_unusable")

        if current is not None:
            # Release the anonymous, auto-provisioned record this browser was
            # using so the unique reference is free. Its sessions stay on it:
            # ownership is established once and is never moved, so earlier
            # anonymous history is left where it happened rather than being
            # silently reattributed to a named person.
            self._repository.bind_student_learner_ref(
                current.student_id, None, expected_learner_ref=learner_ref)

        bound = self._repository.bind_student_learner_ref(
            target.student_id, learner_ref,
            expected_learner_ref=target.learner_ref)
        if bound is None:
            raise ManagementRefused(self.ENROLLMENT_UNUSABLE,
                                    code="enrollment_unusable")
        return bound, True

    def _active_work(self, student):
        """``(ownerships, attempts, has_active_work)`` for one student.

        The **one** interpretation of "this student is working right now",
        extracted so enrollment reset and roster deletion cannot drift into
        two different, differently-weak answers to the same question. Both
        callers also need the two lists themselves, because the counts they
        were computed from are what the storage-level guard is conditioned on.

        Active means either of:

        * an ordinary owned session -- Practice, Simulation or Assessment --
          that is still active; or
        * an Attempt whose row still says ``active``, whatever state its
          bound session is in.

        An *unreadable* ordinary session is deliberately not called active: we
        cannot read it, so we must not assert it is running. An Assessment
        whose session is unreadable or missing is still caught, because its
        Attempt row is read directly and needs no session to be readable.
        """
        ownerships = self._repository.list_session_ownership(
            student_id=student.student_id)
        attempts = self._repository.list_attempts(student_id=student.student_id)
        active = False
        for ownership in ownerships:
            owned = self.load_session(ownership.session_id)
            if owned is not None and owned.is_active:
                active = True
                break
        if not active:
            active = any(attempt.is_active for attempt in attempts)
        return ownerships, attempts, active

    #: Refused because the student is mid-session. One code, one message.
    STUDENT_DELETE_ACTIVE_WORK = "student_delete_active_work"
    STUDENT_DELETE_ACTIVE_MESSAGE = (
        "End the student's active training session before deleting the "
        "student.")

    def delete_student(self, student_id):
        """Remove one student from the trainer roster, safely.

        The trainer asks for one thing -- "delete this student" -- and the
        server decides what that can mean. There is no force flag, no purge
        endpoint and no bypass: a caller cannot ask for a destructive
        outcome, only for the intent.

        **Roster deletion never destroys the Student row.** That is the
        whole design, not an optimisation. Every path that can create work
        for a learner -- ``register_session``, ``_start_bound_attempt`` --
        writes an ownership or Attempt row carrying a ``student_id``, and
        those writes cannot be serialized against a row deletion without a
        lock this storage layer does not have. So a physical delete could
        always be raced by a late insert and leave a row pointing at an
        identity that no longer exists. Keeping the row removes that failure
        class outright: a late insert lands against a Student that is still
        there, still resolvable, merely inactive, and the existing
        compensation in :meth:`register_session` then brings the raced
        session and Attempt to a safe terminal state.

        Two outcomes, in the order they are decided:

        1. **Refused** (:data:`STUDENT_DELETE_ACTIVE_WORK`) while the student
           has active work. Every check happens before any write, so a refusal
           leaves the Student, its binding, its codes, its memberships, its
           assignments, its Attempts and its sessions byte-identical.
        2. **Removed from the roster** otherwise, for every student alike --
           the never-used test record and the one with a term of history. The
           row stays exactly where it is, marked ``deleted_at``; the roster
           stops showing it and every mutation route stops accepting it,
           while ownership, attempts, results, scores, evidence and
           provenance are not read, not rewritten and not deleted.

        Returns a safe result document carrying no ``learner_ref``, no
        enrolment code and no internal identifier the console did not already
        hold.
        """
        student = self.require_roster_student(student_id)
        ownerships, attempts, active = self._active_work(student)
        if active:
            raise ManagementRefused(self.STUDENT_DELETE_ACTIVE_MESSAGE,
                                    code=self.STUDENT_DELETE_ACTIVE_WORK)

        # The counts are what the storage-level guard is conditioned on, so
        # a session or Attempt appearing between the check above and the
        # write below turns the write into a no-op and this into a refusal.
        deleted = self._repository.soft_delete_student(
            student.student_id, self._now(), student.learner_ref,
            expected_ownership_count=len(ownerships),
            expected_attempt_count=len(attempts))
        if deleted is None:
            raise ManagementRefused(
                "Active work or enrollment changed before the student could "
                "be deleted.", code="student_delete_changed")
        return {"kind": "removed_from_roster",
                "student_id": deleted.student_id,
                "student_name": deleted.display_name}

    def reset_enrollment(self, student_id):
        """Unbind a roster student so a new device can claim a new code.

        Session ownership and attempts are intentionally untouched. Open,
        unused codes are revoked; claimed code rows remain as audit history
        and cannot re-establish the old binding after the reset.
        """
        student = self.require_roster_student(student_id)
        ownerships, attempts, active = self._active_work(student)
        if active:
            raise ManagementRefused(
                "End the student's active training session before resetting "
                "enrollment.", code="enrollment_reset_active_work")
        unbound = self._repository.reset_student_enrollment(
            student.student_id, student.learner_ref,
            expected_ownership_count=len(ownerships),
            expected_attempt_count=len(attempts))
        if unbound is None:
            raise ManagementRefused(
                "Active work or enrollment changed before it could be reset.",
                code="enrollment_changed")
        return unbound, student.learner_ref is not None

    # -- groups and membership --------------------------------------------

    def list_groups(self):
        return self._repository.list_groups()

    def get_group(self, group_id):
        return self._repository.get_group(group_id)

    def require_group(self, group_id):
        group = self._repository.get_group(group_id)
        if group is None:
            raise NotFoundError("no group with id %r" % group_id)
        return group

    def create_group(self, name, description=None, created_by=TRAINER_ACTOR):
        group = StudentGroup(group_id=self._ids.new_id("grp"), name=name,
                             description=description, created_at=self._now(),
                             created_by=created_by)
        return self._repository.create_group(group)

    def add_member(self, group_id, student_id, added_by=TRAINER_ACTOR):
        self.require_group(group_id)
        self.require_roster_student(student_id)
        membership = GroupMembership(
            membership_id=self._ids.new_id("mem"), group_id=group_id,
            student_id=student_id, added_at=self._now(), added_by=added_by)
        try:
            return self._repository.add_membership(membership)
        except AlreadyExistsError:
            raise ManagementRefused(
                "That student is already a member of this group.",
                code="already_member")

    def remove_member(self, group_id, student_id):
        """Drop current membership.

        Deliberately does not touch a single assignment or attempt. A group
        assignment stops *reaching* this student -- effective assignments are
        resolved from current membership -- but every attempt already made
        keeps the provenance it was created with, because that provenance was
        copied onto the attempt at the time and is never re-derived.
        """
        self.require_group(group_id)
        self.require_roster_student(student_id)
        return self._repository.remove_membership(group_id, student_id)

    def list_memberships(self, group_id=None, student_id=None):
        return self._repository.list_memberships(group_id=group_id,
                                                 student_id=student_id)

    def groups_for_student(self, student_id):
        self.require_roster_student(student_id)
        groups_by_id = {g.group_id: g for g in self._repository.list_groups()}
        return tuple(
            groups_by_id[m.group_id]
            for m in self._repository.list_memberships(student_id=student_id)
            if m.group_id in groups_by_id)

    # -- assessments -------------------------------------------------------

    def list_assessments(self):
        return self._repository.list_assessments()

    def get_assessment(self, assessment_id):
        return self._repository.get_assessment(assessment_id)

    def require_assessment(self, assessment_id):
        assessment = self._repository.get_assessment(assessment_id)
        if assessment is None:
            raise NotFoundError("no assessment with id %r" % assessment_id)
        return assessment

    def create_assessment(self, name, focus, required_interactions,
                          status="open", max_attempts=1, window_label=None,
                          note=None, created_by=TRAINER_ACTOR):
        """Create an assessment definition.

        The parameter list is the whole product surface, on purpose. There is
        no organisation profile here, no threat-family probability, no hazard
        value, no event ordering, no seed, no learner difficulty and no
        scoring weight -- an assessment says what must be demonstrated and how
        many times, and the system decides how to present it.
        """
        assessment = Assessment(
            assessment_id=self._ids.new_id("as"), name=name, focus=focus,
            required_interactions=required_interactions, status=status,
            max_attempts=max_attempts, window_label=window_label, note=note,
            created_at=self._now(), created_by=created_by)
        return self._repository.create_assessment(assessment)

    def ensure_self_directed_assessment(self, focus):
        """Return the persisted, system-owned default definition for *focus*.

        The stable definition id and version come from
        :mod:`rewindsec.management.assessment_policy`.  This is not a trainer
        assignment and is never exposed as an editable trainer-created
        assessment.  A concurrent first start is idempotent: one create wins
        and every other caller reads that same row.
        """
        assessment_id = assessment_policy.self_directed_assessment_id(focus)
        existing = self._repository.get_assessment(assessment_id)
        if existing is not None:
            if not existing.is_self_directed_policy:
                raise ManagementRefused(
                    "The self-directed assessment policy is unavailable.",
                    code="self_directed_policy_conflict")
            return existing
        capacity = assessment_policy.required_interaction_capacity(focus)
        required = min(assessment_policy.SELF_DIRECTED_REQUIRED_INTERACTIONS,
                       capacity)
        definition = Assessment(
            assessment_id=assessment_id,
            name="Self-directed %s assessment" % focus.capitalize(),
            focus=focus, required_interactions=required, status="open",
            max_attempts=20, window_label=None,
            note="System-owned self-directed Assessment policy.",
            created_at=self._now(), created_by=SYSTEM_ACTOR,
            definition_version=
                assessment_policy.SELF_DIRECTED_DEFINITION_VERSION)
        try:
            return self._repository.create_assessment(definition)
        except AlreadyExistsError:
            existing = self._repository.get_assessment(assessment_id)
            if existing is None or not existing.is_self_directed_policy:
                raise
            return existing

    def set_assessment_status(self, assessment_id, status):
        assessment = self.require_assessment(assessment_id)
        if assessment.is_self_directed_policy:
            raise ManagementRefused(
                "System-owned self-directed policies are not trainer records.",
                code="system_assessment_read_only")
        return self._repository.update_assessment(
            assessment.replace(status=status))

    # -- assignments -------------------------------------------------------

    def _assignment_context(self, assessment_id=None):
        return (self._repository.list_assignments(assessment_id=assessment_id),
                self._repository.list_memberships(),
                {g.group_id: g for g in self._repository.list_groups()},
                {s.student_id: s for s in self._repository.list_students()})

    def assignment_sources(self, assessment_id, student_id):
        """Every route by which a student already receives an assessment."""
        self.require_assessment(assessment_id)
        self.require_roster_student(student_id)
        assignments, memberships, groups_by_id, _students = \
            self._assignment_context(assessment_id)
        return assignment_rules.assignment_sources(
            assessment_id, student_id, assignments, memberships, groups_by_id)

    def duplicate_preview(self, assessment_id, target_type, target_id):
        """What a duplicate warning would say, without creating anything."""
        self.require_assessment(assessment_id)
        self._require_target(target_type, target_id)
        assignments, memberships, groups_by_id, students_by_id = \
            self._assignment_context(assessment_id)
        return assignment_rules.duplicate_report(
            assessment_id, target_type, target_id, assignments, memberships,
            groups_by_id, students_by_id)

    def _require_target(self, target_type, target_id):
        if target_type == "student":
            return self.require_roster_student(target_id)
        if target_type == "group":
            return self.require_group(target_id)
        raise ManagementRefused("A target must be a student or a group.",
                                code="invalid_target")

    def assign(self, assessment_id, target_type, target_id,
               confirm_duplicate=False, request_id=None,
               created_by=TRAINER_ACTOR):
        """Create one assignment, refusing an unconfirmed duplicate.

        The confirmation is **server-side input**. A dialog having been shown
        in a browser proves nothing to this method; the caller has to say, in
        the request, that a duplicate is intended. Without that the operation
        is refused with :class:`DuplicateAssignment`, carrying every existing
        route for every affected student, and nothing is written.

        ``request_id`` is an idempotency token. Re-submitting the same
        operation -- a retried fetch, a double-clicked button, a response lost
        on the way back -- resolves to the assignment already created rather
        than making a second one. Making a second one on purpose is a
        different operation with a different token and an explicit
        confirmation.
        """
        assessment = self.require_assessment(assessment_id)
        if assessment.is_self_directed_policy:
            raise ManagementRefused(
                "A self-directed policy cannot be assigned by a trainer.",
                code="system_assessment_read_only")
        self._require_target(target_type, target_id)

        if request_id:
            existing = self._repository.assignment_for_request(request_id)
            if existing is not None:
                return existing, True

        duplicates = self.duplicate_preview(assessment_id, target_type,
                                            target_id)
        if duplicates and not confirm_duplicate:
            raise DuplicateAssignment(duplicates)

        assignment = Assignment(
            assignment_id=self._ids.new_id("asg"),
            assessment_id=assessment_id, target_type=target_type,
            student_id=target_id if target_type == "student" else None,
            group_id=target_id if target_type == "group" else None,
            created_at=self._now(), created_by=created_by,
            request_id=request_id,
            confirmed_duplicate=bool(duplicates and confirm_duplicate),
            acknowledged_sources=[
                {"student_id": entry["student"]["id"],
                 "sources": [source["label"] for source in entry["sources"]]}
                for entry in duplicates],
            status="active")
        try:
            return self._repository.create_assignment(assignment), False
        except DuplicateRequestError as exc:
            already = self._repository.get_assignment(exc.assignment_id)
            if already is None:
                raise
            return already, True

    def effective_assignments(self, student_id):
        assignments, memberships, groups_by_id, _students = \
            self._assignment_context()
        assessments_by_id = {a.assessment_id: a
                             for a in self._repository.list_assessments()}
        return assignment_rules.effective_assignments(
            student_id, assignments, memberships, groups_by_id,
            assessments_by_id=assessments_by_id)

    # -- attempts ----------------------------------------------------------

    def list_attempts(self, student_id=None, assessment_id=None):
        return self._repository.list_attempts(student_id=student_id,
                                              assessment_id=assessment_id)

    def get_attempt(self, attempt_id):
        return self._repository.get_attempt(attempt_id)

    def attempt_for_session(self, session_id):
        return self._repository.attempt_for_session(session_id)

    def start_attempt(self, learner_ref, assessment_id):
        """Start -- or resume -- this learner's attempt at an assessment.

        Resume comes first, deliberately. A learner who closes the browser and
        comes back must land in the attempt they were already in: minting a
        second attempt would consume one of their allowed retries and would
        abandon a half-finished session that is a factual record. So an
        existing *active* attempt is returned as-is, with its original
        attempt number and its original session, however many times this is
        called.

        Only when there is no active attempt does the retry policy apply.
        """
        student = self.require_enrolled_student(learner_ref)
        assessment = self.require_assessment(assessment_id)
        if assessment.is_self_directed_policy:
            raise ManagementRefused(
                "That is a self-directed policy, not a trainer assignment.",
                code="not_assigned")

        existing = [a for a in self._repository.list_attempts(
            student_id=student.student_id, assessment_id=assessment_id)]
        existing = [self.sync_attempt(attempt) for attempt in existing]

        for attempt in existing:
            if attempt.is_active:
                return attempt, False

        routes = assignment_rules.effective_assignments(
            student.student_id,
            self._repository.list_assignments(assessment_id=assessment_id),
            self._repository.list_memberships(),
            {g.group_id: g for g in self._repository.list_groups()},
            assessment_id=assessment_id)
        if not routes:
            raise ManagementRefused(
                "This assessment has not been assigned to you.",
                code="not_assigned")

        if not assessment.accepts_new_attempts:
            raise ManagementRefused(
                "This assessment is not open for attempts.",
                code="assessment_closed",
                detail={"status": assessment.status})

        if len(existing) >= assessment.max_attempts:
            raise ManagementRefused(
                "You have used all %d attempt%s allowed for this assessment."
                % (assessment.max_attempts,
                   "" if assessment.max_attempts == 1 else "s"),
                code="retry_limit_reached",
                detail={"max_attempts": assessment.max_attempts,
                        "attempts_used": len(existing),
                        "retry_policy": assessment.retry_policy})

        # The first route is the one recorded as this attempt's provenance,
        # and the routes are already in a deterministic order (creation time,
        # then id), so the same learner in the same state always records the
        # same one. Every other route stays exactly where it is.
        route = routes[0]
        return self._start_bound_attempt(
            learner_ref, student, assessment, existing,
            assignment_id=route.assignment.assignment_id,
            assignment_source=route.source,
            assignment_group_id=route.assignment.group_id)

    def start_self_directed_attempt(self, learner_ref, focus):
        """Start or resume a real Attempt for learner-chosen Assessment mode.

        No Assignment is looked up or fabricated.  The learner chooses only
        the architectural focus; the server-owned, versioned policy supplies
        the feasible required count and the server creates the Attempt before
        its TrainingSession exactly as it does for trainer-assigned work.
        """
        student = self.require_enrolled_student(learner_ref)
        assessment = self.ensure_self_directed_assessment(focus)
        existing = [self.sync_attempt(a) for a in
                    self._repository.list_attempts(
                        student_id=student.student_id,
                        assessment_id=assessment.assessment_id)]
        for attempt in existing:
            if attempt.is_active:
                return attempt, False
        if len(existing) >= assessment.max_attempts:
            raise ManagementRefused(
                "You have used all self-directed attempts under this policy.",
                code="retry_limit_reached",
                detail={"max_attempts": assessment.max_attempts,
                        "attempts_used": len(existing),
                        "retry_policy": assessment.retry_policy})
        return self._start_bound_attempt(
            learner_ref, student, assessment, existing,
            assignment_id=None, assignment_source="self_directed",
            assignment_group_id=None)

    def _start_bound_attempt(self, learner_ref, student, assessment, existing,
                             assignment_id, assignment_source,
                             assignment_group_id):
        """Persist Attempt, then create and bind its Assessment session."""
        attempt_number = max([a.attempt_number for a in existing] or [0]) + 1
        attempt = Attempt(
            attempt_id=self._ids.new_id("att"),
            assessment_id=assessment.assessment_id,
            student_id=student.student_id, attempt_number=attempt_number,
            status="active", session_id=None,
            assignment_id=assignment_id,
            assignment_source=assignment_source,
            assignment_group_id=assignment_group_id,
            required_interactions=assessment.required_interactions,
            assessment_definition_version=assessment.definition_version,
            started_at=self._now())
        try:
            self._repository.create_attempt(attempt)
        except AlreadyExistsError:
            # Lost a race for this attempt number. Whoever won has the active
            # attempt; use theirs rather than inventing another.
            for other in self._repository.list_attempts(
                    student_id=student.student_id,
                    assessment_id=assessment.assessment_id):
                if other.is_active:
                    return self.sync_attempt(other), False
            raise

        def stamp(session, cause_event_id=None):
            session_link.stamp_attempt(
                session, attempt_id=attempt.attempt_id,
                assessment_id=assessment.assessment_id,
                student_id=student.student_id,
                assignment_id=assignment_id,
                assignment_source=assignment_source,
                assignment_group_id=assignment_group_id,
                required_interactions=assessment.required_interactions,
                attempt_number=attempt_number, cause_event_id=cause_event_id)

        try:
            # ``attempt_bound=True`` is this service asserting, on the
            # server, that the Attempt row above already exists. It is the
            # only caller in the system that may say so, and it says it after
            # the write, never before.
            session_id = self._workstation.start_session(
                learner_ref, assessment.focus, "assessment", on_created=stamp,
                attempt_bound=True)
        except Exception:
            # No session, so no attempt. Marked abandoned rather than deleted:
            # the row is a factual record that an attempt was begun, and
            # deleting it would also free its attempt number for reuse.
            self._repository.update_attempt(
                attempt.replace(status="abandoned", ended_at=self._now(),
                                termination_reason="session_missing"))
            raise

        attempt = attempt.replace(session_id=session_id)
        self._repository.update_attempt(attempt)
        self.register_session(session_id, learner_ref,
                              attempt_id=attempt.attempt_id)
        return attempt, True

    def sync_attempt(self, attempt):
        """Reconcile an attempt with the session it is bound to.

        The attempt's result is never computed here: it is *read* from the
        session's own finalized, immutable
        :class:`~rewindsec.scoring.result.ScoringResult`, which
        :meth:`rewindsec.workstation.service.WorkstationService.end_session`
        wrote once and can never rewrite. Copying it onto the attempt row is
        what makes the trainer console readable without loading every session,
        and the copy carries the scoring, rubric and evidence-model versions
        it was produced under, so it can never be confused with a result
        produced by a later rubric.

        Idempotent, and safe to call on every read: an active attempt whose
        session is still active is returned unchanged and nothing is written.
        """
        if attempt is None or not attempt.is_active:
            return attempt
        if attempt.session_id is None:
            return attempt
        try:
            session = self._sessions.load(attempt.session_id)
        except SessionNotFoundError:
            return self._repository.update_attempt(
                attempt.replace(status="abandoned", ended_at=self._now(),
                                termination_reason="session_missing"))
        if session.is_active:
            return attempt

        # The required-interaction rule, applied here because this is the one
        # place an attempt stops being active. ``required_interactions`` is
        # part of the assessment's *completion semantics*, not a progress-bar
        # number: an attempt that ended having resolved fewer than the
        # definition asked for did not complete the assessment, however
        # deliberately the learner pressed End Training.
        completed, _presented, _detail = progress_rules.scored_interactions(
            session)
        if session.status.value != "completed":
            status, reason = "abandoned", "session_abandoned"
        elif completed == attempt.required_interactions:
            status, reason = "completed", None
        else:
            # Ended early. The session itself completed normally and its
            # Batch 4 result is stored verbatim below -- the learner's choices
            # keep their natural consequences and their score. What they do
            # not get is a valid completed assessment.
            status, reason = "abandoned", "requirement_unmet"
        result = scoring_state.get_result(session)
        stored = None if result is None else result.to_state()
        updated = attempt.replace(
            status=status, ended_at=self._now(), result_state=stored,
            completed_interactions=completed, termination_reason=reason,
            overall=None if result is None else result.overall,
            scoring_version=None if stored is None
            else stored.get("scoring_version"),
            rubric_version=None if stored is None
            else stored.get("rubric_version"),
            evidence_model_version=None if stored is None
            else stored.get("evidence_model_version"))
        return self._repository.update_attempt(updated)

    def attempt_state(self, attempt, learner_safe=True):
        """The attempt's current state, including its progress.

        With ``learner_safe`` (the default) the document carries progress but
        no score, no correctness and no dimension -- safe to return while the
        attempt is still running. A trainer view passes ``False`` to include
        the finalized result, and reaches this only through an authorized
        route.
        """
        if attempt is None:
            return None
        state = {
            "attempt_id": attempt.attempt_id,
            "assessment_id": attempt.assessment_id,
            "student_id": attempt.student_id,
            "attempt_number": attempt.attempt_number,
            "status": attempt.status,
            "session_id": attempt.session_id,
            "assignment_source": attempt.assignment_source,
            "provenance_type": attempt.provenance_type,
            "assignment_group_id": attempt.assignment_group_id,
            "assignment_id": attempt.assignment_id,
            "required_interactions": attempt.required_interactions,
            "assessment_definition_version":
                attempt.assessment_definition_version,
            "started_at": attempt.started_at,
            "ended_at": attempt.ended_at,
            # Learner-safe. How many of the required interactions were
            # handled, why the attempt ended if it ended early, and whether
            # the requirement was met -- none of which says anything about
            # *how well* any single interaction was handled.
            "completed_interactions": attempt.completed_interactions,
            "termination_reason": attempt.termination_reason,
            "requirement_met": attempt.requirement_met,
            "valid_assessment": attempt.is_valid_assessment,
        }
        state["progress"] = self.attempt_progress(attempt)
        if not learner_safe:
            state["result"] = attempt.result_state
            state["overall"] = attempt.overall
            state["scoring_version"] = attempt.scoring_version
            state["rubric_version"] = attempt.rubric_version
            state["evidence_model_version"] = attempt.evidence_model_version
        return state

    def attempt_progress(self, attempt):
        """Scored-interaction progress for one attempt, or ``None``.

        ``None`` -- not zero -- when the bound session cannot be read, so
        "nothing has been done yet" and "we cannot tell" stay distinguishable.
        """
        if attempt is None or attempt.session_id is None:
            return None
        try:
            session = self._sessions.load(attempt.session_id)
        except SessionNotFoundError:
            return None
        return progress_rules.attempt_progress(session,
                                               attempt.required_interactions)

    # -- session ownership -------------------------------------------------

    def register_session(self, session_id, learner_ref, attempt_id=None):
        """Record which student owns a session. Called once, at creation.

        Ownership is taken from the *session's own* ``learner_ref`` -- the one
        the server minted and the one every access check in
        :mod:`rewindsec.workstation.service` compares against -- never from
        anything in a request body. A caller passing a different reference
        than the session actually carries is refused rather than believed.
        """
        try:
            session = self._sessions.load(session_id)
        except SessionNotFoundError:
            raise NotFoundError("no session with id %r" % session_id)
        if session.learner_ref != learner_ref:
            raise ManagementRefused(
                "That session does not belong to this learner.",
                code="not_owner")
        try:
            student = self.require_enrolled_student(session.learner_ref)
        except ManagementRefused:
            self._abandon_raced_start(session_id, learner_ref, attempt_id)
            raise
        now = self._now()
        ownership = SessionOwnership(
            session_id=session_id, student_id=student.student_id,
            learner_ref=session.learner_ref, focus=session.focus.value,
            mode=session.mode.value, attempt_id=attempt_id,
            started_at=now, last_seen_at=now)
        recorded = self._repository.record_session_ownership(ownership)
        try:
            still_bound = self.require_enrolled_student(session.learner_ref)
            if still_bound.student_id != student.student_id:
                raise ManagementRefused(
                    self.ENROLLMENT_REQUIRED, code="enrollment_required")
        except ManagementRefused:
            self._abandon_raced_start(session_id, learner_ref, attempt_id)
            raise
        return recorded

    def _abandon_raced_start(self, session_id, learner_ref, attempt_id=None):
        """Preserve but invalidate work created after enrollment was reset."""
        self._workstation.abandon_session(
            session_id, learner_ref, reason="start_enrollment_changed")
        if attempt_id is not None:
            attempt = self._repository.get_attempt(attempt_id)
            if attempt is not None:
                self.sync_attempt(attempt)

    def get_session_ownership(self, session_id):
        return self._repository.get_session_ownership(session_id)

    #: Refused because the named session is not the named student's.
    SESSION_NOT_OWNED = "session_not_owned"

    def end_session_for_student(self, student_id, session_id):
        """End one roster student's still-active session, on trainer authority.

        The stuck case this exists for: a learner's browser session is the
        only thing that can reach ``/api/session/end``, because that route
        identifies the session from the learner's own signed cookie. When the
        cookie is lost -- a cleared browser, a different device, an
        enrollment that moved -- the TrainingSession row stays ``active``
        forever, and :meth:`_active_work` therefore refuses enrollment reset
        and roster deletion for as long as it does. Nothing in the system
        could move that row to a terminal state.

        What this does **not** do, and why the trainer cannot ask for it:

        * It does not impersonate the learner. The owning ``learner_ref`` is
          read from the persisted :class:`SessionOwnership` row, checked
          against the session's own ``learner_ref``, and never accepted from
          a caller. There is no parameter here through which an owner, a
          learner reference or an attempt could arrive.
        * It does not delete the session, reset any simulation state, rewind
          the clock, or draw from any RNG stream. It is exactly the ordinary
          end-of-session transition
          (:meth:`WorkstationService.end_session
          <rewindsec.workstation.service.WorkstationService.end_session>`),
          which records ``session.ended``, finalizes the one Batch 4 result
          the session will ever have, and preserves every fact.
        * It does not recompute or invent an assessment outcome. The bound
          Attempt is reconciled through :meth:`sync_attempt`, under exactly
          the policy a learner-ended session goes through: an attempt whose
          required scored-interaction boundary was not satisfied is recorded
          ``abandoned``/``requirement_unmet``, never falsely ``completed``.

        Idempotent. A session that is already terminal -- because the learner
        ended it, because a previous trainer request ended it, or because the
        two raced -- is reported as already ended rather than touched again.
        """
        student = self.require_roster_student(student_id)
        ownership = self._repository.get_session_ownership(session_id)
        if ownership is None:
            raise NotFoundError("no session with id %r" % session_id)
        if ownership.student_id != student.student_id:
            # The trainer named a student and a session that do not belong
            # together. Refused rather than reinterpreted: the student in the
            # URL is the authorization subject, not a hint.
            raise ManagementRefused(
                "That session does not belong to this student.",
                code=self.SESSION_NOT_OWNED)
        session = self.load_session(session_id)
        if session is None:
            raise NotFoundError("no session with id %r" % session_id)
        if session.learner_ref != ownership.learner_ref:
            # Ownership is authoritatively the session's own learner_ref.
            # A row that disagrees is a fault, not a licence to end somebody
            # else's work.
            raise ManagementRefused(
                "That session's ownership record does not match the session.",
                code=self.SESSION_NOT_OWNED)

        if not session.is_active:
            return self._ended_session_result(
                student, session_id, "already_ended")

        try:
            self._workstation.end_session(session_id, ownership.learner_ref)
        except StaleRevisionConflict:
            # The learner (or another trainer request) moved the session
            # between the read above and the write. Re-read the truth: if it
            # is terminal now, the intent was satisfied by whoever won, and
            # this is a safe idempotent answer rather than a second write.
            settled = self.load_session(session_id)
            if settled is not None and not settled.is_active:
                return self._ended_session_result(
                    student, session_id, "already_ended")
            raise ManagementRefused(
                "That session changed while it was being ended. Try again.",
                code="session_end_conflict")

        # Same reconciliation the learner path performs, for the same reason:
        # the attempt's result is *read* from the session's now-finalized,
        # immutable result and never computed here.
        attempt = self._repository.attempt_for_session(session_id)
        if attempt is not None:
            self.sync_attempt(attempt)
        return self._ended_session_result(student, session_id, "ended")

    def _ended_session_result(self, student, session_id, kind):
        """A safe result document describing a session's terminal state."""
        session = self.load_session(session_id)
        attempt = self._repository.attempt_for_session(session_id)
        _ownerships, _attempts, active = self._active_work(student)
        return {
            "kind": kind,
            "session_id": session_id,
            "student_id": student.student_id,
            "status": None if session is None else session.status.value,
            "attempt_status": None if attempt is None else attempt.status,
            "student_has_active_work": active,
        }

    def sessions_for_student(self, student_id):
        return self._repository.list_session_ownership(student_id=student_id)

    def session_summaries(self, learner_refs=None):
        return self._directory.list_summaries(learner_refs=learner_refs)

    def load_session(self, session_id):
        """A stored session, or ``None``. Read-only; mutates nothing."""
        try:
            return self._sessions.load(session_id)
        except Exception:
            # A snapshot this build cannot parse must not take a listing page
            # down with it. It is reported as unreadable, never as absent and
            # never as somebody's result.
            return None
