"""The storage-independent administrative records.

Plain Python objects with an explicit, validated shape and a canonical
``to_state``/``from_state`` pair, in the same style
:mod:`rewindsec.domain` uses for the simulation aggregate: the adapter in
:mod:`rewindsec.persistence.management_adapter` maps these to columns, and
nothing outside that module has to know a column exists.

Identity data is kept to the minimum a trainer console needs -- a display
name, an organisational reference, a cohort label and a status. There is no
address, no date of birth, no contact detail and no free-text note about a
person. Adding one would be a product decision with a data-protection
consequence, not a convenience.

What a *cohort* is here, and is not
-----------------------------------
``Student.cohort`` is a presentational label and nothing more. It is never
consulted to decide who receives an assessment: that is what
:class:`StudentGroup` and :class:`GroupMembership` are for, and the
many-to-many relation between them is the only membership fact in the system.
A single cohort string could not express "Aarti is in Operations - Cohort A
*and* in Finance - payment handlers", which is exactly the situation
assignment provenance has to survive.
"""

from rewindsec.domain.enums import Focus, coerce_enum
from rewindsec.domain.errors import InvalidIdentityError
from rewindsec.domain.identifiers import (validate_bounded_str,
                                          validate_identity,
                                          validate_nonneg_int)
from rewindsec.management import assessment_policy

__all__ = [
    "Student", "StudentGroup", "GroupMembership", "Assessment", "Assignment",
    "Attempt", "SessionOwnership", "EnrollmentCode",
    "STUDENT_STATUSES", "ASSESSMENT_STATUSES", "ATTEMPT_STATUSES",
    "ASSIGNMENT_TARGETS", "ATTEMPT_SOURCES", "RETRY_POLICY_BOUNDED",
    "RETRY_POLICIES",
    "ASSESSMENT_DEFINITION_VERSION", "MAX_REQUIRED_INTERACTIONS",
    "MAX_ATTEMPTS_CEILING", "ATTEMPT_STARTABLE_STATUSES",
    "TERMINATION_REASONS", "ENROLLMENT_STATUSES",
    "validate_focus_id", "validate_optional_identity",
]

#: Bumped when the *meaning* of an assessment definition's fields changes.
#: Stamped onto every assessment at creation and copied onto every attempt, so
#: a historical attempt always says which definition shape it ran under.
ASSESSMENT_DEFINITION_VERSION = "rewindsec-assessment-definition/v1"

#: The only retry policy this batch implements: a bounded maximum number of
#: attempts per (student, assessment). Deliberately small. An adaptive
#: retesting rule would be a product invention with no authority behind it.
RETRY_POLICY_BOUNDED = "bounded-attempts/v1"
RETRY_POLICIES = (RETRY_POLICY_BOUNDED,)

STUDENT_STATUSES = ("active", "onboarding", "inactive")
ASSESSMENT_STATUSES = ("draft", "scheduled", "open", "closed")
ATTEMPT_STATUSES = ("active", "completed", "abandoned")
ASSIGNMENT_TARGETS = ("student", "group")
ATTEMPT_SOURCES = ("direct", "group", "self_directed")

#: The assessment statuses from which a *new* attempt may be started.
#:
#: ``open`` and only ``open``. ``scheduled`` used to be accepted here on the
#: grounds that this batch implements no scheduling engine, which was an
#: argument about what the server does *not* do being used to widen what a
#: learner *may* do. The approved trainer UI shows ``scheduled`` and ``open``
#: as different states, a trainer who sets one and gets the behaviour of the
#: other has been lied to, and "not yet released" is exactly the meaning a
#: trainer chooses ``scheduled`` for. A scheduled assessment is therefore
#: visible and assignable and refuses to start; releasing it is the explicit
#: act of setting it ``open``. Automating that transition on a window is a
#: separate feature and is deliberately not invented here.
ATTEMPT_STARTABLE_STATUSES = ("open",)

#: Why an attempt ended in something other than ``completed``. ``None`` on an
#: active attempt and on a validly completed one.
#:
#: ``requirement_unmet``
#:     The learner ended the session before resolving the assessment
#:     definition's ``required_interactions`` scored interactions. The session
#:     itself completed normally and its Batch 4 result is stored verbatim --
#:     what did *not* happen is a valid assessment.
#: ``session_abandoned``
#:     The bound session was abandoned rather than completed.
#: ``session_missing``
#:     The bound session can no longer be read at all.
TERMINATION_REASONS = ("requirement_unmet", "session_abandoned",
                       "session_missing")

#: The lifecycle of one enrolment code. See :class:`EnrollmentCode`.
ENROLLMENT_STATUSES = ("open", "claimed", "revoked")

#: Sanity ceilings. An assessment requiring more scored interactions than a
#: session can present would be unsatisfiable by construction, and a very
#: large retry allowance is indistinguishable from no policy at all.
MAX_REQUIRED_INTERACTIONS = max(
    assessment_policy.capacity_by_focus().values())
MAX_ATTEMPTS_CEILING = 20

_MAX_NAME = 120
_MAX_LABEL = 160
_MAX_NOTE = 400


def validate_focus_id(value, what="focus"):
    """Return the focus *string*, validated against the domain vocabulary.

    Records store the serialised value rather than the enum member so a stored
    row is JSON, but the vocabulary is the domain's -- there is no second list
    of focus names anywhere in this package.
    """
    return coerce_enum(value, Focus, what).value


def validate_optional_identity(value, what):
    if value is None:
        return None
    return validate_identity(value, what)


def _validate_choice(value, choices, what):
    if value not in choices:
        raise InvalidIdentityError(
            "%s must be one of %s, got %r" % (what, ", ".join(choices), value))
    return value


def _validate_timestamp(value, what):
    """An administrative timestamp: ISO-8601 text, or ``None``.

    Text rather than a datetime so a record is JSON by construction and the
    adapter stores exactly what it was given. These never reach a simulation
    decision -- see :mod:`rewindsec.management`'s determinism note.
    """
    if value is None:
        return None
    return validate_bounded_str(value, what, 64)


def _bounded_int(value, what, minimum, maximum):
    value = validate_nonneg_int(value, what, max_value=maximum)
    if value < minimum:
        raise InvalidIdentityError(
            "%s must be at least %d, got %d" % (what, minimum, value))
    return value


class _Record(object):
    """Shared equality/repr for the small value objects below."""

    _FIELDS = ()

    def to_state(self):
        return {name: getattr(self, name) for name in self._FIELDS}

    @classmethod
    def from_state(cls, state):
        return cls(**{name: state.get(name) for name in cls._FIELDS})

    def replace(self, **changes):
        state = self.to_state()
        state.update(changes)
        return type(self).from_state(state)

    def __eq__(self, other):
        return (type(other) is type(self)
                and other.to_state() == self.to_state())

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, ", ".join(
            "%s=%r" % (name, getattr(self, name)) for name in self._FIELDS))


class Student(_Record):
    """One persistent learner record.

    ``learner_ref`` is the server-minted opaque token a
    :class:`~rewindsec.domain.session.SimulationSession` is owned by. It is the
    *only* link between a person and their sessions, it is never accepted from
    a request, and it is never derived from a display name -- so no client can
    claim somebody else's history by sending a different name.

    ``deleted_at`` is the roster lifecycle marker. ``None`` -- the only value
    every row written before this field existed can read back as -- means
    *on the active roster*. A timestamp means the trainer removed this
    student from the roster while historical training evidence existed, so
    the row survives to keep that evidence resolvable and is excluded from
    every active-roster list, picker, count and mutation route. It is a
    roster deletion, not an erasure: no session, attempt, result, score or
    provenance record is touched by setting it.
    """

    _FIELDS = ("student_id", "display_name", "reference", "cohort", "status",
               "learner_ref", "origin", "created_at", "deleted_at")

    def __init__(self, student_id, display_name, reference=None, cohort=None,
                 status="active", learner_ref=None, origin="trainer",
                 created_at=None, deleted_at=None):
        self.student_id = validate_identity(student_id, "student_id")
        self.display_name = validate_bounded_str(
            display_name, "display_name", _MAX_NAME)
        self.reference = (None if reference is None else
                          validate_bounded_str(reference, "reference", 64))
        self.cohort = (None if cohort is None else
                       validate_bounded_str(cohort, "cohort", 64))
        self.status = _validate_choice(status, STUDENT_STATUSES, "status")
        self.learner_ref = validate_optional_identity(learner_ref, "learner_ref")
        self.origin = _validate_choice(
            origin, ("trainer", "self_provisioned"), "origin")
        self.created_at = _validate_timestamp(created_at, "created_at")
        self.deleted_at = _validate_timestamp(deleted_at, "deleted_at")

    @property
    def is_deleted(self):
        """Whether this student has been removed from the active roster.

        The single predicate every reader uses, so "deleted" is never spelled
        two different ways in two different modules.
        """
        return self.deleted_at is not None

    @property
    def initials(self):
        """Two letters for the avatar chip. Presentation only."""
        parts = [part for part in self.display_name.split() if part]
        if not parts:
            return "?"
        if len(parts) == 1:
            return parts[0][:2].upper()
        return (parts[0][:1] + parts[-1][:1]).upper()


class StudentGroup(_Record):
    """A named set of students. Membership lives in :class:`GroupMembership`."""

    _FIELDS = ("group_id", "name", "description", "created_at", "created_by")

    def __init__(self, group_id, name, description=None, created_at=None,
                 created_by=None):
        self.group_id = validate_identity(group_id, "group_id")
        self.name = validate_bounded_str(name, "name", _MAX_NAME)
        self.description = (None if description is None else
                            validate_bounded_str(description, "description",
                                                 _MAX_NOTE, allow_empty=True))
        self.created_at = _validate_timestamp(created_at, "created_at")
        self.created_by = (None if created_by is None else
                           validate_bounded_str(created_by, "created_by",
                                                _MAX_NAME))


class GroupMembership(_Record):
    """One student's membership of one group. The many-to-many relation.

    A student may hold any number of these, and a group may contain any
    number. Removing one deletes *current* membership only: every
    :class:`Assignment` and every :class:`Attempt` already made keeps its own
    provenance, because neither is derived from this row at read time.
    """

    _FIELDS = ("membership_id", "group_id", "student_id", "added_at",
               "added_by")

    def __init__(self, membership_id, group_id, student_id, added_at=None,
                 added_by=None):
        self.membership_id = validate_identity(membership_id, "membership_id")
        self.group_id = validate_identity(group_id, "group_id")
        self.student_id = validate_identity(student_id, "student_id")
        self.added_at = _validate_timestamp(added_at, "added_at")
        self.added_by = (None if added_by is None else
                         validate_bounded_str(added_by, "added_by", _MAX_NAME))


class Assessment(_Record):
    """A persistent assessment *definition*.

    Product-level controls only. There is deliberately no field here for an
    organisation profile, a threat-family probability, a hazard value, an
    event ordering, an RNG seed, a learner difficulty or a scoring weight: an
    assessment says *what must be demonstrated and how many times*, and the
    system decides how to present it.

    ``required_interactions`` counts **scored interactions** -- opportunities
    the session presented that the learner actually resolved with a recorded
    decision. It is not an event count, a message count, a duration or a
    scheduler-tick count; see :mod:`rewindsec.management.progress`.
    """

    _FIELDS = ("assessment_id", "name", "focus", "required_interactions",
               "status", "max_attempts", "retry_policy", "window_label",
               "note", "created_at", "created_by", "definition_version")

    def __init__(self, assessment_id, name, focus, required_interactions,
                 status="draft", max_attempts=1,
                 retry_policy=RETRY_POLICY_BOUNDED, window_label=None,
                 note=None, created_at=None, created_by=None,
                 definition_version=ASSESSMENT_DEFINITION_VERSION):
        self.assessment_id = validate_identity(assessment_id, "assessment_id")
        self.name = validate_bounded_str(name, "name", _MAX_NAME)
        self.focus = validate_focus_id(focus)
        capacity = assessment_policy.required_interaction_capacity(self.focus)
        self.required_interactions = _bounded_int(
            required_interactions, "required_interactions", 1, capacity)
        self.status = _validate_choice(status, ASSESSMENT_STATUSES, "status")
        self.max_attempts = _bounded_int(
            max_attempts, "max_attempts", 1, MAX_ATTEMPTS_CEILING)
        self.retry_policy = _validate_choice(
            retry_policy, RETRY_POLICIES, "retry_policy")
        self.window_label = (None if window_label is None else
                             validate_bounded_str(window_label, "window_label",
                                                  _MAX_LABEL, allow_empty=True))
        self.note = (None if note is None else
                     validate_bounded_str(note, "note", _MAX_NOTE,
                                          allow_empty=True))
        self.created_at = _validate_timestamp(created_at, "created_at")
        self.created_by = (None if created_by is None else
                           validate_bounded_str(created_by, "created_by",
                                                _MAX_NAME))
        self.definition_version = validate_bounded_str(
            definition_version, "definition_version", 64)

    @property
    def accepts_new_attempts(self):
        """Whether the definition's own lifecycle allows an attempt to start.

        ``open`` only -- see :data:`ATTEMPT_STARTABLE_STATUSES`. A draft has
        not been written yet, a scheduled assessment has been written but not
        released, and a closed one is retained for the record. None of the
        three is a retry-policy question -- see
        :mod:`rewindsec.management.service` for that.
        """
        return self.status in ATTEMPT_STARTABLE_STATUSES

    @property
    def is_self_directed_policy(self):
        """Whether this is a system-owned learner policy, not trainer data."""
        return (self.definition_version
                == assessment_policy.SELF_DIRECTED_DEFINITION_VERSION)


class Assignment(_Record):
    """One route by which an assessment reaches learners, with its provenance.

    An assignment is never merged with another. A student who receives the
    same assessment through two groups *and* directly holds three assignment
    rows, and each one still says where it came from. That is what makes the
    duplicate warning answerable with "here is where it already comes from"
    rather than a bare boolean.

    ``request_id`` is the trainer client's own idempotency token for the
    operation. A retried network submission carrying the same token resolves
    to the row it already created rather than manufacturing a second one;
    manufacturing a second one is what ``confirmed_duplicate`` is for, and
    that requires an explicit, separate act.
    """

    _FIELDS = ("assignment_id", "assessment_id", "target_type", "student_id",
               "group_id", "created_at", "created_by", "request_id",
               "confirmed_duplicate", "acknowledged_sources", "status")

    def __init__(self, assignment_id, assessment_id, target_type,
                 student_id=None, group_id=None, created_at=None,
                 created_by=None, request_id=None, confirmed_duplicate=False,
                 acknowledged_sources=None, status="active"):
        self.assignment_id = validate_identity(assignment_id, "assignment_id")
        self.assessment_id = validate_identity(assessment_id, "assessment_id")
        self.target_type = _validate_choice(
            target_type, ASSIGNMENT_TARGETS, "target_type")
        self.student_id = validate_optional_identity(student_id, "student_id")
        self.group_id = validate_optional_identity(group_id, "group_id")
        if self.target_type == "student":
            if self.student_id is None or self.group_id is not None:
                raise InvalidIdentityError(
                    "a direct assignment names a student and no group")
        else:
            if self.group_id is None or self.student_id is not None:
                raise InvalidIdentityError(
                    "a group assignment names a group and no student")
        self.created_at = _validate_timestamp(created_at, "created_at")
        self.created_by = (None if created_by is None else
                           validate_bounded_str(created_by, "created_by",
                                                _MAX_NAME))
        self.request_id = (None if request_id is None else
                           validate_bounded_str(request_id, "request_id", 80))
        self.confirmed_duplicate = bool(confirmed_duplicate)
        #: The existing sources the trainer was shown and acknowledged when
        #: they confirmed a duplicate. Kept so the record says what the
        #: decision was made in the knowledge of, not merely that it was made.
        self.acknowledged_sources = list(acknowledged_sources or [])
        self.status = _validate_choice(
            status, ("active", "withdrawn"), "status")

    @property
    def source(self):
        """``"direct"`` or ``"group"`` -- the provenance vocabulary the UI uses."""
        return "direct" if self.target_type == "student" else "group"


class Attempt(_Record):
    """One learner's attempt at one assessment, bound to one TrainingSession.

    A trainer-assigned link runs Student -> effective Assignment -> Attempt ->
    TrainingSession -> immutable finalized
    :class:`~rewindsec.scoring.result.ScoringResult`.  A self-directed link
    omits Assignment entirely and records ``assignment_source=self_directed``;
    it never fabricates a group/direct assignment.  Real assignment provenance
    is copied at creation, so later membership changes cannot rewrite history.

    ``result_state`` is the session's own finalized Batch 4 result artifact,
    stored verbatim. There is no second, competing trainer score anywhere.
    """

    _FIELDS = ("attempt_id", "assessment_id", "student_id", "attempt_number",
               "status", "session_id", "assignment_id", "assignment_source",
               "assignment_group_id", "required_interactions",
               "assessment_definition_version", "started_at", "ended_at",
               "result_state", "scoring_version", "rubric_version",
               "evidence_model_version", "overall", "completed_interactions",
               "termination_reason")

    def __init__(self, attempt_id, assessment_id, student_id, attempt_number,
                 status="active", session_id=None, assignment_id=None,
                 assignment_source=None, assignment_group_id=None,
                 required_interactions=1,
                 assessment_definition_version=ASSESSMENT_DEFINITION_VERSION,
                 started_at=None, ended_at=None, result_state=None,
                 scoring_version=None, rubric_version=None,
                 evidence_model_version=None, overall=None,
                 completed_interactions=None, termination_reason=None):
        self.attempt_id = validate_identity(attempt_id, "attempt_id")
        self.assessment_id = validate_identity(assessment_id, "assessment_id")
        self.student_id = validate_identity(student_id, "student_id")
        self.attempt_number = _bounded_int(
            attempt_number, "attempt_number", 1, MAX_ATTEMPTS_CEILING)
        self.status = _validate_choice(status, ATTEMPT_STATUSES, "status")
        self.session_id = validate_optional_identity(session_id, "session_id")
        self.assignment_id = validate_optional_identity(
            assignment_id, "assignment_id")
        self.assignment_source = (
            None if assignment_source is None else
            _validate_choice(assignment_source, ATTEMPT_SOURCES,
                             "assignment_source"))
        self.assignment_group_id = validate_optional_identity(
            assignment_group_id, "assignment_group_id")
        if self.assignment_source == "self_directed" and (
                self.assignment_id is not None
                or self.assignment_group_id is not None):
            raise InvalidIdentityError(
                "a self-directed attempt has no assignment provenance")
        self.required_interactions = _bounded_int(
            required_interactions, "required_interactions", 1,
            MAX_REQUIRED_INTERACTIONS)
        self.assessment_definition_version = validate_bounded_str(
            assessment_definition_version, "assessment_definition_version", 64)
        self.started_at = _validate_timestamp(started_at, "started_at")
        self.ended_at = _validate_timestamp(ended_at, "ended_at")
        self.result_state = (None if result_state is None else dict(result_state))
        self.scoring_version = (None if scoring_version is None else
                                validate_bounded_str(scoring_version,
                                                     "scoring_version", 64))
        self.rubric_version = (None if rubric_version is None else
                               validate_bounded_str(rubric_version,
                                                    "rubric_version", 64))
        self.evidence_model_version = (
            None if evidence_model_version is None else
            validate_bounded_str(evidence_model_version,
                                 "evidence_model_version", 64))
        if overall is not None:
            overall = validate_nonneg_int(overall, "overall", max_value=100)
        self.overall = overall
        #: Scored interactions the bound session had actually resolved when
        #: this attempt was reconciled. ``None`` on an active attempt and on a
        #: legacy row written before the completion rule existed -- "we never
        #: recorded it" and "the learner resolved none" must not look alike.
        if completed_interactions is not None:
            completed_interactions = validate_nonneg_int(
                completed_interactions, "completed_interactions",
                max_value=10000)
        self.completed_interactions = completed_interactions
        self.termination_reason = (
            None if termination_reason is None else
            _validate_choice(termination_reason, TERMINATION_REASONS,
                             "termination_reason"))

    @property
    def is_active(self):
        return self.status == "active"

    @property
    def provenance_type(self):
        """Stable provenance vocabulary for learner/trainer projections."""
        return self.assignment_source

    @property
    def requirement_met(self):
        """Whether the recorded scored-interaction count satisfies the rule.

        ``None`` when the count was never recorded, so an unanswerable
        question is never answered ``False``.
        """
        if self.completed_interactions is None:
            return None
        return self.completed_interactions == self.required_interactions

    @property
    def is_valid_assessment(self):
        """Whether this attempt is a *valid, completed* assessment.

        The single predicate every reader should use. ``completed`` is only
        ever written when the requirement was satisfied (see
        :meth:`rewindsec.management.service.ManagementService.sync_attempt`),
        so the two halves of this cannot drift apart -- but stating both is
        what makes the invariant checkable from outside the service.
        """
        return self.status == "completed" and self.requirement_met is True


class SessionOwnership(_Record):
    """The explicit, persisted owner of one TrainingSession.

    Ownership is *authoritatively* the session's own ``learner_ref`` -- that is
    what every access check in :mod:`rewindsec.workstation.service` compares,
    and this record never overrides it. What this row adds is the resolved
    student, the administrative timestamps the session aggregate deliberately
    does not carry (it has no wall clock at all), and the attempt link when
    the session is an assessment attempt.

    A session with no row here is a *legacy or unowned* session: it is shown
    as such, and is never attributed to a student on a guess.
    """

    _FIELDS = ("session_id", "student_id", "learner_ref", "focus", "mode",
               "attempt_id", "started_at", "last_seen_at")

    def __init__(self, session_id, student_id, learner_ref, focus, mode,
                 attempt_id=None, started_at=None, last_seen_at=None):
        self.session_id = validate_identity(session_id, "session_id")
        self.student_id = validate_identity(student_id, "student_id")
        self.learner_ref = validate_identity(learner_ref, "learner_ref")
        self.focus = validate_focus_id(focus)
        self.mode = validate_bounded_str(mode, "mode", 32)
        self.attempt_id = validate_optional_identity(attempt_id, "attempt_id")
        self.started_at = _validate_timestamp(started_at, "started_at")
        self.last_seen_at = _validate_timestamp(last_seen_at, "last_seen_at")


class EnrollmentCode(_Record):
    """One bounded, single-use claim on one roster :class:`Student`.

    Batch 5 created students but gave a real browser no way to *become* one:
    the smoke tests seeded the learner cookie by hand, which meant that
    trainer-created students, group memberships and assignments were not
    genuinely end-to-end usable. This record is the smallest mechanism that
    closes that gap without inventing an account system.

    What it deliberately is not
    ---------------------------
    * **Not a password, and not a credential.** It authenticates nothing and
      grants no ongoing access. It is consumed once, at the moment a browser
      claims a student, and is dead thereafter.
    * **Not the** ``learner_ref``. The learner reference is the server-minted
      token a session is owned by and is never shown to anybody; the code is a
      separate, separately-minted secret that exists only to be spent. Handing
      out the learner reference as a roster identifier would mean anyone who
      saw it could claim that person's whole history.
    * **Not personal data.** It is random bytes bound to a student id.

    ``claimed_learner_ref`` is what makes replay a refusal rather than a
    silent transfer: once a code carries one, the only browser it will ever
    resolve for again is that same one, and a second browser presenting the
    same material is refused rather than being handed the student.
    """

    _FIELDS = ("code_id", "code", "student_id", "status", "created_at",
               "created_by", "claimed_at", "claimed_learner_ref")

    def __init__(self, code_id, code, student_id, status="open",
                 created_at=None, created_by=None, claimed_at=None,
                 claimed_learner_ref=None):
        self.code_id = validate_identity(code_id, "code_id")
        self.code = validate_identity(code, "code")
        self.student_id = validate_identity(student_id, "student_id")
        self.status = _validate_choice(status, ENROLLMENT_STATUSES, "status")
        self.created_at = _validate_timestamp(created_at, "created_at")
        self.created_by = (None if created_by is None else
                           validate_bounded_str(created_by, "created_by",
                                                _MAX_NAME))
        self.claimed_at = _validate_timestamp(claimed_at, "claimed_at")
        self.claimed_learner_ref = validate_optional_identity(
            claimed_learner_ref, "claimed_learner_ref")

    @property
    def is_open(self):
        return self.status == "open" and self.claimed_learner_ref is None
