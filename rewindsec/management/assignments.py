"""Effective assignments, and where each one came from.

Pure functions over :mod:`rewindsec.management.records` objects. No storage,
no HTTP, no service. Kept separate from
:mod:`rewindsec.management.service` because "which assessments does this
learner effectively hold, and by what route" is the question the whole
duplicate-assignment interaction is built on, and it should be answerable --
and testable -- without a database.

The rule that shapes all of it
------------------------------
An assignment is a *route*, and routes are never merged. A student who is in
Operations - Cohort A (which was assigned the Q3 check), is also in Finance -
payment handlers (which was assigned it too), and was later assigned it
directly, holds **three** effective assignments for one assessment. Each says
where it came from. Flattening them into a single membership row would
destroy the only answer the trainer actually needs when they ask "why does
this person have this?", and would make removing one group silently revoke an
assessment that arrived by a different route.

That is also why membership is consulted *at read time* for group routes but
copied *at write time* onto an attempt: an effective assignment is a live
question about who is in which group today, while an attempt is a historical
fact about how it was assigned when it was taken.
"""

__all__ = ["EffectiveAssignment", "effective_assignments",
           "assignment_sources", "covered_students", "duplicate_report"]


class EffectiveAssignment(object):
    """One route by which one student holds one assessment."""

    __slots__ = ("assignment", "student_id", "source", "group", "assessment")

    def __init__(self, assignment, student_id, source, group=None,
                 assessment=None):
        self.assignment = assignment
        self.student_id = student_id
        #: ``"direct"`` or ``"group"``.
        self.source = source
        #: The :class:`~rewindsec.management.records.StudentGroup` this route
        #: came through, for a group route. ``None`` for a direct one.
        self.group = group
        self.assessment = assessment

    @property
    def origin_label(self):
        if self.source == "direct":
            return "Assigned directly"
        name = self.group.name if self.group is not None else self.assignment.group_id
        return "Via group · %s" % name

    def to_state(self):
        return {
            "assignment_id": self.assignment.assignment_id,
            "assessment_id": self.assignment.assessment_id,
            "source": self.source,
            "origin_label": self.origin_label,
            "group_id": self.assignment.group_id,
            "group_name": None if self.group is None else self.group.name,
            "created_at": self.assignment.created_at,
            "created_by": self.assignment.created_by,
            "confirmed_duplicate": self.assignment.confirmed_duplicate,
        }


def _membership_index(memberships):
    """``{student_id: {group_id}}`` from current membership rows."""
    index = {}
    for membership in memberships:
        index.setdefault(membership.student_id, set()).add(membership.group_id)
    return index


def effective_assignments(student_id, assignments, memberships, groups_by_id,
                          assessments_by_id=None, assessment_id=None):
    """Every route by which *student_id* currently holds an assessment.

    Ordered by the assignment's creation timestamp then its id, so two calls
    on the same data always list the routes in the same order -- never by
    dict iteration.
    """
    groups = _membership_index(memberships).get(student_id, set())
    assessments_by_id = assessments_by_id or {}
    found = []
    for assignment in assignments:
        if assignment.status != "active":
            continue
        if assessment_id is not None \
                and assignment.assessment_id != assessment_id:
            continue
        assessment = assessments_by_id.get(assignment.assessment_id)
        if assignment.target_type == "student":
            if assignment.student_id != student_id:
                continue
            found.append(EffectiveAssignment(
                assignment, student_id, "direct", assessment=assessment))
        else:
            if assignment.group_id not in groups:
                continue
            found.append(EffectiveAssignment(
                assignment, student_id, "group",
                group=groups_by_id.get(assignment.group_id),
                assessment=assessment))
    found.sort(key=lambda item: (item.assignment.created_at or "",
                                 item.assignment.assignment_id))
    return tuple(found)


def assignment_sources(assessment_id, student_id, assignments, memberships,
                       groups_by_id):
    """Every existing route by which *student_id* already receives an assessment.

    A list, never a boolean. "Already assigned" on its own tells a trainer
    nothing they can act on -- they need to know whether it arrives through a
    group they are about to remove, through a group somebody else manages, or
    directly, before they can decide whether a second, separately provenanced
    assignment is what they want.
    """
    routes = effective_assignments(
        student_id, assignments, memberships, groups_by_id,
        assessment_id=assessment_id)
    out = []
    for route in routes:
        assignment = route.assignment
        entry = {
            "assignment_id": assignment.assignment_id,
            "source": route.source,
            "label": ("Assigned directly to this student"
                      if route.source == "direct" else route.origin_label),
            "created": assignment.created_at,
            "created_by": assignment.created_by,
            "confirmed_duplicate": assignment.confirmed_duplicate,
        }
        if route.source == "group":
            entry["group_id"] = assignment.group_id
            entry["group_name"] = (route.group.name if route.group is not None
                                   else assignment.group_id)
        out.append(entry)
    return out


def covered_students(target_type, target_id, memberships):
    """The students a requested assignment target would actually reach.

    A direct target reaches one student. A group target reaches its current
    members -- which may be nobody, and an empty group is a legitimate target:
    assigning to it now and adding members later is an ordinary thing to do,
    and refusing it would push the trainer into assigning individually and
    losing the group provenance.
    """
    if target_type == "student":
        return (target_id,)
    return tuple(sorted(m.student_id for m in memberships
                        if m.group_id == target_id))


def duplicate_report(assessment_id, target_type, target_id, assignments,
                     memberships, groups_by_id, students_by_id):
    """Which of the students this target covers already receive the assessment.

    Returns a list of ``{"student": {...}, "sources": [...]}`` -- one entry per
    *affected* student, each carrying every existing route. An empty list means
    no student this target covers holds the assessment yet, and the assignment
    can proceed without a confirmation.

    Assigning a group whose members mostly do not have the assessment, but one
    of whom does, is the case this exists for: the trainer is told exactly who
    and exactly why, rather than being blocked or -- worse -- allowed through
    silently.
    """
    affected = []
    for student_id in covered_students(target_type, target_id, memberships):
        sources = assignment_sources(assessment_id, student_id, assignments,
                                     memberships, groups_by_id)
        if not sources:
            continue
        student = students_by_id.get(student_id)
        affected.append({
            "student": {
                "id": student_id,
                "name": (student.display_name if student is not None
                         else student_id),
                "reference": None if student is None else student.reference,
            },
            "sources": sources,
        })
    affected.sort(key=lambda entry: (entry["student"]["name"],
                                     entry["student"]["id"]))
    return affected
