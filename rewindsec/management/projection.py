"""Trainer-facing view models, built from persisted RewindSec 2.0 records.

The only module that decides what a trainer screen sees. It reads through
:class:`~rewindsec.management.service.ManagementService`, joins the
administrative records to the stored sessions and their finalized scoring
results, and returns plain dictionaries the templates render. No template
performs a lookup, and no template computes a figure.

Every value here is measured or stored. Where a figure cannot be derived from
persisted data, the field is ``None`` and the screen renders an honest dash --
never a placeholder number, and never a fixture value presented as a
measurement.

This is a *trainer* projection and is reached only through an authorized
route. It legitimately carries finalized scores and results for completed
sessions. It must never be handed to a learner-facing endpoint, and the
learner projection (:mod:`rewindsec.workstation.projection`) has no import of
this module in either direction.
"""

from rewindsec.management import analytics
from rewindsec.management.assignments import effective_assignments
from rewindsec.scoring import state as scoring_state
from rewindsec.training import policy as training_policy

__all__ = ["dashboard", "students_overview", "student_detail",
           "groups_overview", "group_detail", "assessments_overview",
           "profile_label", "session_row", "TRAINER_IDENTITY"]

#: What the console header says about who is signed in. The deployment has one
#: instructor role and no user table (see ``security.py``), so this states the
#: role rather than inventing a person -- the fixture console's named trainer
#: was demonstration data and does not survive into the real screens.
TRAINER_IDENTITY = {
    "name": "Trainer",
    "role": "Authorized console",
    "organization": "RewindSec 2.0",
}

#: The derived scaffolding profile, by mode. Derived, never chosen: a trainer
#: may see which profile a session ran under and can no more set it than a
#: learner can. The mode is the learner's own choice for a self-directed run
#: and the assessment's for an attempt; the profile follows from it.
_PROFILE_LABELS = {
    "practice": "High scaffolding",
    "simulation": "Standard scaffolding",
    "assessment": "Minimal scaffolding",
}

_STATUS_LABELS = {
    "active": "In progress",
    "completed": "Complete",
    "abandoned": "Abandoned",
}


def profile_label(mode):
    """The derived scaffolding profile label for a mode, with its version."""
    base = _PROFILE_LABELS.get(mode)
    if base is None:
        return None
    return "%s · %s" % (base, training_policy.ENGINE_VERSION)


def _score_for(session):
    """The finalized overall score for a stored session, or ``None``.

    ``None`` covers three genuinely different situations, and the caller shows
    a dash for all of them rather than a zero: the session is still running,
    the session predates Batch 4 scoring entirely, or every dimension was N/A
    so there is no overall figure to state.
    """
    if session is None:
        return None
    result = scoring_state.get_result(session)
    return None if result is None else result.overall


def session_row(service, ownership, summary=None, session=None,
                students_by_id=None, assessments_by_id=None,
                attempts_by_id=None):
    """One row of session history, joined across the records that describe it."""
    students_by_id = students_by_id or {}
    assessments_by_id = assessments_by_id or {}
    attempts_by_id = attempts_by_id or {}

    status = summary.status if summary is not None else None
    student = students_by_id.get(ownership.student_id)
    attempt = attempts_by_id.get(ownership.attempt_id)
    assessment = (assessments_by_id.get(attempt.assessment_id)
                  if attempt is not None else None)

    return {
        "session_id": ownership.session_id,
        "student_id": ownership.student_id,
        "student_name": (student.display_name if student is not None
                         else ownership.student_id),
        "student_reference": None if student is None else student.reference,
        "focus": ownership.focus,
        "mode": ownership.mode,
        "profile": profile_label(ownership.mode),
        "started": ownership.started_at,
        "status": status,
        "status_label": _STATUS_LABELS.get(status, "Unknown"),
        "readable": summary is not None,
        "score": _score_for(session),
        "attempt_id": ownership.attempt_id,
        "attempt_number": None if attempt is None else attempt.attempt_number,
        "assessment_id": None if attempt is None else attempt.assessment_id,
        "assessment_name": None if assessment is None else assessment.name,
    }


def _context(service):
    """The record lookups every screen needs, read once."""
    students = service.list_students()
    groups = service.list_groups()
    assessments = service.list_assessments()
    trainer_assessments = tuple(
        assessment for assessment in assessments
        if not assessment.is_self_directed_policy)
    attempts = tuple(service.sync_attempt(a) for a in service.list_attempts())
    return {
        "students": students,
        "students_by_id": {s.student_id: s for s in students},
        "groups": groups,
        "groups_by_id": {g.group_id: g for g in groups},
        "assessments": assessments,
        "trainer_assessments": trainer_assessments,
        "assessments_by_id": {a.assessment_id: a for a in assessments},
        "assignments": service.repository.list_assignments(),
        "memberships": service.list_memberships(),
        "attempts": attempts,
        "attempts_by_id": {a.attempt_id: a for a in attempts},
    }


def _session_rows(service, context, student_id=None, load_sessions=True,
                  limit=None):
    ownerships = service.repository.list_session_ownership(
        student_id=student_id)
    summaries = {s.session_id: s for s in service.session_summaries(
        learner_refs=[o.learner_ref for o in ownerships])}
    if limit is not None:
        ownerships = ownerships[:limit]
    rows = []
    for ownership in ownerships:
        session = (service.load_session(ownership.session_id)
                   if load_sessions else None)
        rows.append(session_row(
            service, ownership, summary=summaries.get(ownership.session_id),
            session=session, students_by_id=context["students_by_id"],
            assessments_by_id=context["assessments_by_id"],
            attempts_by_id=context["attempts_by_id"]))
    return rows


def _analytics_rows(service, student_ids=None):
    """Aggregate metrics over every readable stored session in scope."""
    ownerships = service.repository.list_session_ownership()
    if student_ids is not None:
        wanted = set(student_ids)
        ownerships = [o for o in ownerships if o.student_id in wanted]
    facts = []
    for ownership in ownerships:
        session = service.load_session(ownership.session_id)
        if session is None:
            continue
        facts.append(analytics.session_facts(session))
    return [metric.to_state() for metric in analytics.aggregate(facts)]


# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------

#: How many session rows the overview shows. A dashboard is a summary, and
#: loading every stored session to render one page is not a summary.
DASHBOARD_SESSION_LIMIT = 25


def dashboard(service):
    context = _context(service)
    rows = _session_rows(service, context, limit=DASHBOARD_SESSION_LIMIT)

    all_summaries = service.session_summaries()
    by_status = {"active": 0, "completed": 0, "abandoned": 0}
    for summary in all_summaries:
        if summary.status in by_status:
            by_status[summary.status] += 1

    open_assessments = [a for a in context["trainer_assessments"]
                        if a.status == "open"]
    scheduled = [a for a in context["trainer_assessments"]
                 if a.status == "scheduled"]
    closed = [a for a in context["trainer_assessments"]
              if a.status == "closed"]
    outstanding = [a for a in context["attempts"] if a.is_active]

    cards = [
        {"id": "students", "label": "Students",
         "value": str(len(context["students"])),
         "sub": "%d group%s" % (len(context["groups"]),
                                "" if len(context["groups"]) == 1 else "s")},
        {"id": "sessions", "label": "Sessions recorded",
         "value": str(len(all_summaries)),
         "sub": "%d complete · %d in progress · %d abandoned"
                % (by_status["completed"], by_status["active"],
                   by_status["abandoned"])},
        {"id": "assessments_open", "label": "Assessments open",
         "value": str(len(open_assessments)),
         "sub": "%d scheduled · %d closed" % (len(scheduled), len(closed))},
        {"id": "attempts_outstanding", "label": "Attempts outstanding",
         "value": str(len(outstanding)),
         "sub": "across %d assessment%s"
                % (len({a.assessment_id for a in outstanding}),
                   "" if len({a.assessment_id for a in outstanding}) == 1
                   else "s")},
    ]

    return {
        "trainer": TRAINER_IDENTITY,
        "cards": cards,
        "sessions": rows,
        "session_total": len(all_summaries),
        "metrics": _analytics_rows(service),
        "metric_version": analytics.METRIC_SET_VERSION,
        "interpretation": analytics.INTERPRETATION_LIMIT,
        "outstanding": [
            {
                "attempt_id": attempt.attempt_id,
                "student_id": attempt.student_id,
                "student_name": _name_of(context, attempt.student_id),
                "assessment_id": attempt.assessment_id,
                "assessment_name": _assessment_name(context,
                                                    attempt.assessment_id),
                "attempt_number": attempt.attempt_number,
                "started": attempt.started_at,
                "progress": service.attempt_progress(attempt),
            }
            for attempt in outstanding
        ],
    }


def _name_of(context, student_id):
    student = context["students_by_id"].get(student_id)
    return student.display_name if student is not None else student_id


def _assessment_name(context, assessment_id):
    assessment = context["assessments_by_id"].get(assessment_id)
    return assessment.name if assessment is not None else assessment_id


def _student_groups(context, student_id):
    return [context["groups_by_id"][m.group_id]
            for m in context["memberships"]
            if m.student_id == student_id and m.group_id in context["groups_by_id"]]


def _student_assignments(context, student_id):
    return effective_assignments(
        student_id, context["assignments"], context["memberships"],
        context["groups_by_id"],
        assessments_by_id=context["assessments_by_id"])


def students_overview(service):
    context = _context(service)
    ownerships = service.repository.list_session_ownership()
    sessions_by_student = {}
    for ownership in ownerships:
        sessions_by_student.setdefault(ownership.student_id, []).append(ownership)

    summaries = {s.session_id: s for s in service.session_summaries()}

    rows = []
    for student in context["students"]:
        owned = sessions_by_student.get(student.student_id, [])
        latest = None
        for ownership in owned:
            summary = summaries.get(ownership.session_id)
            if summary is None or summary.status != "completed":
                continue
            session = service.load_session(ownership.session_id)
            score = _score_for(session)
            latest = {"started": ownership.started_at, "score": score}
            break
        rows.append({
            "student": student,
            "groups": _student_groups(context, student.student_id),
            "assignments": [route.to_state()
                            for route in _student_assignments(
                                context, student.student_id)],
            "assignment_names": [
                _assessment_name(context, route.assignment.assessment_id)
                for route in _student_assignments(context, student.student_id)],
            "session_count": len(owned),
            "latest": latest,
        })
    return {"trainer": TRAINER_IDENTITY, "rows": rows,
            "student_total": len(context["students"])}


def student_detail(service, student_id):
    student = service.get_student(student_id)
    if student is None:
        return None
    context = _context(service)
    routes = _student_assignments(context, student_id)
    attempts = [a for a in context["attempts"] if a.student_id == student_id]

    return {
        "trainer": TRAINER_IDENTITY,
        "student": student,
        "groups": _student_groups(context, student_id),
        "assignments": [
            dict(route.to_state(),
                 assessment_name=_assessment_name(
                     context, route.assignment.assessment_id))
            for route in routes],
        "sessions": _session_rows(service, context, student_id=student_id),
        "attempts": [
            dict(service.attempt_state(attempt, learner_safe=False) or {},
                 assessment_name=_assessment_name(context,
                                                  attempt.assessment_id))
            for attempt in attempts],
        "metrics": _analytics_rows(service, student_ids=[student_id]),
        "metric_version": analytics.METRIC_SET_VERSION,
        "interpretation": analytics.INTERPRETATION_LIMIT,
    }


def groups_overview(service):
    context = _context(service)
    rows = []
    for group in context["groups"]:
        members = [context["students_by_id"][m.student_id]
                   for m in context["memberships"]
                   if m.group_id == group.group_id
                   and m.student_id in context["students_by_id"]]
        assigned = [context["assessments_by_id"][a.assessment_id]
                    for a in context["assignments"]
                    if a.target_type == "group"
                    and a.group_id == group.group_id
                    and a.assessment_id in context["assessments_by_id"]]
        rows.append({"group": group, "members": members,
                     "assessments": assigned,
                     "overlaps": _overlaps(context, group)})
    return {"trainer": TRAINER_IDENTITY, "rows": rows}


def _overlaps(context, group):
    member_ids = {m.student_id for m in context["memberships"]
                  if m.group_id == group.group_id}
    out = []
    for other in context["groups"]:
        if other.group_id == group.group_id:
            continue
        shared = sorted(
            _name_of(context, m.student_id) for m in context["memberships"]
            if m.group_id == other.group_id and m.student_id in member_ids)
        if shared:
            out.append({"group": other, "shared": shared})
    return out


def group_detail(service, group_id):
    group = service.get_group(group_id)
    if group is None:
        return None
    context = _context(service)
    member_ids = [m.student_id for m in context["memberships"]
                  if m.group_id == group_id]
    members = []
    for student_id in member_ids:
        student = context["students_by_id"].get(student_id)
        if student is None:
            continue
        members.append({
            "student": student,
            "other_groups": [g for g in _student_groups(context, student_id)
                             if g.group_id != group_id],
        })
    members.sort(key=lambda row: (row["student"].display_name,
                                  row["student"].student_id))

    carried = [
        {"assignment": assignment,
         "assessment": context["assessments_by_id"].get(assignment.assessment_id)}
        for assignment in context["assignments"]
        if assignment.target_type == "group" and assignment.group_id == group_id
    ]
    return {
        "trainer": TRAINER_IDENTITY,
        "group": group,
        "members": members,
        "assessments": [row for row in carried if row["assessment"] is not None],
        "overlaps": _overlaps(context, group),
        "candidates": [s for s in context["students"]
                       if s.student_id not in set(member_ids)],
    }


def assessments_overview(service):
    context = _context(service)
    rows = []
    for assessment in context["trainer_assessments"]:
        groups, students = [], []
        for assignment in context["assignments"]:
            if assignment.assessment_id != assessment.assessment_id:
                continue
            if assignment.target_type == "group":
                group = context["groups_by_id"].get(assignment.group_id)
                if group is not None:
                    groups.append({"group": group, "assignment": assignment})
            else:
                student = context["students_by_id"].get(assignment.student_id)
                if student is not None:
                    students.append({"student": student,
                                     "assignment": assignment})
        attempts = [a for a in context["attempts"]
                    if a.assessment_id == assessment.assessment_id]
        rows.append({
            "assessment": assessment,
            "groups": groups,
            "students": students,
            "attempts_total": len(attempts),
            "attempts_active": sum(1 for a in attempts if a.is_active),
            "attempts_completed": sum(1 for a in attempts
                                      if a.status == "completed"),
            "attempts_abandoned": sum(1 for a in attempts
                                      if a.status == "abandoned"),
        })
    return {
        "trainer": TRAINER_IDENTITY,
        "rows": rows,
        "students": context["students"],
        "groups": context["groups"],
        "assessments": context["trainer_assessments"],
    }
