"""The HTTP adapter for the trainer console.

The trainer-side counterpart to :mod:`rewindsec.prototype.api`, and it holds
the same line: this module knows what a request and a status code are, and
:mod:`rewindsec.management.service` knows everything else. No rule is decided
here, no record is built here, and no figure is computed here.

Authorization
-------------
Every route registered by this module -- without exception -- is wrapped in
the ``require_trainer`` guard the application hands in. That guard is the
repository's real instructor authentication (``security.require_instructor``:
a session flag established by a password held in the environment, with login
throttling and session rotation). It is **not** "the path starts with
``/trainer``": the decorator is applied here, in one place, to every view
function this module creates, and the blueprint factory fails closed with a
guard that refuses everything when no real one is supplied -- so a deployment
with instructor authentication unconfigured exposes no trainer data at all.

Nothing here relaxes CSRF. Every state-changing route is a POST and is
covered by the application's global gate exactly like every other unsafe
request; the console reads the token from the meta tag the server rendered.

Leakage
-------
These endpoints legitimately carry finalized scores, because a trainer is
authorized to see them. That is precisely why they are gated: adding a
trainer data API must not create a second, differently-filtered way for
session truth to reach a browser. A learner's ordinary session authorization
reaches none of these routes -- a learner cookie carries no instructor flag --
and no learner-facing endpoint imports
:mod:`rewindsec.management.projection`.
"""

import json

from flask import jsonify, request

from rewindsec.management import assessment_policy
from rewindsec.management.ports import ManagementError, NotFoundError
from rewindsec.management.projection import (assessments_overview, dashboard,
                                             group_detail, groups_overview,
                                             student_detail, students_overview)
from rewindsec.management.records import (ASSESSMENT_STATUSES,
                                          ASSIGNMENT_TARGETS, STUDENT_STATUSES)
from rewindsec.management.service import (DuplicateAssignment,
                                          ManagementRefused, TRAINER_ACTOR)
from rewindsec.workstation.content import index as ix

__all__ = ["register_trainer_api", "MAX_TRAINER_BODY_BYTES"]

#: The trainer console posts short forms. A generous ceiling that is still far
#: below anything that could be used to make the server do work.
MAX_TRAINER_BODY_BYTES = 16 * 1024


def _error(code, message, status, detail=None):
    payload = {"error": {"code": code, "message": message}}
    if detail:
        payload["error"]["detail"] = detail
    return jsonify(payload), status


def register_trainer_api(bp, service_factory, require_trainer):
    """Attach the trainer API to the prototype blueprint.

    ``service_factory`` is a zero-argument callable returning the configured
    :class:`~rewindsec.management.service.ManagementService`.
    ``require_trainer`` is the authorization decorator; every route below is
    wrapped in it.
    """

    def body():
        length = request.content_length
        if length is not None and length > MAX_TRAINER_BODY_BYTES:
            raise ManagementRefused("That request is too large.",
                                    code="too_large")
        raw = request.get_data(cache=False, as_text=True)
        if len(raw.encode("utf-8")) > MAX_TRAINER_BODY_BYTES:
            raise ManagementRefused("That request is too large.",
                                    code="too_large")
        if not raw.strip():
            return {}
        try:
            payload = json.loads(raw)
        except ValueError:
            raise ManagementRefused("That request was not valid JSON.",
                                    code="invalid_json")
        if not isinstance(payload, dict):
            raise ManagementRefused("The request body must be a JSON object.",
                                    code="invalid_body")
        return payload

    def field(payload, name, allowed, required=True, default=None):
        unknown = sorted(set(payload) - set(allowed) - {"csrf_token"})
        if unknown:
            raise ManagementRefused(
                "Unrecognised field(s): %s." % ", ".join(unknown),
                code="unknown_field")
        value = payload.get(name, default)
        if required and (value is None or value == ""):
            raise ManagementRefused("%s is required." % name,
                                    code="missing_field")
        return value

    def text(value, name, limit=200, allow_none=True):
        if value is None or value == "":
            if allow_none:
                return None
            raise ManagementRefused("%s is required." % name,
                                    code="missing_field")
        if not isinstance(value, str):
            raise ManagementRefused("%s must be text." % name,
                                    code="invalid_field")
        value = value.strip()
        if len(value) > limit:
            raise ManagementRefused(
                "%s must be at most %d characters." % (name, limit),
                code="invalid_field")
        return value or None

    def whole_number(value, name, minimum, maximum, default=None):
        if value is None:
            value = default
        if isinstance(value, str) and value.strip().isdigit():
            value = int(value.strip())
        if isinstance(value, bool) or not isinstance(value, int):
            raise ManagementRefused("%s must be a whole number." % name,
                                    code="invalid_field")
        if not (minimum <= value <= maximum):
            raise ManagementRefused(
                "%s must be between %d and %d." % (name, minimum, maximum),
                code="invalid_field")
        return value

    def choice(value, name, options, default=None):
        if value is None:
            value = default
        if value not in options:
            raise ManagementRefused(
                "%s must be one of %s." % (name, ", ".join(options)),
                code="invalid_field")
        return value

    def route(rule, endpoint, methods=("GET",)):
        """Register one trainer route, authorization-wrapped, no exceptions.

        Every route this module creates goes through here, so there is no way
        to add an unguarded one by forgetting a decorator: the guard is
        applied by the registration helper, not by the view.
        """
        def decorate(view):
            def guarded(*args, **kwargs):
                try:
                    return view(*args, **kwargs)
                except DuplicateAssignment as exc:
                    return _error(exc.code, exc.message, 409, exc.detail)
                except ManagementRefused as exc:
                    return _error(exc.code, exc.message, 400, exc.detail)
                except NotFoundError as exc:
                    return _error("not_found", str(exc), 404)
                except ManagementError as exc:
                    return _error("conflict", str(exc), 409)
            guarded.__name__ = endpoint
            bp.add_url_rule(rule, endpoint, require_trainer(guarded),
                            methods=list(methods))
            return view
        return decorate

    # -- read models -------------------------------------------------------

    @route("/api/trainer/dashboard", "api_trainer_dashboard")
    def api_dashboard():
        return jsonify(dashboard(service_factory()))

    @route("/api/trainer/students", "api_trainer_students")
    def api_students():
        service = service_factory()
        overview = students_overview(service)
        return jsonify({"students": [
            {"id": row["student"].student_id,
             "name": row["student"].display_name,
             "reference": row["student"].reference,
             "cohort": row["student"].cohort,
             "status": row["student"].status,
             "origin": row["student"].origin,
             "groups": [{"id": g.group_id, "name": g.name}
                        for g in row["groups"]],
             "assignments": row["assignments"],
             "session_count": row["session_count"],
             "latest": row["latest"]}
            for row in overview["rows"]]})

    @route("/api/trainer/students/<student_id>", "api_trainer_student")
    def api_student(student_id):
        detail = student_detail(service_factory(), student_id)
        if detail is None:
            return _error("not_found", "No such student.", 404)
        return jsonify({
            "student": {"id": detail["student"].student_id,
                        "name": detail["student"].display_name,
                        "reference": detail["student"].reference,
                        "cohort": detail["student"].cohort,
                        "status": detail["student"].status},
            "groups": [{"id": g.group_id, "name": g.name}
                       for g in detail["groups"]],
            "assignments": detail["assignments"],
            "sessions": detail["sessions"],
            "attempts": detail["attempts"],
            "metrics": detail["metrics"],
        })

    @route("/api/trainer/groups", "api_trainer_groups")
    def api_groups():
        overview = groups_overview(service_factory())
        return jsonify({"groups": [
            {"id": row["group"].group_id, "name": row["group"].name,
             "description": row["group"].description,
             "created_at": row["group"].created_at,
             "members": [{"id": s.student_id, "name": s.display_name}
                         for s in row["members"]],
             "assessments": [{"id": a.assessment_id, "name": a.name,
                              "required_interactions": a.required_interactions}
                             for a in row["assessments"]]}
            for row in overview["rows"]]})

    @route("/api/trainer/assessments", "api_trainer_assessments")
    def api_assessments():
        overview = assessments_overview(service_factory())
        return jsonify({
            "assessment_runtime_policy_version":
                assessment_policy.ASSESSMENT_RUNTIME_POLICY_VERSION,
            "capacity_by_focus": assessment_policy.capacity_by_focus(),
            "assessments": [
            {"id": row["assessment"].assessment_id,
             "name": row["assessment"].name,
             "focus": row["assessment"].focus,
             "required_interactions": row["assessment"].required_interactions,
             "status": row["assessment"].status,
             "max_attempts": row["assessment"].max_attempts,
             "retry_policy": row["assessment"].retry_policy,
             "window_label": row["assessment"].window_label,
             "note": row["assessment"].note,
             "definition_version": row["assessment"].definition_version,
             "groups": [{"id": entry["group"].group_id,
                         "name": entry["group"].name,
                         "assignment_id": entry["assignment"].assignment_id}
                        for entry in row["groups"]],
             "students": [{"id": entry["student"].student_id,
                           "name": entry["student"].display_name,
                           "assignment_id": entry["assignment"].assignment_id}
                          for entry in row["students"]],
             "attempts_total": row["attempts_total"],
             "attempts_active": row["attempts_active"],
             "attempts_completed": row["attempts_completed"]}
            for row in overview["rows"]]})

    # -- writes ------------------------------------------------------------

    @route("/api/trainer/students", "api_trainer_create_student",
           methods=("POST",))
    def api_create_student():
        payload = body()
        allowed = ("display_name", "reference", "cohort", "status")
        name = text(field(payload, "display_name", allowed), "display_name",
                    120, allow_none=False)
        student = service_factory().create_student(
            display_name=name,
            reference=text(payload.get("reference"), "reference", 64),
            cohort=text(payload.get("cohort"), "cohort", 64),
            status=choice(payload.get("status"), "status", STUDENT_STATUSES,
                          default="active"))
        return jsonify({"ok": True, "student": {
            "id": student.student_id, "name": student.display_name,
            "reference": student.reference, "cohort": student.cohort,
            "status": student.status}}), 201

    #: Deleting a student removes them from the active roster; the record
    #: itself is deliberately retained so every stored session, attempt and
    #: result stays resolvable. The message says exactly that rather than
    #: claiming an erasure that did not happen. There is no force flag, no
    #: purge variant and no "also remove history" option in this payload,
    #: because there is no such operation behind it. The response never
    #: carries a learner reference, an enrolment code, or an id the console
    #: did not already hold.
    _DELETE_MESSAGES = {
        "removed_from_roster": "Student removed from the active roster.",
    }

    @route("/api/trainer/students/<student_id>/delete",
           "api_trainer_delete_student", methods=("POST",))
    def api_delete_student(student_id):
        payload = body()
        confirm = field(payload, "confirm", ("confirm",))
        if confirm is not True:
            raise ManagementRefused(
                "Confirm the deletion before continuing.",
                code="confirmation_required")
        result = service_factory().delete_student(student_id)
        return jsonify({
            "ok": True,
            "kind": result["kind"],
            "student_id": result["student_id"],
            "message": _DELETE_MESSAGES[result["kind"]],
        })

    @route("/api/trainer/groups", "api_trainer_create_group",
           methods=("POST",))
    def api_create_group():
        payload = body()
        allowed = ("name", "description")
        name = text(field(payload, "name", allowed), "name", 120,
                    allow_none=False)
        group = service_factory().create_group(
            name=name,
            description=text(payload.get("description"), "description", 400),
            created_by=TRAINER_ACTOR)
        return jsonify({"ok": True, "group": {
            "id": group.group_id, "name": group.name,
            "description": group.description,
            "created_at": group.created_at}}), 201

    @route("/api/trainer/groups/<group_id>/members",
           "api_trainer_add_member", methods=("POST",))
    def api_add_member(group_id):
        payload = body()
        student_id = field(payload, "student_id", ("student_id",))
        service_factory().add_member(group_id, student_id)
        return jsonify({"ok": True, "group_id": group_id,
                        "student_id": student_id}), 201

    @route("/api/trainer/groups/<group_id>/members/remove",
           "api_trainer_remove_member", methods=("POST",))
    def api_remove_member(group_id):
        payload = body()
        student_id = field(payload, "student_id", ("student_id",))
        removed = service_factory().remove_member(group_id, student_id)
        return jsonify({"ok": True, "removed": bool(removed)})

    @route("/api/trainer/assessments", "api_trainer_create_assessment",
           methods=("POST",))
    def api_create_assessment():
        payload = body()
        allowed = ("name", "focus", "required_interactions", "status",
                   "max_attempts", "window_label", "note")
        name = text(field(payload, "name", allowed), "name", 120,
                    allow_none=False)
        focus = choice(payload.get("focus"), "focus", ix.FOCUS_IDS,
                       default="mixed")
        capacity = assessment_policy.required_interaction_capacity(focus)
        assessment = service_factory().create_assessment(
            name=name,
            focus=focus,
            required_interactions=whole_number(
                payload.get("required_interactions"),
                "required_interactions", 1, capacity, default=None),
            status=choice(payload.get("status"), "status",
                          ASSESSMENT_STATUSES, default="open"),
            max_attempts=whole_number(payload.get("max_attempts"),
                                      "max_attempts", 1, 20, default=1),
            window_label=text(payload.get("window_label"), "window_label", 160),
            note=text(payload.get("note"), "note", 400),
            created_by=TRAINER_ACTOR)
        return jsonify({"ok": True, "assessment": {
            "id": assessment.assessment_id, "name": assessment.name,
            "focus": assessment.focus,
            "required_interactions": assessment.required_interactions,
            "status": assessment.status,
            "max_attempts": assessment.max_attempts,
            "retry_policy": assessment.retry_policy,
            "window_label": assessment.window_label,
            "note": assessment.note,
            "definition_version": assessment.definition_version,
            "assessment_runtime_policy_version":
                assessment_policy.ASSESSMENT_RUNTIME_POLICY_VERSION,
            "required_interactions_capacity": capacity}}), 201

    # -- assignment provenance and creation --------------------------------

    @route("/api/trainer/assignment-sources", "api_trainer_assignment_sources")
    def api_assignment_sources():
        """Where a student already receives an assessment from, if anywhere.

        Answers "where did this come from", not "is it already assigned",
        because the trainer cannot decide anything useful from a boolean. The
        ``duplicate`` field is present only as a convenience for rendering;
        the sources are the answer.
        """
        service = service_factory()
        assessment_id = request.args.get("assessment_id", "")
        student_id = request.args.get("student_id", "")
        if not assessment_id or not student_id:
            return _error("missing_field",
                          "assessment_id and student_id are required.", 400)
        assessment = service.get_assessment(assessment_id)
        if assessment is None:
            return _error("not_found", "No such assessment.", 404)
        student = service.require_roster_student(student_id)
        sources = service.assignment_sources(assessment_id, student_id)
        return jsonify({
            "ok": True,
            "student": {"id": student.student_id,
                        "name": student.display_name},
            "assessment": {"id": assessment.assessment_id,
                           "name": assessment.name},
            "existing_sources": sources,
            "duplicate": bool(sources),
        })

    @route("/api/trainer/assignment-duplicates",
           "api_trainer_assignment_duplicates")
    def api_assignment_duplicates():
        """Every learner a proposed target would double-assign, with sources.

        A group target is resolved to its current members here, on the server,
        so assigning a group one of whose members already holds the assessment
        raises exactly the same warning a direct assignment would.
        """
        service = service_factory()
        assessment_id = request.args.get("assessment_id", "")
        target_type = request.args.get("target_type", "")
        target_id = request.args.get("target_id", "")
        if not assessment_id or not target_id:
            return _error("missing_field",
                          "assessment_id and target_id are required.", 400)
        target_type = choice(target_type, "target_type", ASSIGNMENT_TARGETS)
        duplicates = service.duplicate_preview(assessment_id, target_type,
                                               target_id)
        return jsonify({"ok": True, "duplicates": duplicates,
                        "duplicate": bool(duplicates)})

    @route("/api/trainer/assignments", "api_trainer_create_assignment",
           methods=("POST",))
    def api_create_assignment():
        """Create one assignment, refusing an unconfirmed duplicate.

        The confirmation is server-side input, and it is checked here against
        the server's own duplicate resolution -- a dialog having been shown in
        a browser proves nothing. Without ``confirm_duplicate``, a request
        that would duplicate an existing route is answered ``409`` carrying
        every existing route for every affected learner, and **nothing is
        written**.

        ``request_id`` is the client's idempotency token. A retried submission
        of the same operation resolves to the assignment already created; it
        never manufactures a second one. A *deliberate* second assignment is a
        different operation, with its own token and its own explicit
        confirmation, and it produces a separate row that keeps its own
        provenance -- the first route is never replaced or merged away.
        """
        payload = body()
        allowed = ("assessment_id", "target_type", "target_id",
                   "confirm_duplicate", "request_id")
        assessment_id = field(payload, "assessment_id", allowed)
        target_id = field(payload, "target_id", allowed)
        target_type = choice(payload.get("target_type"), "target_type",
                             ASSIGNMENT_TARGETS)
        confirm = payload.get("confirm_duplicate", False)
        if not isinstance(confirm, bool):
            raise ManagementRefused(
                "confirm_duplicate must be true or false.",
                code="invalid_field")
        request_id = text(payload.get("request_id"), "request_id", 80)

        assignment, replayed = service_factory().assign(
            assessment_id, target_type, target_id,
            confirm_duplicate=confirm, request_id=request_id,
            created_by=TRAINER_ACTOR)
        return jsonify({
            "ok": True,
            "replayed": replayed,
            "assignment": {
                "id": assignment.assignment_id,
                "assessment_id": assignment.assessment_id,
                "source": assignment.source,
                "student_id": assignment.student_id,
                "group_id": assignment.group_id,
                "created_at": assignment.created_at,
                "created_by": assignment.created_by,
                "confirmed_duplicate": assignment.confirmed_duplicate,
            },
        }), (200 if replayed else 201)

    # -- enrolment ---------------------------------------------------------
    #
    # A trainer mints one single-use code and gives it to one learner. That
    # code is the only thing a browser needs to become that student, and it
    # works exactly once. The learner's own persistent ``learner_ref`` is
    # never minted here, never returned here and never shown on any screen:
    # it is the token every one of that person's sessions is owned by, and
    # anybody who saw it could claim their whole history. The code is a
    # different, disposable secret that exists only to be spent.

    @route("/api/trainer/students/<student_id>/enrollment-code",
           "api_trainer_create_enrollment_code", methods=("POST",))
    def api_create_enrollment_code(student_id):
        body()
        code = service_factory().create_enrollment_code(student_id)
        return jsonify({"ok": True, "enrollment": {
            "code": code.code,
            "student_id": code.student_id,
            "created_at": code.created_at,
            "status": code.status,
        }}), 201

    @route("/api/trainer/students/<student_id>/enrollment",
           "api_trainer_enrollment_status")
    def api_enrollment_status(student_id):
        service = service_factory()
        student = service.require_roster_student(student_id)
        codes = service.enrollment_codes_for_student(student_id)
        return jsonify({
            "student_id": student.student_id,
            # Whether this student has been claimed by a browser -- never the
            # reference that claimed them.
            "enrolled": student.learner_ref is not None,
            "codes": [{"code_id": row.code_id, "status": row.status,
                       "created_at": row.created_at,
                       "claimed_at": row.claimed_at}
                      for row in codes],
        })

    @route("/api/trainer/students/<student_id>/enrollment/reset",
           "api_trainer_reset_enrollment", methods=("POST",))
    def api_reset_enrollment(student_id):
        payload = body()
        confirm = field(payload, "confirm", ("confirm",))
        if confirm is not True:
            raise ManagementRefused(
                "Confirm the enrollment reset before continuing.",
                code="confirmation_required")
        student, changed = service_factory().reset_enrollment(student_id)
        return jsonify({"ok": True, "reset": bool(changed),
                        "student_id": student.student_id,
                        "enrolled": False})

    # -- attempts and results ----------------------------------------------

    @route("/api/trainer/attempts", "api_trainer_attempts")
    def api_attempts():
        service = service_factory()
        student_id = request.args.get("student_id") or None
        assessment_id = request.args.get("assessment_id") or None
        if student_id is not None:
            service.require_roster_student(student_id)
        attempts = [service.sync_attempt(a) for a in
                    service.list_attempts(student_id=student_id,
                                          assessment_id=assessment_id)]
        return jsonify({"attempts": [
            service.attempt_state(attempt, learner_safe=False)
            for attempt in attempts]})
