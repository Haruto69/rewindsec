"""Flask routes for the RewindSec 2.0 learner and trainer surfaces.

Batch 2 changed what this blueprint is. It began as a GET-only presentation
prototype whose world was a fixture document. It now also mounts the learner
workstation API (:mod:`rewindsec.prototype.api`), which is server-authoritative
and does persist: a learner action is a ``POST`` that reaches a real
:class:`~rewindsec.domain.session.SimulationSession` through the workstation
application layer.

Two things follow, and both are deliberate:

* The state-changing routes are all ``POST`` under ``/prototype/api/``, so the
  application's global CSRF gate (``security.init_csrf``) covers every one of
  them with no exemption of any kind. Nothing here weakens it.
* The **trainer** surfaces are still fixture-backed, and the results screen
  still computes its demonstration numbers in the browser. Those belong to
  Batches 4 and 5. What is real after this batch is the learner workstation.

The blueprint is mounted under one prefix and owns one template directory and
one static directory. Deleting this package, ``templates/prototype/``,
``static/prototype/`` and the ``register_blueprint`` call in ``app.py`` removes
the entire mock layer with nothing left behind.

Nothing here touches the database, the sandbox, the telemetry ledger, the
deterministic core, or any v1 module.
"""

from flask import Blueprint, abort, jsonify, render_template, request, session

from rewindsec.prototype import fixtures
from rewindsec.prototype.api import SESSION_KEY, register_workstation_api

#: Endpoints a learner actually sits in front of during a session.
#:
#: The learner integrity controls (clipboard restriction, screenshot notice,
#: display-capture policy) are attached from here rather than from a template,
#: so the scope is one list in one place and a new screen has to be added to it
#: deliberately. The trainer console and the fixture API are not on it, and
#: neither is ``/prototype/`` itself: that page is the reviewer's entry point
#: to the prototype -- a description of the thing, not the thing -- and
#: restricting the clipboard on documentation would be pure friction.
LEARNER_ENDPOINTS = frozenset({
    "prototype.entry",
    "prototype.workstation",
    "prototype.results",
})


def create_prototype_blueprint(service_factory=None, updates=None):
    """Build the ``/prototype`` blueprint.

    A factory rather than a module-level object so the application decides
    when -- and whether -- these surfaces exist at all.

    ``service_factory`` and ``updates`` wire the learner workstation API to a
    configured :class:`~rewindsec.workstation.service.WorkstationService` and
    its update broker. Passed in rather than imported so this module never
    reaches for the application object, and so a test can mount the API on a
    service backed by a throwaway database.
    """
    bp = Blueprint("prototype", __name__, url_prefix="/prototype")

    if service_factory is not None:
        register_workstation_api(bp, service_factory, updates)

    # -- shared template context ------------------------------------------

    #: What each screen is actually backed by, stated on the screen itself.
    #:
    #: Batch 2 made the learner workstation real, and left the trainer console
    #: and the numeric part of the debrief as authored demonstrations. One
    #: banner saying "prototype" everywhere would now be wrong in one
    #: direction on the workstation and right in the other on the trainer, so
    #: it says which is which. A reviewer must never have to guess whether
    #: what they are looking at is implemented.
    BANNERS = {
        "workstation": (
            "RewindSec 2.0 — this workstation runs on a real persisted "
            "simulation session. Scoring, the threat engine and the trainer "
            "records are not implemented yet."),
        "results": (
            "The timeline, decisions, consequence chains and evidence on this "
            "page come from your real session. The numeric scores are an "
            "authored demonstration, not RewindSec 2.0 scoring."),
        "trainer": (
            "Trainer console — fixture data. Student, group, assessment and "
            "analytics records are not implemented yet."),
        "entry": (
            "RewindSec 2.0. Entering the workstation creates a real, "
            "persisted training session you can leave and come back to."),
    }

    def _banner_for(endpoint):
        if endpoint == "prototype.workstation":
            return BANNERS["workstation"]
        if endpoint == "prototype.results":
            return BANNERS["results"]
        if endpoint == "prototype.entry":
            return BANNERS["entry"]
        return BANNERS["trainer"]

    @bp.context_processor
    def _prototype_context():
        """Values every template under this blueprint needs."""
        return {
            "prototype_banner": _banner_for(request.endpoint),
            "org": fixtures.world.ORGANIZATION,
            "learner": fixtures.world.LEARNER,
            "integrity_scope": (
                "learner" if request.endpoint in LEARNER_ENDPOINTS else "none"),
        }

    # -- learner integrity controls ---------------------------------------

    @bp.after_request
    def _learner_capture_policy(response):
        """Refuse display capture initiated by a learner page itself.

        ``display-capture=()`` stops this document from calling
        ``getDisplayMedia`` -- so nothing in the workstation can quietly record
        the screen, and a script injected into it could not either. It does
        *not* stop the operating system's own screenshot tools, and it is not
        claimed to.

        Registered on the blueprint, so it reaches prototype responses only.
        Restricting it further to the learner endpoints keeps the trainer
        console and the v1 application on exactly the headers they had.
        """
        if request.endpoint in LEARNER_ENDPOINTS:
            response.headers["Permissions-Policy"] = "display-capture=()"
        return response

    # -- learner surfaces --------------------------------------------------

    @bp.route("/")
    def index():
        """Entry point for the manual product review."""
        return render_template(
            "prototype/index.html",
            safety=fixtures.safety_report())

    @bp.route("/start")
    def entry():
        """Focus and mode selection. No Easy/Medium/Hard control exists."""
        return render_template(
            "prototype/entry.html",
            focus_options=fixtures.scen.FOCUS_OPTIONS,
            modes=fixtures.scen.MODES,
            cadence=fixtures.scen.CADENCE)

    @bp.route("/workstation")
    def workstation():
        """The synthetic workstation shell.

        Renders an empty shell. Every fact in it arrives from
        ``/prototype/api/session``, projected from a real persisted
        :class:`~rewindsec.domain.session.SimulationSession`, and is drawn by
        ``static/prototype/workstation.js``.

        ``has_session`` is a boot hint and nothing more: it saves the client
        from probing an endpoint that answers 404 on every first entry, which
        would put a red line in the console of an otherwise healthy page. It
        carries no simulation state, and the client does not trust it -- if it
        says yes and the session has since gone, the ordinary "no session"
        path still runs.
        """
        return render_template("prototype/workstation.html",
                               has_session=bool(session.get(SESSION_KEY)))

    @bp.route("/results")
    def results():
        """Learner debrief.

        The page is rendered from the run state the workstation left in
        ``sessionStorage``. Opened directly, it falls back to a representative
        fixture session so the screen is always reviewable.
        """
        return render_template(
            "prototype/results.html",
            dimensions=fixtures.scen.SCORE_DIMENSIONS)

    # -- trainer surfaces --------------------------------------------------

    @bp.route("/trainer")
    def trainer_dashboard():
        snapshot = fixtures.trainer_snapshot()
        sessions = sorted(snapshot["sessions"], key=lambda s: s["started"],
                          reverse=True)
        return render_template(
            "prototype/trainer_dashboard.html",
            snapshot=snapshot, sessions=sessions,
            active="dashboard")

    @bp.route("/trainer/students")
    def trainer_students():
        snapshot = fixtures.trainer_snapshot()
        rows = []
        for student in snapshot["students"]:
            detail = fixtures.student_detail(student["id"])
            completed = [s for s in detail["sessions"]
                         if s["status"] == "complete"]
            latest = completed[-1] if completed else None
            rows.append({
                "student": student,
                "groups": detail["groups"],
                "sessions": detail["sessions"],
                "assignments": detail["assignments"],
                "latest": latest,
            })
        return render_template(
            "prototype/trainer_students.html",
            snapshot=snapshot, rows=rows, active="students")

    @bp.route("/trainer/students/<student_id>")
    def trainer_student(student_id):
        detail = fixtures.student_detail(student_id)
        if detail is None:
            abort(404)
        return render_template(
            "prototype/trainer_student.html",
            snapshot=fixtures.trainer_snapshot(), detail=detail,
            active="students")

    @bp.route("/trainer/groups")
    def trainer_groups():
        snapshot = fixtures.trainer_snapshot()
        rows = [fixtures.group_detail(group["id"])
                for group in snapshot["groups"]]
        return render_template(
            "prototype/trainer_groups.html",
            snapshot=snapshot, rows=rows, active="groups")

    @bp.route("/trainer/groups/<group_id>")
    def trainer_group(group_id):
        detail = fixtures.group_detail(group_id)
        if detail is None:
            abort(404)
        return render_template(
            "prototype/trainer_group.html",
            snapshot=fixtures.trainer_snapshot(), detail=detail,
            active="groups")

    @bp.route("/trainer/assessments")
    def trainer_assessments():
        snapshot = fixtures.trainer_snapshot()
        rows = []
        for assessment in snapshot["assessments"]:
            groups = []
            students = []
            for row in snapshot["assignments"]:
                if row["assessment_id"] != assessment["id"]:
                    continue
                if row["source"] == "group":
                    group = snapshot["index"]["groups_by_id"].get(
                        row["group_id"])
                    if group:
                        groups.append(group)
                else:
                    student = snapshot["index"]["students_by_id"].get(
                        row["student_id"])
                    if student:
                        students.append(student)
            rows.append({"assessment": assessment, "groups": groups,
                         "students": students})
        return render_template(
            "prototype/trainer_assessments.html",
            snapshot=snapshot, rows=rows, active="assessments")

    # -- fixture API -------------------------------------------------------

    @bp.route("/api/world")
    def api_world():
        """The authored content document, for the results and trainer screens.

        This was the workstation's world in the UI prototype. It is not any
        more: the workstation now reads
        ``/prototype/api/session``, which is projected from a real
        :class:`~rewindsec.domain.session.SimulationSession` and carries no
        authored ground truth.

        What is left here still carries the ``analysis`` blocks -- decision
        classes, dispositions, evidence models -- because the debrief screen
        renders from them. So it is **closed while a session is running**. A
        learner in the middle of an attempt cannot read the answer key by
        opening a second tab, and the results screen, which runs after the
        attempt has ended, is unaffected.
        """
        if session.get(SESSION_KEY) and service_factory is not None:
            try:
                simulation = service_factory().load(session[SESSION_KEY])
            except Exception:
                simulation = None
            if simulation is not None and simulation.is_active:
                return jsonify({"error": {
                    "code": "forbidden",
                    "message": "Not available while a session is running.",
                }}), 403
        return jsonify(fixtures.learner_snapshot())

    @bp.route("/api/assignment-provenance")
    def api_assignment_provenance():
        """Where a student already receives an assessment from, if anywhere.

        Read-only lookup behind the duplicate-assignment warning in
        architecture §27. It answers "where did this come from", not "is it
        already assigned", because the trainer cannot decide anything useful
        from a boolean.
        """
        assessment_id = request.args.get("assessment_id", "")
        student_id = request.args.get("student_id", "")
        if not assessment_id or not student_id:
            return jsonify({"ok": False,
                            "error": "assessment_id and student_id required"}), 400

        snapshot = fixtures.trainer_snapshot()
        if assessment_id not in snapshot["index"]["assessments_by_id"]:
            return jsonify({"ok": False, "error": "unknown assessment"}), 404
        if student_id not in snapshot["index"]["students_by_id"]:
            return jsonify({"ok": False, "error": "unknown student"}), 404

        sources = fixtures.existing_assignment_sources(assessment_id,
                                                       student_id)
        student = snapshot["index"]["students_by_id"][student_id]
        assessment = snapshot["index"]["assessments_by_id"][assessment_id]
        return jsonify({
            "ok": True,
            "student": {"id": student["id"], "name": student["name"]},
            "assessment": {"id": assessment["id"], "name": assessment["name"]},
            "existing_sources": sources,
            "duplicate": bool(sources),
        })

    return bp
