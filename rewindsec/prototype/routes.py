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
* The **trainer** surfaces are real as of Batch 5. Every student, group,
  assessment, assignment, attempt, session row and analytics figure on them
  comes from persisted RewindSec 2.0 records, resolved through
  :mod:`rewindsec.management`. They are authorization-gated: the whole trainer
  surface, pages and API alike, is behind the application's real instructor
  authentication, injected as ``require_trainer`` rather than inferred from a
  URL prefix, and the blueprint fails closed when no guard is supplied.
  ``trainer_fixtures.py`` survives only for standalone visual development and
  is imported by no production trainer route.

The blueprint is mounted under one prefix and owns one template directory and
one static directory. Deleting this package, ``templates/prototype/``,
``static/prototype/`` and the ``register_blueprint`` call in ``app.py`` removes
the entire mock layer with nothing left behind.

Nothing here touches the database, the sandbox, the telemetry ledger, the
deterministic core, or any v1 module.
"""

from flask import (Blueprint, abort, jsonify, redirect, render_template,
                   request, session)

from rewindsec.management import assessment_policy
from rewindsec.management import projection as trainer_view
from rewindsec.prototype import fixtures
from rewindsec.prototype.api import (SELF_DIRECTED_MODES, SESSION_KEY,
                                     register_workstation_api)
from rewindsec.prototype.trainer_api import register_trainer_api

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


def create_prototype_blueprint(service_factory=None, updates=None,
                               management_factory=None,
                               require_trainer=None):
    """Build the ``/prototype`` blueprint.

    A factory rather than a module-level object so the application decides
    when -- and whether -- these surfaces exist at all.

    ``service_factory`` and ``updates`` wire the learner workstation API to a
    configured :class:`~rewindsec.workstation.service.WorkstationService` and
    its update broker. Passed in rather than imported so this module never
    reaches for the application object, and so a test can mount the API on a
    service backed by a throwaway database.

    ``management_factory`` is the same arrangement for the Batch 5
    :class:`~rewindsec.management.service.ManagementService`, and
    ``require_trainer`` is the authorization decorator every trainer surface
    is wrapped in. Both are injected rather than imported: this module has no
    business knowing how this deployment authenticates a trainer, and a test
    can mount the console on a throwaway database with a guard of its own.

    **Fail closed.** When ``require_trainer`` is not supplied, the default
    guard below refuses every trainer request. An unconfigured deployment
    therefore exposes no student, group, assessment or result data at all --
    the same posture ``security.instructor_auth_configured`` already takes for
    the v1 dashboard.
    """
    bp = Blueprint("prototype", __name__, url_prefix="/prototype")

    if require_trainer is None:
        require_trainer = _refuse_all

    if service_factory is not None:
        register_workstation_api(bp, service_factory, updates,
                                 management_factory=management_factory)

    if management_factory is not None:
        register_trainer_api(bp, management_factory, require_trainer)

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
            "simulation session, driven by the training engine and scored by "
            "the RewindSec 2.0 rubric when it ends."),
        "results": (
            "The timeline, decisions, consequence chains, evidence and the six "
            "dimension scores on this page all come from your real session, "
            "scored once by the RewindSec 2.0 rubric when it ended."),
        "trainer": (
            "Trainer console — real persisted RewindSec 2.0 records. Students, "
            "groups, assessments, assignments, attempts and results are "
            "stored; every analytics figure is derived from stored sessions, "
            "and a figure that cannot be derived is shown as unavailable "
            "rather than estimated."),
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
        """Focus and mode selection, plus enrolment. No difficulty control.

        The mode list is the architecture-owned self-directed vocabulary:
        Practice, Simulation and Assessment.  The Assessment choice delegates
        to the server-owned Attempt policy; it never creates a bare
        Assessment-mode TrainingSession.

        The assigned assessments and the enrolment state on this page are
        fetched from the real learner API by the page's own script; nothing
        about who this browser is, or what they have been assigned, is
        rendered from a fixture.
        """
        modes = [mode for mode in fixtures.scen.MODES
                 if mode["id"] in SELF_DIRECTED_MODES]
        return render_template(
            "prototype/entry.html",
            focus_options=fixtures.scen.FOCUS_OPTIONS,
            modes=modes,
            assessments_available=management_factory is not None,
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
    #
    # Real as of Batch 5. Every value on these pages comes from persisted
    # RewindSec 2.0 records through ``rewindsec.management.projection``; none
    # of them reads ``trainer_fixtures``. Where a figure cannot be derived
    # from stored data the projection returns ``None`` and the template shows
    # a dash -- a fixture number presented as a measurement is the one thing
    # these screens must never do.
    #
    # Each route is wrapped in ``require_trainer`` explicitly. The guard is
    # not inferred from the ``/trainer`` prefix: a page that was authorized
    # because of its URL would lose its authorization the moment somebody
    # moved it.

    def trainer_page(rule, endpoint):
        def decorate(view):
            bp.add_url_rule(rule, endpoint, require_trainer(view),
                            methods=["GET"])
            return view
        return decorate

    def _require_console():
        if management_factory is None:
            # No management service configured: the console has nothing real
            # to show, and showing something unreal is not the alternative.
            abort(503)
        return management_factory()

    @trainer_page("/trainer", "trainer_dashboard")
    def trainer_dashboard():
        return render_template(
            "prototype/trainer_dashboard.html",
            view=trainer_view.dashboard(_require_console()),
            active="dashboard")

    @trainer_page("/trainer/students", "trainer_students")
    def trainer_students():
        return render_template(
            "prototype/trainer_students.html",
            view=trainer_view.students_overview(_require_console()),
            active="students")

    @trainer_page("/trainer/students/<student_id>", "trainer_student")
    def trainer_student(student_id):
        detail = trainer_view.student_detail(_require_console(), student_id)
        if detail is None:
            abort(404)
        return render_template("prototype/trainer_student.html",
                               view=detail, active="students")

    @trainer_page("/trainer/groups", "trainer_groups")
    def trainer_groups():
        return render_template(
            "prototype/trainer_groups.html",
            view=trainer_view.groups_overview(_require_console()),
            active="groups")

    @trainer_page("/trainer/groups/<group_id>", "trainer_group")
    def trainer_group(group_id):
        detail = trainer_view.group_detail(_require_console(), group_id)
        if detail is None:
            abort(404)
        return render_template("prototype/trainer_group.html",
                               view=detail, active="groups")

    @trainer_page("/trainer/assessments", "trainer_assessments")
    def trainer_assessments():
        return render_template(
            "prototype/trainer_assessments.html",
            view=trainer_view.assessments_overview(_require_console()),
            assessment_capacities=assessment_policy.capacity_by_focus(),
            assessment_runtime_policy_version=(
                assessment_policy.ASSESSMENT_RUNTIME_POLICY_VERSION),
            active="assessments")

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
    @require_trainer
    def api_assignment_provenance():
        """Where a student already receives an assessment from, if anywhere.

        Kept at its original path -- the trainer console has linked to it
        since the UI prototype -- but the data behind it is real as of Batch 5
        and the route is trainer-authorized. It answers "where did this come
        from", not "is it already assigned", because a boolean is not
        something a trainer can act on.

        The canonical name for this is
        ``/prototype/api/trainer/assignment-sources``; this alias forwards to
        exactly the same view rather than reimplementing the lookup, so the
        two can never drift into different answers.
        """
        if management_factory is None:
            abort(503)
        return redirect(
            "/prototype/api/trainer/assignment-sources?%s"
            % request.query_string.decode("ascii", "ignore"), code=307)

    return bp


def _refuse_all(view):
    """The fail-closed trainer guard used when the application supplies none.

    Returns 403 for every request, including the page routes. A deployment
    that has not wired real instructor authentication must not serve student
    records, results or analytics to anyone -- and must not do so *quietly*,
    which is why this refuses rather than redirecting to a login that may not
    exist.
    """
    def guarded(*args, **kwargs):
        return jsonify({"error": {
            "code": "forbidden",
            "message": "Trainer authorization is not configured.",
        }}), 403
    guarded.__name__ = getattr(view, "__name__", "guarded")
    return guarded
