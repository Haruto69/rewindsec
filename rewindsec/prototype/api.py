"""The HTTP adapter for the learner workstation.

This module is the *only* place in the RewindSec 2.0 stack that knows what a
request, a status code or an SSE frame is. It translates:

    HTTP request  ->  a validated semantic action
    WorkstationError  ->  a status code and a stable JSON error body
    a learner-safe projection  ->  a JSON response

and it does nothing else. It holds no simulation state, applies no rule and
computes no consequence; every decision belongs to
:mod:`rewindsec.workstation.service`, which has never heard of Flask.

Session identity
----------------
The active session id lives in the **signed Flask session cookie** and nowhere
else. It is never accepted from a request body, a query string, a header or a
path segment. A client can therefore only ever address the session the server
already believes it is in, which is what makes cross-session access a
non-question rather than a check that has to be remembered: there is no
parameter to tamper with.

The learner reference is a per-browser-session opaque token, minted
server-side. It is deliberately not the v1 study identity, not an email
address and not a database row id. Batch 5 binds it to a persistent
:class:`~rewindsec.management.records.Student`, and that binding is the *only*
link between a person and their sessions: it is never accepted from a request
body, never derived from a display name, and never taken from a URL. A client
therefore has no parameter through which it could claim somebody else's
history, in the same way it has no parameter through which it could open
somebody else's session.

Assessment attempts
-------------------
Self-directed Assessment is a real learner choice. The generic start route
delegates it to the management service, which resolves a versioned,
system-owned definition for the chosen focus and writes an Attempt before it
creates the TrainingSession. Assigned Assessment remains the separate
``/api/session/assessment/start`` path, where the server checks the real
assignment and uses its preserved provenance.

The invariant this holds is ``Assessment mode => persistent Assessment Attempt
=> TrainingSession``. It has to be held at the door, because the alternative
is an Assessment-mode session with no attempt behind it. The generic route
never directly creates such a session; it can only request the Attempt-backed
self-directed service path.

Enrolment
---------
``/api/enroll`` is how a real browser becomes a *roster* student -- one a
trainer created, put in groups and assigned assessments to. It takes a
single-use enrolment code and nothing else: no student id, no learner
reference, no attempt id and no session id, so there is no parameter through
which a learner could ask to be somebody else. The binding is written by
:mod:`rewindsec.management.service`, from the server-minted reference already
in this browser's signed cookie.

CSRF
----
Nothing here relaxes the application's global CSRF gate. Every state-changing
route is a POST, and the gate in ``security.init_csrf`` applies to it exactly
as it applies to every other unsafe request in the application. The front end
reads the token from a meta tag the server rendered and sends it in the
``X-CSRF-Token`` header.
"""

import json

from flask import Response, jsonify, request, session, stream_with_context

from rewindsec.management.ports import ManagementError, NotFoundError
from rewindsec.management.service import ManagementRefused
from rewindsec.workstation import debrief as debrief_module
from rewindsec.workstation.actions import MAX_BODY_BYTES, parse_action_request
from rewindsec.workstation.errors import (AssessmentRefusedError,
                                          InternalWorkstationError,
                                          InvalidRequestError,
                                          NoActiveSessionError,
                                          SessionAlreadyActiveError,
                                          WorkstationError)
from rewindsec.workstation.content import index as ix

__all__ = ["register_workstation_api", "SESSION_KEY", "LEARNER_KEY",
           "SELF_DIRECTED_MODES", "SSE_KEEPALIVE_SECONDS", "SSE_MAX_SECONDS"]

#: The modes a learner may choose for a session they start themselves.
#:
#: Exactly the architecture-owned mode vocabulary. Assessment is selectable,
#: but its creation is delegated to the Attempt service below rather than to
#: :meth:`WorkstationService.start_session` directly.
SELF_DIRECTED_MODES = tuple(ix.MODE_IDS)

#: Signed-cookie keys. Namespaced so they cannot collide with the v1 session
#: values that share the same cookie.
SESSION_KEY = "rewindsec2_session"
LEARNER_KEY = "rewindsec2_learner"

#: How long a stream waits for a revision change before writing a keepalive
#: comment. A comment carries no event and no revision, and writing one
#: changes nothing about the simulation.
SSE_KEEPALIVE_SECONDS = 15

#: How long one stream connection lives before politely ending so the client
#: reconnects. Bounded so a forgotten tab cannot hold a worker forever, and so
#: a test can never hang.
SSE_MAX_SECONDS = 300


def register_workstation_api(bp, service_factory, updates,
                             management_factory=None):
    """Attach the learner API to the prototype blueprint.

    ``service_factory`` is a zero-argument callable returning the configured
    :class:`~rewindsec.workstation.service.WorkstationService`. A callable
    rather than an instance so the blueprint never has to be constructed after
    the database, and so a test can swap the whole service out.

    ``management_factory`` is the same arrangement for the Batch 5
    :class:`~rewindsec.management.service.ManagementService`. When it is
    ``None`` the learner API still works exactly as it did -- sessions are
    created, acted on and ended -- but they are recorded with no student
    owner, and the assessment-attempt routes answer that assessments are
    unavailable rather than pretending an attempt was made.
    """

    # -- helpers ----------------------------------------------------------

    def learner_ref():
        """This browser's opaque learner reference, minted on first use."""
        ref = session.get(LEARNER_KEY)
        if not ref:
            import secrets
            ref = "learner-%s" % secrets.token_hex(8)
            session[LEARNER_KEY] = ref
            session.modified = True
        return ref

    def active_session_id():
        return session.get(SESSION_KEY)

    def body():
        """The decoded JSON body, size-checked before it is parsed.

        ``request.get_json`` would happily decode a very large document
        first and complain afterwards, so the length is checked at the door.
        """
        length = request.content_length
        if length is not None and length > MAX_BODY_BYTES:
            raise InvalidRequestError("That request is too large.")
        raw = request.get_data(cache=False, as_text=True)
        if len(raw.encode("utf-8")) > MAX_BODY_BYTES:
            raise InvalidRequestError("That request is too large.")
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except ValueError:
            raise InvalidRequestError("That request was not valid JSON.")

    def error_response(exc):
        """One stable error shape. No stack trace, no SQL, no scenario truth."""
        payload = {"error": {"code": exc.code, "message": exc.message}}
        if exc.detail:
            payload["error"]["detail"] = exc.detail
        return jsonify(payload), exc.status

    @bp.errorhandler(WorkstationError)
    def _workstation_error(exc):
        return error_response(exc)

    def ok(payload, status=200):
        return jsonify(payload), status

    # -- session lifecycle ------------------------------------------------

    def read_focus_and_mode():
        """The only two things about a session a client may choose."""
        payload = body()
        if not isinstance(payload, dict):
            raise InvalidRequestError("The request body must be a JSON object.")
        unknown = sorted(set(payload) - {"focus", "mode", "csrf_token"})
        if unknown:
            raise InvalidRequestError(
                "Unrecognised field(s): %s." % ", ".join(unknown))
        focus = payload.get("focus", "mixed")
        mode = payload.get("mode", "simulation")
        if focus not in ix.FOCUS_IDS:
            raise InvalidRequestError("That focus is not one of the options.")
        if mode not in SELF_DIRECTED_MODES:
            raise InvalidRequestError("That mode is not one of the options.")
        return focus, mode

    def live_session(service):
        """The caller's session if it exists and is still active, else None."""
        session_id = active_session_id()
        if not session_id:
            return None
        try:
            simulation = service.require_owned(session_id, learner_ref())
        except NoActiveSessionError:
            return None
        return simulation if simulation.is_active else None

    def management():
        """The management service, or ``None`` when this app has none."""
        return None if management_factory is None else management_factory()

    def register_ownership(session_id, attempt_id=None):
        """Bind a freshly created session to its persistent Student.

        Best-effort by design: a failure to record the administrative
        ownership row must never destroy a session the learner is already in.
        The session's own ``learner_ref`` remains the authoritative owner
        either way -- every access check in
        :mod:`rewindsec.workstation.service` compares that and nothing else --
        so an unregistered session is *unowned in the console*, never
        misattributed.
        """
        manager = management()
        if manager is None:
            return None
        try:
            return manager.register_session(session_id, learner_ref(),
                                            attempt_id=attempt_id)
        except (ManagementError, ManagementRefused):
            return None

    def sync_attempt_for(session_id):
        """Reconcile the attempt bound to this session, if there is one."""
        manager = management()
        if manager is None:
            return None
        try:
            attempt = manager.attempt_for_session(session_id)
            return manager.sync_attempt(attempt)
        except (ManagementError, ManagementRefused):
            return None

    def create(service, focus, mode):
        if mode == "assessment":
            manager = management()
            if manager is None:
                raise InvalidRequestError(
                    "Self-directed Assessment is not available here.")
            try:
                attempt, created = manager.start_self_directed_attempt(
                    learner_ref(), focus)
            except ManagementRefused as exc:
                raise AssessmentRefusedError(
                    exc.message, detail=exc.detail, code=exc.code)
            except ManagementError:
                raise InternalWorkstationError()
            session[SESSION_KEY] = attempt.session_id
            session.modified = True
            return ok({
                "attempt": manager.attempt_state(attempt),
                "resumed": not created,
                "snapshot": service.snapshot(attempt.session_id,
                                             learner_ref()),
            }, 201 if created else 200)
        session_id = service.start_session(learner_ref(), focus, mode)
        session[SESSION_KEY] = session_id
        session.modified = True
        register_ownership(session_id)
        return ok({"snapshot": service.snapshot(session_id, learner_ref())}, 201)

    @bp.route("/api/session/start", methods=["POST"])
    def api_session_start():
        """Create a server-side session and remember it in the signed cookie.

        Focus and mode are the learner's own choices. Practice/Simulation
        create an ordinary session; Assessment delegates to the system-policy
        Attempt path and therefore cannot create a bare Assessment session.

        Refused with 409 if this browser already has an *active* session. A
        session is a factual record -- a world, a ledger, an action log -- and
        it is not something a repeated request, a bookmarked link or a page
        that booted twice gets to throw away. Replacing one on purpose is what
        ``/api/session/new`` is for, and it ends the current attempt on the
        record first.
        """
        focus, mode = read_focus_and_mode()
        service = service_factory()
        if live_session(service) is not None:
            raise SessionAlreadyActiveError(
                "You already have a training session open.")
        return create(service, focus, mode)

    @bp.route("/api/session/new", methods=["POST"])
    def api_session_new():
        """Deliberately end the current attempt and begin a fresh one.

        The one operation allowed to replace a live session, and it is a POST
        carrying an explicit intent -- never a page render, never a query
        parameter. The outgoing session is *completed*, not deleted: its
        record stays in the database and stays readable.
        """
        focus, mode = read_focus_and_mode()
        service = service_factory()
        current = live_session(service)
        if current is not None:
            service.end_session(current.session_id, learner_ref())
            sync_attempt_for(current.session_id)
        return create(service, focus, mode)

    @bp.route("/api/session", methods=["GET"])
    def api_session():
        """The authoritative snapshot. Reads only; mutates nothing."""
        service = service_factory()
        session_id = active_session_id()
        if not session_id:
            raise NoActiveSessionError("There is no training session open.")
        return ok({"snapshot": service.snapshot(session_id, learner_ref())})

    @bp.route("/api/session/tick", methods=["POST"])
    def api_session_tick():
        """Let simulation time move on and apply whatever became due.

        A POST because it changes state. The client decides only *whether*
        to ask; how far the clock moves is an authored constant on the server,
        and no real elapsed time is measured anywhere. A slow machine, a
        throttled tab and a fast one all buy exactly the same step. If the
        client never asks, nothing is lost and nothing is skipped: the
        schedule simply waits for the next explicit advance.
        """
        service = service_factory()
        session_id = active_session_id()
        if not session_id:
            raise NoActiveSessionError("There is no training session open.")
        body()  # size- and syntax-checked even though nothing is read from it
        return ok({"snapshot": service.tick(session_id, learner_ref())})

    @bp.route("/api/session/end", methods=["POST"])
    def api_session_end():
        """End the attempt. Preserves every fact; resets nothing."""
        service = service_factory()
        session_id = active_session_id()
        if not session_id:
            raise NoActiveSessionError("There is no training session open.")
        body()
        snapshot = service.end_session(session_id, learner_ref())
        # The attempt's result is *read* from the session's now-finalized,
        # immutable Batch 4 ScoringResult -- never recomputed here. Doing it
        # at the moment the session ends keeps the trainer console readable
        # without loading every session; doing it again later is a no-op.
        sync_attempt_for(session_id)
        return ok({"snapshot": snapshot})

    @bp.route("/api/session/debrief", methods=["GET"])
    def api_session_debrief():
        """The factual debrief. Available only once the session has finished."""
        service = service_factory()
        session_id = active_session_id()
        if not session_id:
            raise NoActiveSessionError("There is no training session open.")
        simulation = service.require_owned(session_id, learner_ref())
        return ok({"debrief": debrief_module.debrief_document(simulation)})

    # -- assessments (Batch 5) ---------------------------------------------
    #
    # An Assessment attempt is the one kind of session a learner does not
    # configure. They name an assessment they have been assigned; the server
    # resolves who they are from the signed cookie, checks that an effective
    # assignment actually reaches them, applies the assessment's retry policy,
    # and derives the focus and the mode from the definition. There is no
    # parameter here for a focus, a mode, a seed, a difficulty or a scaffolding
    # profile, and no attempt id is ever accepted from a client.

    def require_management():
        manager = management()
        if manager is None:
            raise InvalidRequestError("Assessments are not available here.")
        return manager

    @bp.route("/api/enroll", methods=["POST"])
    def api_enroll():
        """Claim a roster student with a single-use enrolment code.

        The whole request is one code. The server reads *who this browser is*
        from the signed cookie -- the same server-minted reference every
        session it has ever created is owned by -- and binds that reference to
        the student the code names. Nothing about the identity comes from the
        request.

        Three refusals, and they are deliberately not distinguishable from
        each other: an unknown code, a code somebody else has already spent,
        and a revoked one all answer the same thing. Telling them apart would
        let a stranger use this endpoint to discover which codes exist and
        which roster students have already enrolled.

        Idempotent for the browser that already holds the binding: re-posting
        the same code -- a double-submitted form, a reload, a retried fetch --
        returns the same student rather than a second binding or an error.
        """
        manager = require_management()
        payload = body()
        if not isinstance(payload, dict):
            raise InvalidRequestError("The request body must be a JSON object.")
        unknown = sorted(set(payload) - {"code", "csrf_token"})
        if unknown:
            # Named explicitly, because the fields somebody would *try* to add
            # here are exactly student_id and learner_ref.
            raise InvalidRequestError(
                "Unrecognised field(s): %s." % ", ".join(unknown))
        code = payload.get("code")
        if not isinstance(code, str) or not code.strip() or len(code) > 128:
            raise InvalidRequestError("An enrolment code is required.")

        try:
            student, bound = manager.claim_enrollment(learner_ref(),
                                                      code.strip())
        except ManagementRefused as exc:
            raise AssessmentRefusedError(exc.message, detail=exc.detail,
                                         code=exc.code)
        except ManagementError:
            raise InternalWorkstationError()
        # The display name and the id of the student this browser now *is*.
        # No learner reference, no enrolment code and no other student.
        return ok({"enrolled": True, "newly_bound": bool(bound),
                   "student": {"id": student.student_id,
                               "name": student.display_name,
                               "reference": student.reference,
                               "cohort": student.cohort}},
                  201 if bound else 200)

    @bp.route("/api/me", methods=["GET"])
    def api_me():
        """Which persistent student this browser currently is.

        Read-only, and provisions nothing: a browser that has never trained
        and never enrolled answers ``{"student": null}`` rather than being
        given an identity by the act of asking.
        """
        manager = require_management()
        student = manager.student_for_learner_ref(learner_ref())
        if student is None:
            return ok({"student": None})
        return ok({"student": {"id": student.student_id,
                               "name": student.display_name,
                               "reference": student.reference,
                               "cohort": student.cohort,
                               "origin": student.origin}})

    @bp.route("/api/assessments", methods=["GET"])
    def api_assessments():
        """The assessments assigned to *this* learner, with their attempt state.

        Learner-safe throughout. An attempt's state carries scored-interaction
        progress and nothing else: no score, no correctness, no disposition,
        no dimension and no decision id. Progress says how much of the
        assessment has been handled, never how well.
        """
        manager = require_management()
        student = manager.ensure_student_for_learner_ref(learner_ref())
        routes = manager.effective_assignments(student.student_id)

        seen, out = set(), []
        for route in routes:
            assessment = route.assessment
            if assessment is None or assessment.assessment_id in seen:
                continue
            seen.add(assessment.assessment_id)
            attempts = [manager.sync_attempt(a) for a in manager.list_attempts(
                student_id=student.student_id,
                assessment_id=assessment.assessment_id)]
            active = next((a for a in attempts if a.is_active), None)
            out.append({
                "id": assessment.assessment_id,
                "name": assessment.name,
                "focus": assessment.focus,
                "required_interactions": assessment.required_interactions,
                "status": assessment.status,
                "window_label": assessment.window_label,
                "note": assessment.note,
                "attempts_used": len(attempts),
                "max_attempts": assessment.max_attempts,
                "retry_policy": assessment.retry_policy,
                "attempts_remaining": max(
                    0, assessment.max_attempts - len(attempts)),
                "active_attempt": manager.attempt_state(active),
                "assigned_via": [
                    {"source": r.source, "label": r.origin_label}
                    for r in routes
                    if r.assignment.assessment_id == assessment.assessment_id],
            })
        return ok({"assessments": out})

    @bp.route("/api/session/assessment/start", methods=["POST"])
    def api_assessment_start():
        """Start -- or resume -- this learner's attempt at an assessment.

        Resume is the first thing this does, so a closed browser, a refresh or
        a double-submitted form lands the learner back in the attempt they
        were already in. It never mints a second attempt for an active one,
        and therefore never silently spends one of their allowed retries.
        """
        manager = require_management()
        service = service_factory()
        payload = body()
        if not isinstance(payload, dict):
            raise InvalidRequestError("The request body must be a JSON object.")
        unknown = sorted(set(payload) - {"assessment_id", "csrf_token"})
        if unknown:
            raise InvalidRequestError(
                "Unrecognised field(s): %s." % ", ".join(unknown))
        assessment_id = payload.get("assessment_id")
        if not isinstance(assessment_id, str) or not assessment_id                 or len(assessment_id) > 128:
            raise InvalidRequestError("An assessment id is required.")

        try:
            attempt, created = manager.start_attempt(learner_ref(),
                                                     assessment_id)
        except NotFoundError:
            raise InvalidRequestError("That assessment does not exist.")
        except ManagementRefused as exc:
            raise AssessmentRefusedError(exc.message, detail=exc.detail,
                                         code=exc.code)

        if not created:
            # Resuming. A live session for this attempt is put back in the
            # cookie; one that has since ended is reconciled and reported.
            attempt = manager.sync_attempt(attempt)
            if not attempt.is_active or attempt.session_id is None:
                raise AssessmentRefusedError(
                    "That attempt has already finished.",
                    code="attempt_finished")

        current = live_session(service)
        if created and current is not None                 and current.session_id != attempt.session_id:
            # A fresh attempt was started while another session was open. The
            # outgoing one is completed on the record rather than discarded --
            # it is a factual history, and a new attempt does not erase it.
            service.end_session(current.session_id, learner_ref())
            sync_attempt_for(current.session_id)

        session[SESSION_KEY] = attempt.session_id
        session.modified = True
        return ok({
            "attempt": manager.attempt_state(attempt),
            "resumed": not created,
            "snapshot": service.snapshot(attempt.session_id, learner_ref()),
        }, 201 if created else 200)

    @bp.route("/api/session/assessment", methods=["GET"])
    def api_session_assessment():
        """The attempt state for the caller's current session, if it is one.

        ``{"attempt": null}`` for a self-directed Practice or Simulation run:
        those legitimately have no assessment and no attempt, and saying so is
        not an error.
        """
        manager = require_management()
        session_id = active_session_id()
        if not session_id:
            raise NoActiveSessionError("There is no training session open.")
        # Establishes ownership before anything about the session is read.
        service_factory().require_owned(session_id, learner_ref())
        attempt = manager.sync_attempt(manager.attempt_for_session(session_id))
        return ok({"attempt": manager.attempt_state(attempt)})

    # -- actions -----------------------------------------------------------

    @bp.route("/api/actions", methods=["POST"])
    def api_actions():
        """Apply one semantic learner action.

        The body names an allowlisted verb, a target and narrow parameters,
        and nothing else. It cannot carry a world, a mutation, an event id, a
        simulation time, a sequence number, a seed or a score: every one of
        those is rejected as an unrecognised field before the session is even
        loaded.
        """
        service = service_factory()
        session_id = active_session_id()
        if not session_id:
            raise NoActiveSessionError("There is no training session open.")
        action = parse_action_request(body())
        result = service.apply_action(session_id, action, learner_ref())
        response = {"snapshot": result.snapshot}
        if result.notice:
            response["notice"] = result.notice
        return ok(response)

    # -- server-sent events -------------------------------------------------

    @bp.route("/api/events", methods=["GET"])
    def api_events():
        """Revision updates for the caller's own session, over SSE.

        The stream carries revision numbers, never content: a woken client
        re-fetches the snapshot through the ordinary read path, so this
        transport can never become a second, differently-filtered way for
        state to reach a browser.

        It is scoped to the session in the signed cookie -- there is no
        session parameter to supply, and therefore no way to subscribe to
        somebody else's session. Opening, waiting, timing out and reconnecting
        change no simulation state, and neither does a keepalive.
        """
        service = service_factory()
        session_id = active_session_id()
        if not session_id:
            raise NoActiveSessionError("There is no training session open.")
        # Establishes that the session exists and belongs to this browser
        # before a long-lived response is opened.
        current = service.revision(session_id, learner_ref())
        since = _last_event_id()
        updates.publish(session_id, current)

        @stream_with_context
        def stream():
            # The first frame always states the current revision, so a client
            # that reconnected after missing an update reconciles immediately
            # rather than waiting for the next change.
            yield _frame(current, "revision", {"revision": current})
            seen = current if since is None or since < current else since
            waited = 0
            while waited < SSE_MAX_SECONDS:
                revision = updates.wait_for_change(
                    session_id, seen, SSE_KEEPALIVE_SECONDS)
                if revision is None:
                    waited += SSE_KEEPALIVE_SECONDS
                    # A comment. No event, no id, no revision, no state change.
                    yield ": keepalive\n\n"
                    continue
                seen = revision
                yield _frame(revision, "revision", {"revision": revision})

        response = Response(stream(), mimetype="text/event-stream")
        response.headers["Cache-Control"] = "no-cache, no-store"
        response.headers["X-Accel-Buffering"] = "no"
        response.headers["Connection"] = "keep-alive"
        return response

    # -- development-only operations ---------------------------------------
    #
    # Prototype tooling. Every one of these goes through the same service, the
    # same persistence and the same projection a learner action does: they
    # compress waiting, never causality, and none of them can produce a state
    # a learner action could not have produced. They are POSTs under an
    # explicit ``/api/dev/`` prefix so that no learner route can grow into one
    # by accident.

    @bp.route("/api/dev/advance", methods=["POST"])
    def api_dev_advance():
        service = service_factory()
        session_id = active_session_id()
        if not session_id:
            raise NoActiveSessionError("There is no training session open.")
        payload = body()
        if not isinstance(payload, dict):
            raise InvalidRequestError("The request body must be a JSON object.")
        unknown = sorted(set(payload) - {"milliseconds", "csrf_token"})
        if unknown:
            raise InvalidRequestError(
                "Unrecognised field(s): %s." % ", ".join(unknown))
        milliseconds = payload.get("milliseconds", 10000)
        if isinstance(milliseconds, bool) or not isinstance(milliseconds, int):
            raise InvalidRequestError("milliseconds must be a whole number.")
        return ok({"snapshot": service.dev_advance(
            session_id, milliseconds, learner_ref())})

    @bp.route("/api/dev/deliver-next", methods=["POST"])
    def api_dev_deliver_next():
        service = service_factory()
        session_id = active_session_id()
        if not session_id:
            raise NoActiveSessionError("There is no training session open.")
        body()
        return ok({"snapshot": service.dev_deliver_next(
            session_id, learner_ref())})

    @bp.route("/api/dev/deliver-candidate", methods=["POST"])
    def api_dev_deliver_candidate():
        """Deliver one named engine candidate. Development tooling.

        The only endpoint in the product that names a candidate, and it exists
        so a developer or a suite can put a *specific* piece of activity in
        front of the learner instead of waiting for the engine to choose it.
        It bypasses the lottery and nothing else: the same adapter, the same
        world operations, the same causal event, and no draw from any
        selection stream.

        It reveals nothing. The caller has to already know the candidate id to
        use it, and the response is the ordinary learner projection -- the same
        document, filtered the same way, with no engine field in it.
        """
        service = service_factory()
        session_id = active_session_id()
        if not session_id:
            raise NoActiveSessionError("There is no training session open.")
        payload = body()
        if not isinstance(payload, dict):
            raise InvalidRequestError("The request body must be a JSON object.")
        unknown = sorted(set(payload) - {"candidate", "csrf_token"})
        if unknown:
            raise InvalidRequestError(
                "Unrecognised field(s): %s." % ", ".join(unknown))
        candidate = payload.get("candidate")
        if not isinstance(candidate, str) or not candidate \
                or len(candidate) > 128:
            raise InvalidRequestError("A candidate id is required.")
        return ok({"snapshot": service.dev_force_candidate(
            session_id, candidate, learner_ref())})

    @bp.route("/api/dev/engine", methods=["POST"])
    def api_dev_engine():
        """The engine's internal state. Development boundary only.

        Deliberately a separate endpoint under ``/api/dev/`` rather than a
        field on the learner snapshot. Eligibility reasons, family pressure
        and the selection trace are between them a description of what is
        about to happen, and there must be exactly one document a learner's
        browser receives -- the projection -- with none of it in there.
        """
        service = service_factory()
        session_id = active_session_id()
        if not session_id:
            raise NoActiveSessionError("There is no training session open.")
        body()
        return ok({"engine": service.dev_engine_state(session_id, learner_ref())})


def _frame(event_id, event_name, payload):
    """One SSE frame. The revision is the event id, so reconnect is trivial."""
    return ("id: %d\nevent: %s\ndata: %s\n\n"
            % (event_id, event_name, json.dumps(payload, separators=(",", ":"))))


def _last_event_id():
    """The revision a reconnecting client last saw, if it told us.

    Advisory only. It cannot make the server show a client anything it would
    not otherwise show: the worst a forged value can do is make the stream
    send one more revision frame than it needed to.
    """
    raw = request.headers.get("Last-Event-ID") or request.args.get("since")
    if raw is None:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if 0 <= value <= 2 ** 53 - 1 else None
