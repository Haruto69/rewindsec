"""The error vocabulary the workstation application layer speaks.

Every failure a caller can provoke is one of these, and each carries a stable
machine-readable ``code`` plus a message that is safe to show a learner. The
HTTP adapter maps ``status`` onto a response code and serialises ``code`` and
``message`` -- it never serialises an exception it did not expect, so a stack
trace, a SQL error, a filesystem path or a piece of hidden scenario truth
cannot escape through an error body.

The messages here are deliberately dull. "No such message" is a true and
useless answer; "no such message, but there is a hostile one at m-rate-card"
would be an oracle.
"""

__all__ = [
    "WorkstationError",
    "InvalidRequestError",
    "UnknownActionError",
    "UnknownTargetError",
    "ForbiddenActionError",
    "NoActiveSessionError",
    "SessionEndedError",
    "SessionAlreadyActiveError",
    "StaleRevisionConflict",
    "InternalWorkstationError",
]


class WorkstationError(Exception):
    """Base class for every failure the application layer raises deliberately.

    ``status`` is advisory: it is the HTTP status the adapter should use, kept
    here rather than in the adapter so that one exception cannot be mapped two
    different ways by two different routes.
    """

    code = "error"
    status = 400

    def __init__(self, message, code=None, status=None, detail=None):
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        if status is not None:
            self.status = status
        #: Extra machine-readable fields for the client to reconcile with.
        #: Must never contain hidden scenario truth -- today only revisions.
        self.detail = dict(detail or {})


class InvalidRequestError(WorkstationError):
    """The request body is malformed, out of bounds, or carries unknown keys."""

    code = "invalid_request"
    status = 400


class UnknownActionError(WorkstationError):
    """The action type is not in the server-side allowlist."""

    code = "unknown_action"
    status = 400


class UnknownTargetError(WorkstationError):
    """The action names a target the learner cannot currently see."""

    code = "unknown_target"
    status = 404


class ForbiddenActionError(WorkstationError):
    """The action exists but is not permitted in this mode or lifecycle state.

    Also raised for the safer-alternative and integrity boundaries: an
    Assessment attempt asking for pedagogical material is a forbidden request,
    not a missing one, and answering 404 would tell the client that the
    material exists elsewhere.
    """

    code = "forbidden"
    status = 403


class NoActiveSessionError(WorkstationError):
    """This browser session has no server-side simulation session."""

    code = "no_session"
    status = 404


class SessionEndedError(WorkstationError):
    """The session is complete or abandoned; no consequential action may run.

    410 rather than 403: the resource genuinely existed and is genuinely gone
    as a place to act, while its factual history stays readable for the
    debrief.
    """

    code = "session_ended"
    status = 410


class SessionAlreadyActiveError(WorkstationError):
    """A new session was asked for while this browser still has a live one.

    Refused rather than granted, because granting it would abandon a factual
    session -- its world, its ledger, its recorded actions -- on nothing more
    than a page load or a stale link. Starting over is a deliberate act and
    goes through the explicit new-session operation, which ends the current
    attempt on the record before opening another.

    Carries no detail: the caller already knows which session it owns, and the
    remedy is simply to read it.
    """

    code = "session_active"
    status = 409


class StaleRevisionConflict(WorkstationError):
    """The action was built against a revision that is no longer current.

    Carries ``detail["revision"]`` -- the authoritative revision now -- so the
    client can refetch and reconcile without guessing. Nothing is applied: a
    conflict is the mechanism that stops a retried, duplicated or replayed
    submission from applying the same consequence twice.
    """

    code = "stale_revision"
    status = 409


class InternalWorkstationError(WorkstationError):
    """Something failed that is not the caller's fault. Details are not shared."""

    code = "internal_error"
    status = 500

    def __init__(self, message="The workstation could not complete that."):
        super().__init__(message)
